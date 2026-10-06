"""Command-line entry point for ``portsight``.

Default invocation prints the full aesthetic report. Other flags select a
single question instead: who owns a port, is it free, give me N ports,
stop the container publishing it, or what changed since a snapshot.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.prompt import Confirm
from rich.text import Text

from portsight import __version__
from portsight.docker_stop import plan_docker_stop, stop_containers
from portsight.expect import classify_expected, discover_expected
from portsight.filters import filter_services
from portsight.inventory import build_inventory
from portsight.kill import find_targets_on_port, free_port
from portsight.lookup import lookup_port
from portsight.models import PortInventory
from portsight.ranges import pick_random_free_port, take_free_ports
from portsight.report import (
    render_compact_report,
    render_expected,
    render_kill_preview,
    render_kill_result,
    render_port_lookup,
    render_report,
    render_stop_result,
)
from portsight.snapshot import (
    diff_inventory,
    format_diff_lines,
    inventory_to_dict,
    load_snapshot,
    save_snapshot,
    service_to_dict,
)

_DESCRIPTION = """\
See who owns every local port and which ports are free.

With no options, prints a full report: host listeners (with process,
command line, and parent), Docker published ports, Windows excluded
port ranges, the OS ephemeral pool, and contiguous free ranges.
Options below replace the report with a single answer."""

_EPILOG = """\
examples:
  portsight                          full report
  portsight -c                       compact report
  portsight --port 3000              who owns 3000, and why can't I bind it?
  portsight --check 3000 && npm run dev
  PORT=$(portsight -r --from 4000 --to 4999)
  portsight --take 3 --contiguous    three adjacent free ports
  portsight --expect "3000 web, 5432 db"
  portsight --project                read .portsight and compose.yaml
  portsight -k 3000                  kill the host process on 3000 (asks first)
  portsight --stop 5432              docker stop the container publishing 5432
  portsight --snapshot before.json   later: portsight --diff before.json
  portsight --json | jq '.listening[].port'

exit codes:
  0    success; --check / --port: free; --diff: no changes
  1    --check / --port: in use; --diff: changed; --random / --take: not
       enough free ports; --kill / --stop: port not freed
  2    usage error, unreadable snapshot, or bad --expect / project file
  130  declined a confirmation prompt

environment:
  NO_COLOR      disable color (same as --no-color)
  FORCE_COLOR   force color even when stdout is not a terminal

docs: https://github.com/rfdpro/portsight#readme"""


def _port(text: str) -> int:
    """argparse type for a concrete port, so errors name the bad value."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a port number") from None
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError(f"{value} is outside 1-65535")
    return value


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"{value} must be >= 1")
    return value


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not value > 0:
        raise argparse.ArgumentTypeError(f"{value} must be > 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Define CLI flags; kept separate for testability."""
    parser = argparse.ArgumentParser(
        prog="portsight",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"portsight {__version__}",
    )

    report = parser.add_argument_group("report (default mode)")
    report.add_argument(
        "-c",
        "--compact",
        action="store_true",
        help="Compact report: summary, in-use ports, top free spans.",
    )
    report.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="List every listener and Docker publish (tables are capped by default).",
    )
    report.add_argument(
        "-m",
        "--min-size",
        type=_positive_int,
        default=1,
        metavar="N",
        help="Only show free ranges with at least N contiguous ports (default: 1).",
    )
    report.add_argument(
        "-l",
        "--free-limit",
        type=_positive_int,
        default=15,
        metavar="N",
        help="Max free ranges shown per table (default: 15).",
    )

    filters = parser.add_argument_group(
        "filters",
        "Narrow what is shown. Free ranges still count every occupied port.",
    )
    filters.add_argument(
        "--exposed",
        action="store_true",
        help="Hide loopback binds (127.0.0.1, ::1); show only reachable ones.",
    )
    filters.add_argument(
        "--process",
        metavar="TEXT",
        help="Only rows whose process name, path, command line, or parent contains TEXT.",
    )
    filters.add_argument(
        "-t",
        "--tcp-only",
        action="store_true",
        help="Ignore UDP sockets (also limits --kill to TCP listeners).",
    )
    filters.add_argument(
        "--no-docker",
        action="store_true",
        help="Skip Docker discovery (faster when Docker is slow to answer).",
    )

    query = parser.add_argument_group("query one port")
    query.add_argument(
        "--port",
        type=_port,
        metavar="PORT",
        help="Explain PORT: owner, command line, parent, Docker publish, TIME_WAIT "
        "sockets, Windows exclusion. Exit 0 if free, 1 if not.",
    )
    query.add_argument(
        "--check",
        type=_port,
        metavar="PORT",
        help="Print 'free' or 'in use' and exit 0 or 1. Reasons go to stderr.",
    )

    allocate = parser.add_argument_group("allocate free ports")
    allocate.add_argument(
        "-r",
        "--random",
        action="store_true",
        help="Print one random free port (1024-49151 preferred unless --from/--to).",
    )
    allocate.add_argument(
        "--take",
        type=_positive_int,
        metavar="N",
        help="Print the N lowest free ports, one per line.",
    )
    allocate.add_argument(
        "--contiguous",
        action="store_true",
        help="With --take, return one adjacent block of N ports.",
    )
    allocate.add_argument(
        "--from",
        dest="port_from",
        type=_port,
        metavar="PORT",
        help="With --random or --take, first port of the search window (inclusive).",
    )
    allocate.add_argument(
        "--to",
        dest="port_to",
        type=_port,
        metavar="PORT",
        help="With --random or --take, last port of the search window (inclusive).",
    )

    project = parser.add_argument_group(
        "expected ports",
        "Check a planned set of ports. Combines with the report, --json, and --watch.",
    )
    project.add_argument(
        "--expect",
        metavar="SPEC",
        help="Ports to classify: '3000,5432', '8080-8082', or '3000 web, 5432 db'.",
    )
    project.add_argument(
        "--project",
        action="store_true",
        help="Also read ./.portsight and the first docker-compose.yml / compose.yaml.",
    )

    act = parser.add_argument_group("free a port")
    act.add_argument(
        "-k",
        "--kill",
        type=_port,
        metavar="PORT",
        help="Terminate the host process(es) listening on PORT. Asks first.",
    )
    act.add_argument(
        "--stop",
        type=_port,
        metavar="PORT",
        help="docker stop the container(s) publishing PORT. Asks first.",
    )
    act.add_argument(
        "--stop-container",
        metavar="NAME",
        help="docker stop the container NAME. Asks first.",
    )
    act.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt for --kill / --stop / --stop-container.",
    )
    act.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="With --kill, hard-kill immediately instead of terminate-then-wait.",
    )

    output = parser.add_argument_group("output and history")
    output.add_argument(
        "--json",
        action="store_true",
        help="Machine-readable JSON instead of tables (see docs/json.md).",
    )
    output.add_argument(
        "--no-color",
        action="store_true",
        help="Disable color. Color is already off when stdout is not a terminal.",
    )
    output.add_argument(
        "--snapshot",
        metavar="FILE",
        help="Also save the full, unfiltered inventory to FILE as JSON.",
    )
    output.add_argument(
        "--diff",
        metavar="FILE",
        help="Compare now against a --snapshot FILE. Exit 1 when something changed.",
    )
    output.add_argument(
        "--watch",
        nargs="?",
        const=2.0,
        type=_positive_float,
        metavar="SECONDS",
        help="Rescan every SECONDS (default 2) until Ctrl+C. Prints the report once, "
        "then timestamped changes. With --json, one JSON document per line.",
    )
    return parser


def _configure_stdio() -> None:
    """Prefer UTF-8 on Windows so box-drawing and accents render cleanly.

    Legacy ``cp1252`` consoles raise ``UnicodeEncodeError`` on characters like
    en-dashes and geometric bullets. Reconfigure when the stream supports it;
    otherwise the report falls back to ASCII-safe glyphs via Rich.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            # Some redirected handles reject reconfigure; ignore and continue.
            with contextlib.suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")


def _console(args: argparse.Namespace) -> Console:
    """Rich console that respects ``--no-color`` and avoids the legacy code page.

    Terminal detection is left to Rich so piping into a file or ``less``
    does not embed ANSI escapes. Rich also honors ``NO_COLOR`` and
    ``FORCE_COLOR`` from the environment.
    """
    return Console(
        no_color=True if args.no_color else None,
        legacy_windows=False,
    )


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject flag combinations that would answer two questions at once."""
    if args.port_from is not None and args.port_to is not None and args.port_from > args.port_to:
        parser.error("--from must be <= --to")

    window = args.port_from is not None or args.port_to is not None
    if window and not (args.random or args.take is not None):
        parser.error("--from/--to require --random or --take")
    if args.contiguous and args.take is None:
        parser.error("--contiguous requires --take")

    # One primary question per invocation. Filters and --json/--snapshot
    # ride along; these flags each replace the report with their own answer.
    modes = [
        args.random,
        args.kill is not None,
        args.port is not None,
        args.check is not None,
        args.take is not None,
        args.stop is not None,
        args.stop_container is not None,
        args.diff is not None,
        args.watch is not None,
    ]
    if sum(bool(mode) for mode in modes) > 1:
        parser.error(
            "choose only one of --random, --kill, --port, --check, --take, "
            "--stop, --stop-container, --diff, --watch"
        )

    asking = any(modes)
    # The expected-port table rides on the report, on --json, and on --watch.
    # It does not ride on a one-shot mode that already has its own stdout.
    if (args.expect or args.project) and asking and args.watch is None:
        parser.error("--expect/--project only combine with the report, --json, or --watch")


def _load_inventory(args: argparse.Namespace) -> PortInventory:
    """Scan once. ``--stop`` always includes Docker so the plan can see publishes."""
    include_docker = not args.no_docker or args.stop is not None or args.stop_container is not None
    return build_inventory(
        include_udp=not args.tcp_only,
        min_free_size=args.min_size,
        include_docker=include_docker,
    )


def _for_display(inventory: PortInventory, args: argparse.Namespace) -> PortInventory:
    """Apply view filters without changing which ports count as occupied.

    Free ranges are computed from every listener. Hiding loopback rows in
    the table must not make those ports look bindable.
    """
    if not args.process and not args.exposed:
        return inventory
    return replace(
        inventory,
        listening=filter_services(
            inventory.listening,
            process=args.process,
            exposed_only=args.exposed,
        ),
        docker=filter_services(
            inventory.docker,
            process=args.process,
            exposed_only=args.exposed,
        ),
        held=filter_services(
            inventory.held,
            process=args.process,
            exposed_only=args.exposed,
        ),
    )


def _maybe_snapshot(args: argparse.Namespace, inventory: PortInventory) -> None:
    """Write the unfiltered inventory when ``--snapshot`` was passed.

    Filters are a view. The file is the full scan so a later ``--diff``
    is not missing ports the filter hid.
    """
    if not args.snapshot:
        return
    save_snapshot(inventory, Path(args.snapshot))


def _expected_statuses(args: argparse.Namespace, inventory: PortInventory):
    """Load ``--expect`` / ``--project`` rows and classify them. None if unused."""
    if not args.expect and not args.project:
        return None
    expected = discover_expected(
        Path.cwd(),
        args.expect,
        use_project_files=args.project,
    )
    return classify_expected(expected, inventory)


def _error(args: argparse.Namespace, message: object) -> None:
    """Errors go to stderr so a captured stdout stays parseable."""
    console = Console(stderr=True, no_color=True if args.no_color else None, legacy_windows=False)
    console.print(Text.assemble(("error: ", "bold red"), str(message)))


def _print_json(payload: object) -> None:
    """Pretty JSON on stdout. Callers that need a bare token do not use this."""
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _confirmed(args: argparse.Namespace, console: Console, question: str) -> bool:
    """Ask before a destructive action. Defaults to no.

    Without a terminal there is nobody to answer, so the action is declined
    rather than crashing on EOF or hanging; scripts pass --yes.
    """
    if args.yes:
        return True
    if not sys.stdin or not sys.stdin.isatty():
        console.print("[yellow]No terminal to confirm on; pass --yes to proceed.[/]")
        return False
    try:
        return Confirm.ask(f"[bold]{question}[/]", default=False, console=console)
    except EOFError:
        return False


def _run_kill(args: argparse.Namespace, console: Console) -> int:
    """Handle ``--kill PORT``: preview, confirm, terminate, report."""
    port = args.kill
    include_udp = not args.tcp_only
    targets = find_targets_on_port(port, include_udp=include_udp)

    if not targets:
        # Still run free_port so orphan-PID / Docker / already-free messaging
        # stays consistent.
        outcome = free_port(port, include_udp=include_udp, force=args.force)
        render_kill_result(outcome, console=console)
        # Docker-owned and PID-less ports are in use but not killable here.
        return 0 if outcome.already_free else 1

    render_kill_preview(port, targets, console=console)

    if not _confirmed(args, console, f"Kill process(es) on port {port}?"):
        console.print("[dim]Aborted - port left unchanged.[/]")
        return 130

    # Kill exactly what was previewed. A rescan here could pick up a process
    # that bound the port while the prompt was open.
    outcome = free_port(
        port,
        include_udp=include_udp,
        force=args.force,
        targets=targets,
    )
    render_kill_result(outcome, console=console)
    return 0 if outcome.ok else 1


def _run_stop(args: argparse.Namespace, console: Console) -> int:
    """Confirm and ``docker stop`` a container by published port or by name."""
    inventory = _load_inventory(args)
    try:
        _maybe_snapshot(args, inventory)
        plan = plan_docker_stop(
            port=args.stop,
            name=args.stop_container,
            services=inventory.docker,
            docker_available=inventory.docker_available,
        )
    except (OSError, ValueError) as exc:
        _error(args, exc)
        return 2

    # Name-based stop still needs a reachable Docker CLI. plan_docker_stop
    # already clears ok_to_run when docker_available is false.
    if not plan.ok_to_run:
        console.print(f"[yellow]{plan.message}[/]")
        return 1

    console.print(f"[bold]{plan.message}[/]")
    if not _confirmed(args, console, "Stop these container(s)?"):
        console.print("[dim]Aborted - container left running.[/]")
        return 130

    result = stop_containers(plan.containers)
    render_stop_result(result, console=console)
    return 0 if result.ok else 1


def _run_port(args: argparse.Namespace, inventory: PortInventory, console: Console) -> int:
    """``--port``: one owner, command line, parent, Docker row, or exclusion."""
    lookup = lookup_port(args.port, inventory)
    if args.json:
        # Same service shape as an inventory snapshot, so callers can share
        # one decoder for rows from --json and from --port --json.
        _print_json(
            {
                "port": lookup.port,
                "free": lookup.free,
                "reasons": lookup.reasons,
                "exclusion_advice": lookup.exclusion_advice,
                "listeners": [service_to_dict(row) for row in lookup.listeners],
                "docker": [service_to_dict(row) for row in lookup.docker],
                "held": [service_to_dict(row) for row in lookup.held],
            }
        )
        return 0 if lookup.free else 1

    render_port_lookup(lookup, console=console)
    return 0 if lookup.free else 1


def _run_check(args: argparse.Namespace, inventory: PortInventory) -> int:
    """``--check``: exit status is the answer. Stdout stays a single word unless --json."""
    lookup = lookup_port(args.check, inventory)
    if args.json:
        _print_json(
            {
                "port": lookup.port,
                "free": lookup.free,
                "reasons": lookup.reasons,
            }
        )
    else:
        # First line matches format_lookup_lines so scripts can read one token.
        print("free" if lookup.free else "in use")
        if not lookup.free:
            for reason in lookup.reasons:
                print(reason, file=sys.stderr)
    return 0 if lookup.free else 1


def _run_take(args: argparse.Namespace, inventory: PortInventory) -> int:
    """``--take``: lowest N free ports, or the lowest contiguous block."""
    start = 1 if args.port_from is None else args.port_from
    end = 65535 if args.port_to is None else args.port_to
    ports = take_free_ports(
        inventory.free,
        args.take,
        contiguous=args.contiguous,
        window_start=start,
        window_end=end,
    )
    if len(ports) < args.take:
        print(
            f"not enough free ports for --take {args.take}",
            file=sys.stderr,
        )
        return 1
    if args.json:
        _print_json({"ports": ports, "contiguous": args.contiguous})
    else:
        for port in ports:
            print(port)
    return 0


def _run_random(args: argparse.Namespace, inventory: PortInventory) -> int:
    """``--random``: one port on stdout. An explicit window replaces the registered-band bias."""
    port = pick_random_free_port(
        inventory.free,
        prefer_registered=True,
        window_start=args.port_from,
        window_end=args.port_to,
    )
    if port is None:
        print("no free ports in the requested window", file=sys.stderr)
        return 1
    if args.json:
        _print_json({"port": port})
    else:
        # Bare integer so ``$(portsight -r)`` keeps working.
        print(port)
    return 0


def _run_diff(args: argparse.Namespace, before: dict, inventory: PortInventory) -> int:
    """``--diff``: added and removed listeners, Docker publishes, held sockets, exclusions."""
    diff = diff_inventory(before, inventory)
    lines = format_diff_lines(diff)
    if args.json:
        _print_json({"changed": not diff.empty, "lines": lines})
    else:
        # Plain print: these lines are meant for grep, and Rich would treat
        # a bracketed IPv6 address as markup.
        for line in lines:
            print(line)
    return 0 if diff.empty else 1


def _json_report(display: PortInventory, statuses) -> dict:
    """The ``--json`` document, plus ``expected`` when one was requested."""
    payload = inventory_to_dict(display)
    if statuses is not None:
        payload["expected"] = [
            {
                "port": status.expected.port,
                "label": status.expected.label,
                "origin": status.expected.origin,
                "status": status.status,
                "detail": status.detail,
            }
            for status in statuses
        ]
    return payload


def _emit_report(
    args: argparse.Namespace,
    display: PortInventory,
    console: Console,
    statuses,
) -> None:
    """Rich report, or JSON, plus the expected-port table when one was requested."""
    if args.json:
        _print_json(_json_report(display, statuses))
        return

    if statuses is not None:
        render_expected(statuses, console=console)
        if not statuses:
            console.print(
                "[dim]No expected ports. Pass --expect, or add .portsight / compose "
                "and use --project.[/]"
            )

    if args.process or args.exposed:
        bits: list[str] = []
        if args.process:
            bits.append(f"process ~ {escape(args.process)}")
        if args.exposed:
            bits.append("exposed binds only")
        console.print(
            "[dim]filter: "
            + ", ".join(bits)
            + "  |  free ranges still count every occupied port[/]"
        )

    listener_limit = None if args.all else (24 if args.compact else 40)
    if args.compact:
        render_compact_report(
            display,
            console=console,
            row_limit=listener_limit or 10_000,
            free_limit=min(args.free_limit, 8) if not args.all else args.free_limit,
        )
    else:
        render_report(
            display,
            console=console,
            listener_limit=listener_limit,
            free_limit=args.free_limit,
            show_udp_note=not args.tcp_only,
        )


def _run_watch(args: argparse.Namespace, console: Console) -> int:
    """Rescan until Ctrl+C.

    Text mode prints the report once, then only timestamped change lines
    (quiet passes print nothing). ``--json`` prints one compact document per
    pass, so the stream is JSON Lines.
    """
    previous: dict | None = None
    while True:
        inventory = _load_inventory(args)
        display = _for_display(inventory, args)
        try:
            _maybe_snapshot(args, inventory)
            statuses = _expected_statuses(args, inventory)
        except (OSError, ValueError) as exc:
            _error(args, exc)
            return 2
        if args.json:
            print(json.dumps(_json_report(display, statuses), ensure_ascii=False), flush=True)
        elif previous is None:
            _emit_report(args, display, console, statuses)
            console.print(f"[dim]watching every {args.watch:g}s - Ctrl+C to stop[/]")
        else:
            diff = diff_inventory(previous, display)
            if not diff.empty:
                stamp = time.strftime("%H:%M:%S")
                for line in format_diff_lines(diff):
                    print(f"{stamp} {line}", flush=True)
        previous = inventory_to_dict(display)
        time.sleep(args.watch)


def _run(args: argparse.Namespace, console: Console) -> int:
    """Dispatch one invocation to the mode it asked for."""
    if args.kill is not None:
        return _run_kill(args, console)
    if args.stop is not None or args.stop_container is not None:
        return _run_stop(args, console)
    if args.watch is not None:
        return _run_watch(args, console)

    # Read the baseline before anything is written, so
    # ``--snapshot state.json --diff state.json`` compares against the old file.
    before: dict | None = None
    if args.diff is not None:
        try:
            before = load_snapshot(Path(args.diff))
        except (OSError, ValueError) as exc:
            _error(args, exc)
            return 2

    inventory = _load_inventory(args)
    display = _for_display(inventory, args)
    try:
        _maybe_snapshot(args, inventory)
        statuses = _expected_statuses(args, inventory)
    except (OSError, ValueError) as exc:
        _error(args, exc)
        return 2

    if args.port is not None:
        return _run_port(args, inventory, console)
    if args.check is not None:
        return _run_check(args, inventory)
    if args.take is not None:
        return _run_take(args, inventory)
    if args.random:
        return _run_random(args, inventory)
    if before is not None:
        return _run_diff(args, before, inventory)

    _emit_report(args, display, console, statuses)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns a process exit code."""
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)
    console = _console(args)

    try:
        return _run(args, console)
    except KeyboardInterrupt:
        # Ctrl+C is how --watch ends; anywhere else it is an abort.
        return 0 if args.watch is not None else 130
    except BrokenPipeError:
        # ``portsight --json | head`` closed the pipe early. Point stdout at
        # devnull so the interpreter's final flush does not raise again.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
