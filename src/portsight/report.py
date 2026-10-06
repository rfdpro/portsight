"""Rich-powered report rendering for the portsight CLI.

Visual language:
  - Deep teal / amber accents (not purple-on-white AI defaults)
  - Panel header with hostname + timestamp
  - Distinct tables for listeners, reserved ranges, and free bands
  - Summary strip with counts so the eye lands on the big picture first
"""

from __future__ import annotations

from datetime import datetime
from platform import node

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from portsight import __version__
from portsight.docker_stop import DockerStopResult
from portsight.expect import ExpectedStatus
from portsight.kill import KillOutcome, KillTarget
from portsight.lookup import PortLookup, format_lookup_lines
from portsight.models import ListeningService, PortInventory, PortRange
from portsight.ranges import largest_ranges, summarize_free_ports
from portsight.system_ranges import reserved_ranges_supported

# Palette — teal harbor meets warm signal lights.
C_TEAL = "#2EC4B6"
C_TEAL_DIM = "#1A9B8E"
C_AMBER = "#FFBF69"
C_CORAL = "#FF6B6B"
C_SLATE = "#8B9BB4"
C_FOG = "#C5D0E0"
C_BORDER = C_TEAL_DIM


def _stat_panel(title: str, value: str, subtitle: str, accent: str) -> Panel:
    """Small KPI tile used in the summary strip."""
    body = Text()
    body.append(value, style=f"bold {accent}")
    body.append("\n")
    body.append(subtitle, style=C_SLATE)
    return Panel(
        Align.center(body),
        title=f"[{accent}]{title}[/]",
        title_align="center",
        border_style=accent,
        box=box.ROUNDED,
        padding=(0, 2),
        expand=True,
    )


def _header() -> Panel:
    """Top banner identifying the tool and host context."""
    host = node() or "localhost"
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = Text()
    title.append("*  PORTSIGHT", style=f"bold {C_TEAL}")
    title.append("  |  ", style=C_SLATE)
    title.append(f"v{__version__}", style=C_FOG)
    title.append("\n")
    title.append(f"host {host}", style=C_AMBER)
    title.append("  |  ", style=C_SLATE)
    title.append(stamp, style=C_SLATE)
    title.append("\n")
    title.append(
        "local listeners  |  reserved exclusions  |  free ranges",
        style=C_SLATE,
    )
    return Panel(
        Align.center(title),
        border_style=C_BORDER,
        box=box.DOUBLE_EDGE,
        padding=(1, 2),
    )


def _summary_strip(inventory: PortInventory) -> Columns:
    """KPI panels: host listeners, Docker publishes, reserved, free ports."""
    listener_count = len(inventory.listening)
    docker_count = len(inventory.docker)
    reserved_count = len(inventory.reserved)
    free_ports = summarize_free_ports(inventory.free)

    return Columns(
        [
            _stat_panel("HOST", str(listener_count), "OS listeners", C_CORAL),
            _stat_panel("DOCKER", str(docker_count), "published ports", "#6C8CFF"),
            _stat_panel("RESERVED", str(reserved_count), "exclusions", C_AMBER),
            _stat_panel("FREE", f"{free_ports:,}", "bindable now", C_TEAL),
        ],
        equal=True,
        expand=True,
    )


def _listeners_table(services: list[ListeningService], *, limit: int | None) -> Table:
    """Table of listening services with process attribution."""
    table = Table(
        title="Listening Services",
        title_style=f"bold {C_TEAL}",
        box=box.SIMPLE_HEAVY,
        border_style=C_BORDER,
        header_style=f"bold {C_AMBER}",
        row_styles=["", "dim"],
        show_lines=False,
        pad_edge=False,
        expand=True,
    )
    table.add_column("Proto", style=C_FOG, width=6)
    table.add_column("Port", justify="right", style=f"bold {C_TEAL}", width=7)
    table.add_column("Address", style=C_FOG, overflow="fold")
    table.add_column("PID", justify="right", style=C_SLATE, width=8)
    table.add_column("Process", style="white", overflow="fold")
    table.add_column("Command", style=C_SLATE, overflow="fold")

    rows = services if limit is None else services[:limit]
    for service in rows:
        pid = "-" if service.pid is None else str(service.pid)
        # Parent is what separates two node.exe rows when the command line
        # itself is truncated or was hidden by the OS.
        who = service.process_name
        if service.parent_name:
            who = f"{who}  <-  {service.parent_name}"
        table.add_row(
            service.protocol,
            str(service.port),
            service.address,
            pid,
            who,
            service.cmdline or "-",
        )

    if limit is not None and len(services) > limit:
        table.caption = (
            f"[dim]showing {limit} of {len(services)} - use --all to list every listener[/]"
        )
    elif not services:
        table.caption = "[dim]no listening sockets discovered[/]"

    return table


def _docker_table(services: list[ListeningService], *, limit: int | None) -> Table:
    """Published Docker host ports (often invisible to Windows netstat)."""
    docker_blue = "#6C8CFF"
    table = Table(
        title="Docker Published Ports",
        title_style=f"bold {docker_blue}",
        box=box.SIMPLE_HEAVY,
        border_style=docker_blue,
        header_style=f"bold {docker_blue}",
        row_styles=["", "dim"],
        pad_edge=False,
        expand=True,
    )
    table.add_column("Proto", style=C_FOG, width=6)
    table.add_column("Host port", justify="right", style=f"bold {docker_blue}", width=10)
    table.add_column("Address", style=C_FOG, overflow="fold")
    table.add_column("Container", style="white", overflow="fold")
    table.add_column("Maps", style=C_SLATE, width=14)

    rows = services if limit is None else services[:limit]
    for service in rows:
        table.add_row(
            service.protocol,
            str(service.port),
            service.address,
            service.process_name,
            service.detail or "-",
        )

    if not services:
        table.caption = "[dim]no published container ports (or Docker CLI unavailable)[/]"
    elif limit is not None and len(services) > limit:
        table.caption = (
            f"[dim]showing {limit} of {len(services)} - use -a/--all for every publish[/]"
        )
    else:
        table.caption = (
            "[dim]Docker Desktop often forwards these without a host socket; "
            "portsight reads them via docker ps[/]"
        )
    return table


def _reserved_table(ranges: list[PortRange], *, supported: bool) -> Table:
    """Windows excluded / reserved port ranges."""
    table = Table(
        title="Reserved / Unallocated Ranges",
        title_style=f"bold {C_AMBER}",
        box=box.SIMPLE_HEAVY,
        border_style=C_AMBER,
        header_style=f"bold {C_AMBER}",
        row_styles=["", "dim"],
        expand=True,
    )
    table.add_column("Range", style=f"bold {C_AMBER}", width=16)
    table.add_column("Ports", justify="right", style=C_FOG, width=8)
    table.add_column("Admin", justify="center", style=C_SLATE, width=6)
    table.add_column("Notes", style=C_SLATE, overflow="fold")

    if not ranges:
        note = (
            "no exclusions reported by netsh"
            if supported
            else "excluded port ranges are Windows-only; nothing to show on this OS"
        )
        table.add_row("-", "0", "-", note)
        return table

    for port_range in ranges:
        admin = "*" if port_range.administered else "-"
        table.add_row(
            port_range.label(),
            str(port_range.size),
            admin,
            port_range.note or "system exclusion",
        )

    table.caption = (
        f"[dim]* = administered exclusion  |  "
        f"{len(ranges)} range(s) from Windows excludedportrange  |  "
        "Hyper-V / WinNAT exclusions block binds even with no listener; "
        "elevated: net stop winnat & net start winnat[/]"
    )
    return table


def _free_table(
    title: str,
    ranges: list[PortRange],
    *,
    accent: str,
    limit: int,
    empty_message: str,
) -> Table:
    """Generic free-range table for a port band or highlight list."""
    table = Table(
        title=title,
        title_style=f"bold {accent}",
        box=box.SIMPLE_HEAVY,
        border_style=accent,
        header_style=f"bold {accent}",
        row_styles=["", "dim"],
        expand=True,
    )
    table.add_column("Range", style=f"bold {accent}", width=18)
    table.add_column("Size", justify="right", style=C_FOG, width=8)
    table.add_column("Suggested pick", style=C_SLATE, width=14)
    table.add_column("Band notes", style=C_SLATE, overflow="fold")

    if not ranges:
        table.add_row("-", "0", "-", empty_message)
        return table

    shown = ranges[:limit]
    for port_range in shown:
        # Suggest the midpoint of large spans, else the start — a practical
        # default when someone needs "give me a free port" quickly.
        if port_range.size == 1 or port_range.size <= 4:
            pick = str(port_range.start)
        else:
            pick = str(port_range.start + min(10, port_range.size // 4))

        table.add_row(
            port_range.label(),
            f"{port_range.size:,}",
            pick,
            port_range.note or "available",
        )

    total = summarize_free_ports(ranges)
    if len(ranges) > limit:
        table.caption = (
            f"[dim]showing {limit} of {len(ranges)} spans  |  {total:,} free ports in this view[/]"
        )
    else:
        table.caption = f"[dim]{total:,} free ports across {len(ranges)} span(s)[/]"

    return table


def _dynamic_note(dynamic: list[PortRange]) -> Text:
    """One-liner describing the Windows ephemeral pool."""
    text = Text()
    if not dynamic:
        text.append("Dynamic port pool: ", style=C_SLATE)
        text.append("unavailable (the OS did not report one)", style=C_CORAL)
        return text

    pool = dynamic[0]
    text.append("Dynamic / ephemeral pool: ", style=C_SLATE)
    text.append(pool.label(), style=f"bold {C_FOG}")
    text.append(f"  ({pool.size:,} ports)", style=C_SLATE)
    if pool.note:
        text.append(f"  - {pool.note}", style="dim")
    return text


def _legend() -> Text:
    """Footer legend so color coding stays self-explanatory."""
    text = Text(justify="center")
    text.append("legend  ", style=C_SLATE)
    text.append("* host ", style=C_CORAL)
    text.append("* docker ", style="#6C8CFF")
    text.append("* reserved ", style=C_AMBER)
    text.append("* free ", style=C_TEAL)
    text.append(
        "| free = not host-bound, not Docker-published, not OS-excluded",
        style="dim",
    )
    return text


def _docker_note(inventory: PortInventory) -> Text:
    """Explain Docker visibility when it is present, empty, or unreachable."""
    text = Text()
    if inventory.docker:
        text.append("Docker: ", style=C_SLATE)
        text.append(f"{len(inventory.docker)} published host port(s)", style="bold #6C8CFF")
        text.append(
            "  - counted as occupied even when no host socket shows them",
            style="dim",
        )
    elif inventory.docker_available:
        text.append("Docker: ", style=C_SLATE)
        text.append("CLI reachable, no published ports", style=C_FOG)
    else:
        text.append("Docker: ", style=C_SLATE)
        text.append("not scanned (skipped, CLI missing, or daemon not running)", style="dim")
    return text


def _scan_warning(inventory: PortInventory) -> Text | None:
    """Elevation note when the socket table could not be read.

    An empty listener table plus this warning is the difference between
    "nothing is listening" and "we were not allowed to look".
    """
    if not inventory.scan_incomplete:
        return None
    text = Text()
    text.append("Scan incomplete. ", style=f"bold {C_CORAL}")
    text.append(inventory.scan_note or "Access denied while reading sockets.", style=C_CORAL)
    return text


def render_report(
    inventory: PortInventory,
    *,
    console: Console | None = None,
    listener_limit: int | None = 40,
    free_limit: int = 15,
    show_udp_note: bool = True,
) -> None:
    """Print the full aesthetic report to the terminal."""
    console = console or Console()

    sections: list = [
        _header(),
        Text(""),
        _summary_strip(inventory),
    ]
    warning = _scan_warning(inventory)
    if warning is not None:
        sections.extend([Text(""), warning])
    sections.extend(
        [
            Text(""),
            _dynamic_note(inventory.dynamic),
            Text(""),
            _docker_note(inventory),
            Text(""),
            Rule("Active host listeners", style=C_BORDER),
            _listeners_table(inventory.listening, limit=listener_limit),
            Text(""),
            Rule("Docker published ports", style="#6C8CFF"),
            _docker_table(inventory.docker, limit=listener_limit),
            Text(""),
            Rule("Reserved / excluded (Windows)", style=C_AMBER),
            _reserved_table(inventory.reserved, supported=reserved_ranges_supported()),
            Text(""),
            Rule("Largest free ranges", style=C_TEAL),
            _free_table(
                "Roomiest Free Blocks",
                largest_ranges(inventory.free, limit=free_limit),
                accent=C_TEAL,
                limit=free_limit,
                empty_message="no free ports in the scanned space",
            ),
            Text(""),
            Rule("Free by IANA band", style=C_FOG),
            _free_table(
                "Well-known  (1-1023)",
                inventory.well_known_free,
                accent=C_CORAL,
                limit=free_limit,
                empty_message="no free well-known ports",
            ),
            Text(""),
            _free_table(
                "Registered  (1024-49151)",
                inventory.registered_free,
                accent=C_AMBER,
                limit=free_limit,
                empty_message="no free registered ports",
            ),
            Text(""),
            _free_table(
                "Dynamic / private  (49152-65535)",
                inventory.ephemeral_free,
                accent=C_FOG,
                limit=free_limit,
                empty_message="no free ephemeral ports",
            ),
            Text(""),
            _legend(),
        ]
    )

    if show_udp_note:
        sections.append(
            Text(
                "\nUDP host binds included; reserved merges TCP+UDP exclusions; "
                "Docker publishes counted as occupied.",
                style="dim",
                justify="center",
            )
        )

    console.print(
        Panel(
            Group(*sections),
            border_style=C_BORDER,
            box=box.ROUNDED,
            padding=(1, 2),
            title=f"[{C_TEAL}]port inventory[/]",
            subtitle=f"[dim]portsight {__version__}[/]",
        )
    )


def render_compact_report(
    inventory: PortInventory,
    *,
    console: Console | None = None,
    row_limit: int = 24,
    free_limit: int = 8,
) -> None:
    """Dense single-panel view: summary, top in-use ports, top free spans."""
    console = console or Console()
    docker_blue = "#6C8CFF"

    # Collapse dual-stack / multi-address noise: one row per (source, port, name).
    in_use: dict[tuple[str, int, str], ListeningService] = {}
    for service in inventory.listening + inventory.docker:
        key = (service.source, service.port, service.process_name)
        existing = in_use.get(key)
        if existing is None or (
            service.address in ("0.0.0.0", "::")
            and existing.address
            not in (
                "0.0.0.0",
                "::",
            )
        ):
            in_use[key] = service

    use_table = Table(
        title="In use",
        title_style=f"bold {C_AMBER}",
        box=box.SIMPLE,
        border_style=C_BORDER,
        header_style=f"bold {C_AMBER}",
        pad_edge=False,
        expand=True,
        show_edge=False,
    )
    use_table.add_column("Src", width=6, style=C_SLATE)
    use_table.add_column("Port", justify="right", style=f"bold {C_TEAL}", width=7)
    use_table.add_column("Proto", width=5, style=C_FOG)
    use_table.add_column("Who", style="white", overflow="fold")

    rows = sorted(in_use.values(), key=lambda s: (s.port, s.source, s.process_name))
    shown = rows[:row_limit]
    for service in shown:
        who = service.process_name
        if service.source == "docker" and service.detail:
            who = f"{who} {service.detail}"
        elif service.pid is not None:
            who = f"{who} ({service.pid})"
        if service.parent_name:
            who = f"{who} <- {service.parent_name}"
        if service.cmdline:
            who = f"{who}  {service.cmdline}"
        src_style = docker_blue if service.source == "docker" else C_CORAL
        use_table.add_row(
            Text(service.source[:6], style=src_style),
            str(service.port),
            service.protocol,
            who,
        )

    if len(rows) > row_limit:
        use_table.caption = f"[dim]{row_limit}/{len(rows)} in-use rows - use -a for full[/]"

    free_table = _free_table(
        "Top free spans",
        largest_ranges(inventory.free, limit=free_limit),
        accent=C_TEAL,
        limit=free_limit,
        empty_message="no free ports",
    )

    console.print(
        Panel(
            Group(
                _header(),
                Text(""),
                _summary_strip(inventory),
                *([Text(""), warning] if (warning := _scan_warning(inventory)) else []),
                Text(""),
                _docker_note(inventory),
                Text(""),
                use_table,
                Text(""),
                free_table,
                Text(""),
                Text(
                    "compact view  |  portsight -c  |  random free: portsight -r",
                    style="dim",
                    justify="center",
                ),
            ),
            border_style=C_BORDER,
            box=box.ROUNDED,
            padding=(1, 1),
            title=f"[{C_TEAL}]portsight compact[/]",
            subtitle=f"[dim]v{__version__}[/]",
        )
    )


def _endpoint_summary(target: KillTarget) -> str:
    """Compact ``TCP 127.0.0.1, TCP ::`` style list for a kill target."""
    parts = [f"{ep.protocol} {ep.address}" for ep in target.endpoints]
    return ", ".join(parts) if parts else "-"


def render_kill_preview(
    port: int,
    targets: list[KillTarget],
    *,
    console: Console | None = None,
) -> None:
    """Show what would be killed before asking for confirmation."""
    console = console or Console()
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style=C_AMBER,
        header_style=f"bold {C_AMBER}",
        expand=True,
        pad_edge=False,
    )
    table.add_column("PID", justify="right", style=f"bold {C_CORAL}", width=8)
    table.add_column("Process", style="white")
    table.add_column("Bound on", style=C_FOG, overflow="fold")

    for target in targets:
        table.add_row(str(target.pid), target.process_name, _endpoint_summary(target))

    console.print(
        Panel(
            Group(
                Text(
                    f"About to free port {port} by stopping:",
                    style=f"bold {C_AMBER}",
                    justify="center",
                ),
                Text(""),
                table,
            ),
            border_style=C_AMBER,
            box=box.ROUNDED,
            title=f"[{C_AMBER}]kill preview[/]",
            subtitle=f"[dim]portsight {__version__}[/]",
            padding=(1, 2),
        )
    )


def render_kill_result(
    outcome: KillOutcome,
    *,
    console: Console | None = None,
) -> None:
    """Aesthetic status panel for a ``--kill`` attempt."""
    console = console or Console()

    if outcome.ok:
        accent = C_TEAL
        status = "FREED"
    elif outcome.killed:
        accent = C_AMBER
        status = "PARTIAL"
    elif outcome.already_free:
        accent = C_TEAL
        status = "ALREADY FREE"
    else:
        accent = C_CORAL
        status = "FAILED"

    header = Text(justify="center")
    header.append(f"*  PORT {outcome.port}  ", style=f"bold {accent}")
    header.append(status, style=f"bold {accent}")
    header.append("\n")
    header.append(outcome.message, style=C_SLATE)

    sections: list = [header, Text("")]

    if outcome.killed:
        table = Table(
            title="Terminated",
            title_style=f"bold {C_TEAL}",
            box=box.SIMPLE_HEAVY,
            border_style=C_TEAL,
            header_style=f"bold {C_TEAL}",
            expand=True,
        )
        table.add_column("PID", justify="right", width=8)
        table.add_column("Process", style="white")
        table.add_column("Was bound on", style=C_FOG, overflow="fold")
        for target in outcome.killed:
            table.add_row(
                str(target.pid),
                target.process_name,
                _endpoint_summary(target),
            )
        sections.extend([table, Text("")])

    if outcome.skipped:
        table = Table(
            title="Skipped",
            title_style=f"bold {C_AMBER}",
            box=box.SIMPLE_HEAVY,
            border_style=C_AMBER,
            header_style=f"bold {C_AMBER}",
            expand=True,
        )
        table.add_column("PID", justify="right", width=8)
        table.add_column("Process", style="white")
        table.add_column("Reason", style=C_SLATE, overflow="fold")
        for target, reason in outcome.skipped:
            table.add_row(str(target.pid), target.process_name, reason)
        sections.extend([table, Text("")])

    if outcome.failed:
        table = Table(
            title="Failed",
            title_style=f"bold {C_CORAL}",
            box=box.SIMPLE_HEAVY,
            border_style=C_CORAL,
            header_style=f"bold {C_CORAL}",
            expand=True,
        )
        table.add_column("PID", justify="right", width=8)
        table.add_column("Process", style="white")
        table.add_column("Reason", style=C_SLATE, overflow="fold")
        for target, reason in outcome.failed:
            table.add_row(str(target.pid), target.process_name, reason)
        sections.extend([table, Text("")])

    console.print(
        Panel(
            Group(*sections),
            border_style=accent,
            box=box.ROUNDED,
            title=f"[{accent}]kill port[/]",
            subtitle=f"[dim]portsight {__version__}[/]",
            padding=(1, 2),
        )
    )


def render_port_lookup(
    lookup: PortLookup,
    *,
    console: Console | None = None,
) -> None:
    """Panel for ``--port``. Text matches :func:`format_lookup_lines`."""
    console = console or Console()
    accent = C_TEAL if lookup.free else C_CORAL
    body = Text()
    lines = format_lookup_lines(lookup)
    for index, line in enumerate(lines):
        if index:
            body.append("\n")
        body.append(line, style=f"bold {accent}" if index == 0 else C_FOG)
    console.print(
        Panel(
            body,
            border_style=accent,
            box=box.ROUNDED,
            title=f"[{accent}]port {lookup.port}[/]",
            subtitle=f"[dim]portsight {__version__}[/]",
            padding=(1, 2),
        )
    )


def render_expected(
    statuses: list[ExpectedStatus],
    *,
    console: Console | None = None,
) -> None:
    """Table of planned ports and what currently holds each one."""
    console = console or Console()
    table = Table(
        title="Expected ports",
        title_style=f"bold {C_TEAL}",
        box=box.SIMPLE_HEAVY,
        border_style=C_BORDER,
        header_style=f"bold {C_AMBER}",
        expand=True,
        pad_edge=False,
    )
    table.add_column("Port", justify="right", style=f"bold {C_TEAL}", width=7)
    table.add_column("Status", width=10)
    table.add_column("Label", style=C_FOG, overflow="fold")
    table.add_column("Origin", style=C_SLATE, overflow="fold")
    table.add_column("Detail", style="white", overflow="fold")

    accents = {
        "free": C_TEAL,
        "host": C_CORAL,
        "docker": "#6C8CFF",
        "reserved": C_AMBER,
        "held": C_SLATE,
    }
    if not statuses:
        table.add_row("-", "-", "-", "-", "no expected ports")
    for status in statuses:
        accent = accents.get(status.status, C_FOG)
        label = status.expected.label or "-"
        table.add_row(
            str(status.expected.port),
            Text(status.status, style=f"bold {accent}"),
            label,
            status.expected.origin,
            status.detail or "-",
        )

    console.print(
        Panel(
            table,
            border_style=C_BORDER,
            box=box.ROUNDED,
            title=f"[{C_TEAL}]project ports[/]",
            subtitle=f"[dim]portsight {__version__}[/]",
            padding=(1, 2),
        )
    )


def render_stop_result(
    result: DockerStopResult,
    *,
    console: Console | None = None,
) -> None:
    """Panel for a ``docker stop`` attempt."""
    console = console or Console()
    accent = C_TEAL if result.ok else C_CORAL
    body = Text()
    body.append(result.message or "docker stop finished", style=f"bold {accent}")
    if result.stopped:
        body.append("\n")
        body.append("stopped: " + ", ".join(result.stopped), style=C_TEAL)
    for name, reason in result.failed:
        body.append("\n")
        body.append(f"{name}: {reason}", style=C_CORAL)
    console.print(
        Panel(
            body,
            border_style=accent,
            box=box.ROUNDED,
            title=f"[{accent}]docker stop[/]",
            subtitle=f"[dim]portsight {__version__}[/]",
            padding=(1, 2),
        )
    )
