"""Plan and execute ``docker stop`` for a container that publishes a host port.

Why this exists
---------------
``kill.py`` can only terminate a host process. Docker Desktop (WSL2 on
Windows, a VM on macOS) often publishes ``0.0.0.0:PORT->...`` without a host
LISTEN socket and without a PID, so process kill cannot free the port. The container
has to be stopped with the Docker CLI instead.

This module does two separate jobs:

1. :func:`plan_docker_stop` decides *which* container names to stop. It does
   not spawn anything, so the CLI can show the plan and tests can cover every
   branch without Docker installed.
2. :func:`stop_containers` runs ``docker stop <name>`` once per name. Names
   are passed as an argv list (never through a shell).

Callers pass ``docker_available`` in from :func:`portsight.docker_ports.docker_available`.
This module does not import that helper, so importing or planning never
touches the Docker CLI.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from portsight.models import ListeningService

# Docker container names (and short hex ids) are a small alphabet. We pass
# them as argv, so the shell cannot interpret them, but a typo like
# "web; rm -rf" or a path should still be rejected before we hand it to
# ``docker stop``. Length cap matches Docker's own name limit (128).
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# ``subprocess.run(argv, timeout)`` is wrong: the second positional argument
# is ``input``, not ``timeout``. The default runner therefore wraps
# ``subprocess.run`` and always passes timeout by keyword. Fakes only need
# ``returncode`` and ``stderr``; they do not have to be a real CompletedProcess.
Runner = Callable[[list[str], int], subprocess.CompletedProcess[str]]


def validate_container_name(name: str) -> str:
    """Return the stripped name, or raise ``ValueError`` if it is unsafe.

    Empty / whitespace-only names and anything outside
    ``[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`` are rejected. We still pass the
    accepted name as a single argv element (no shell), but rejecting odd
    names means a typo cannot target something surprising.
    """
    if not isinstance(name, str):
        raise ValueError(f"invalid container name: expected str, got {type(name).__name__}")

    cleaned = name.strip()
    if not cleaned or _NAME_RE.fullmatch(cleaned) is None:
        raise ValueError(
            "invalid container name "
            f"{name!r}: expected 1-128 characters starting with a letter or "
            "digit, then only letters, digits, '_', '.', or '-'"
        )
    return cleaned


@dataclass(slots=True)
class DockerStopPlan:
    """What :func:`plan_docker_stop` decided, before any ``docker`` process runs.

    Attributes:
        containers: Unique container names, sorted. Empty when there is
            nothing safe to stop.
        port: Host port the plan was built for, or ``None`` when the caller
            asked to stop by name only.
        message: Human summary the CLI can print as-is.
        ok_to_run: ``False`` when there is nothing to stop, Docker is missing,
            or the port is not published by a container. ``True`` only when
            ``containers`` is non-empty and the Docker CLI is available.
    """

    containers: list[str]
    port: int | None
    message: str
    ok_to_run: bool


def _require_port(port: int) -> None:
    """Raise ``ValueError`` unless ``port`` is a real TCP/UDP port number.

    Bool is rejected explicitly because ``bool`` is a subclass of ``int``
    (``True == 1``) and must not be treated as a port.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"port must be in 1-65535, got {port}")


def _names_publishing(port: int, services: list[ListeningService]) -> list[str]:
    """Unique Docker container names that publish ``port``, sorted.

    Host listeners on the same port are ignored: they have a PID and belong
    to process kill, not ``docker stop``. ``detail`` (for example
    ``->8080/tcp``) is display-only and is not parsed here — the inventory
    row already recorded the host port.

    Blank ``process_name`` values are dropped. A row with no name is not a
    container we can target, and we must not invent one.
    """
    names: set[str] = set()
    for service in services:
        if service.source != "docker" or service.port != port:
            continue
        # process_name is the container name on docker rows; process_path
        # is the container id. Stopping by the name from the inventory is
        # what the user sees in ``docker ps``.
        name = (service.process_name or "").strip()
        if not name:
            continue
        names.add(name)
    return sorted(names)


def plan_docker_stop(
    *,
    port: int | None = None,
    name: str | None = None,
    services: list[ListeningService],
    docker_available: bool,
) -> DockerStopPlan:
    """Resolve which containers to stop. Does not run Docker.

    Selection rules, in order:

    * A provided ``port`` must be in 1..65535, otherwise ``ValueError``.
      This is checked even when ``name`` is also set, so a bad port never
      hides behind a name-based plan.
    * If ``name`` is set (including empty string), it is validated and is
      the only stop target. It does not have to appear in ``services`` —
      the user may already know the container name. When both ``name`` and
      ``port`` are passed, the name wins for *which* container to stop and
      the port is only recorded on the plan.
    * If ``port`` is set and ``name`` is not, select services with
      ``source == "docker"`` and a matching host port. Names are unique
      and sorted. Host listeners on that port are ignored.
    * If neither ``name`` nor ``port`` is set, there is nothing to stop.

    ``ok_to_run`` is ``False`` when Docker is missing, when the port has no
    container publisher, or when the caller gave neither a name nor a port.
    A missing Docker CLI is reported even if containers were resolved, so
    the CLI does not attempt a stop that cannot start.
    """
    if port is not None:
        _require_port(port)

    # ``name is not None`` treats "" as "the user asked to stop by name"
    # so validate_container_name can reject it, rather than silently
    # falling through to a port plan.
    if name is not None:
        containers = [validate_container_name(name)]
        selected_by_name = True
    elif port is not None:
        containers = _names_publishing(port, services)
        selected_by_name = False
    else:
        containers = []
        selected_by_name = False

    if not docker_available:
        # Resolved names stay on the plan so the CLI can say *what* it
        # would have stopped, but nothing may be executed.
        return DockerStopPlan(
            containers=containers,
            port=port,
            message="Docker is not reachable (CLI missing or daemon not running)",
            ok_to_run=False,
        )

    if not containers:
        if port is not None:
            # Do not invent a ``docker stop``. The port may belong to a
            # normal host process, which is kill.py's job.
            message = f"no container publishes port {port}; a host process may own it"
        else:
            message = "nothing to stop (no port or container name was given)"
        return DockerStopPlan(
            containers=[],
            port=port,
            message=message,
            ok_to_run=False,
        )

    if selected_by_name:
        message = f"stop container {containers[0]}"
    elif len(containers) == 1:
        message = f"stop container {containers[0]} publishing port {port}"
    else:
        listed = ", ".join(containers)
        message = f"stop containers {listed} publishing port {port}"

    return DockerStopPlan(
        containers=containers,
        port=port,
        message=message,
        ok_to_run=True,
    )


@dataclass(slots=True)
class DockerStopResult:
    """Outcome of :func:`stop_containers`.

    Attributes:
        containers: Names considered, in request order, after stripping and
            de-duplication. Invalid names are included so the caller can see
            what was rejected.
        stopped: Names whose ``docker stop`` exited 0.
        failed: ``(name, error)`` for validation failures and non-zero exits.
        message: Human summary.
    """

    containers: list[str]
    stopped: list[str]
    failed: list[tuple[str, str]]
    message: str

    @property
    def ok(self) -> bool:
        """True only when at least one container stopped and none failed.

        A partial stop is not success: the port may still be published by
        a container that we failed to stop.
        """
        return bool(self.stopped) and not self.failed


def _default_runner(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` with ``subprocess.run`` and no console window.

    ``shell`` is left at its default (``False``). ``CREATE_NO_WINDOW`` is set
    only when the attribute exists (Windows). On other platforms the flag is
    omitted so we do not pass a Windows-only keyword that older Pythons reject.

    ``timeout`` is the subprocess timeout, not Docker's internal stop grace
    period (``docker stop -t``, default 10s). Callers that expect a slow
    container shutdown should pass a ``timeout`` larger than that grace.
    """
    kwargs: dict[str, object] = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "check": False,
        "timeout": timeout,
    }
    # Present on Windows. Skipping it elsewhere keeps the call portable for
    # unit tests that exercise the default runner under a patched subprocess.
    create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", None)
    if create_no_window is not None:
        kwargs["creationflags"] = create_no_window
    return subprocess.run(argv, **kwargs)


def _stderr_message(stderr: str | bytes | None) -> str:
    """Prefer Docker's stderr; fall back when the CLI said nothing useful."""
    if stderr is None:
        return "docker stop failed"
    if isinstance(stderr, bytes):
        text = stderr.decode("utf-8", errors="replace")
    else:
        text = str(stderr)
    text = text.strip()
    return text or "docker stop failed"


def _result_message(stopped: list[str], failed: list[tuple[str, str]]) -> str:
    """One line the CLI can print after a stop attempt."""
    if stopped and not failed:
        if len(stopped) == 1:
            return f"stopped container {stopped[0]}"
        return f"stopped {len(stopped)} containers: {', '.join(stopped)}"
    if failed and not stopped:
        if len(failed) == 1:
            name, error = failed[0]
            return f"failed to stop {name}: {error}"
        names = ", ".join(name for name, _error in failed)
        return f"failed to stop {len(failed)} containers: {names}"
    if stopped and failed:
        failed_names = ", ".join(name for name, _error in failed)
        return f"stopped {', '.join(stopped)}; failed {failed_names}"
    return "nothing to stop"


def stop_containers(
    names: list[str],
    *,
    timeout: int = 10,
    runner: Runner | None = None,
) -> DockerStopResult:
    """Run ``docker stop <name>`` once per container.

    ``runner`` defaults to a wrapper around ``subprocess.run`` (not
    ``subprocess.run`` itself — see :func:`_default_runner`). Tests inject a
    fake with the signature ``runner(argv: list[str], timeout: int)`` that
    returns an object with ``returncode`` and ``stderr``.

    Each name is validated before it is executed. Invalid names are recorded
    in ``failed`` and are not passed to the runner. Duplicate names are
    stopped once, in first-seen order.

    A non-zero return code records stderr, or ``"docker stop failed"`` when
    stderr is empty. ``OSError`` and ``subprocess.TimeoutExpired`` record
    ``str(exc)`` and the loop continues with the next name so one failure
    does not skip the rest of the plan.
    """
    if runner is None:
        runner = _default_runner

    containers: list[str] = []
    stopped: list[str] = []
    failed: list[tuple[str, str]] = []
    # De-dupe by the label we would display. Valid names use the stripped
    # form so "web" and " web " are the same container.
    seen: set[str] = set()

    for raw_name in names:
        try:
            cleaned = validate_container_name(raw_name)
        except ValueError as exc:
            # Keep a stable label for the failure row. A whitespace-only
            # name has nothing left after strip, so show the original text.
            if isinstance(raw_name, str):
                label = raw_name.strip() or raw_name
            else:
                label = str(raw_name)
            if label in seen:
                continue
            seen.add(label)
            containers.append(label)
            failed.append((label, str(exc)))
            # Do not call the runner. An invalid name must never become argv.
            continue

        if cleaned in seen:
            continue
        seen.add(cleaned)
        containers.append(cleaned)

        argv = ["docker", "stop", cleaned]
        try:
            completed = runner(argv, timeout)
        except subprocess.TimeoutExpired as exc:
            failed.append((cleaned, str(exc) or "docker stop timed out"))
            continue
        except OSError as exc:
            failed.append((cleaned, str(exc) or exc.__class__.__name__))
            continue

        returncode = getattr(completed, "returncode", None)
        if returncode == 0:
            stopped.append(cleaned)
            continue

        # Missing returncode is treated as failure: a fake runner that
        # forgets the attribute must not look like success.
        failed.append((cleaned, _stderr_message(getattr(completed, "stderr", None))))

    return DockerStopResult(
        containers=containers,
        stopped=stopped,
        failed=failed,
        message=_result_message(stopped, failed),
    )
