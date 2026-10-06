"""Terminate processes that hold a local port so it becomes free to bind.

Flow:
  1. Resolve listeners on the target port (reuse the scanner inventory).
  2. Deduplicate by PID — one process may bind IPv4 + IPv6 on the same port.
  3. Refuse obviously unsafe targets (missing PID, PID 0, current process).
  4. Terminate via psutil; on Windows ``terminate()`` already maps to
     ``TerminateProcess``, so a follow-up ``kill()`` is only needed when the
     process survives the wait window (rare, but kept for cross-platform
     consistency).

Elevation: AccessDenied is common for System / service PIDs (or another
user's processes on Linux / macOS). We surface that clearly so the user
knows to re-run from an elevated shell when needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import psutil

from portsight.models import ListeningService
from portsight.scanner import collect_socket_scan

# PIDs that must never be targeted: the idle / swapper process (0), init or
# launchd (1), and the Windows System process (4). Windows PIDs are multiples
# of four, so 1 never collides there; Linux PID 4 is a kernel thread that
# never owns a socket.
_PROTECTED_PIDS = frozenset({0, 1, 4})


@dataclass(frozen=True, slots=True)
class KillTarget:
    """One unique process selected for termination on a port."""

    pid: int
    process_name: str
    process_path: str
    endpoints: tuple[ListeningService, ...]


@dataclass(slots=True)
class KillOutcome:
    """Result of attempting to free a single port."""

    port: int
    targets: list[KillTarget] = field(default_factory=list)
    killed: list[KillTarget] = field(default_factory=list)
    failed: list[tuple[KillTarget, str]] = field(default_factory=list)
    skipped: list[tuple[KillTarget, str]] = field(default_factory=list)
    message: str = ""
    # Nothing owned the port, so there was nothing to do. Distinct from
    # ``ok``, which means "we killed something".
    already_free: bool = False

    @property
    def ok(self) -> bool:
        """True when at least one process was killed and none failed."""
        return bool(self.killed) and not self.failed


def find_targets_on_port(
    port: int,
    *,
    include_udp: bool = True,
) -> list[KillTarget]:
    """Group listening endpoints on ``port`` into unique kill targets by PID.

    Returns an empty list when nothing is listening — callers should treat
    that as "port already free" rather than an error.
    """
    if not 1 <= port <= 65535:
        raise ValueError(f"port must be in 1-65535, got {port}")

    services = [
        service
        for service in collect_socket_scan(include_udp=include_udp).listeners
        if service.port == port
    ]
    by_pid: dict[int, list[ListeningService]] = {}
    for service in services:
        if service.pid is None:
            continue
        by_pid.setdefault(service.pid, []).append(service)

    targets: list[KillTarget] = []
    for pid, endpoints in sorted(by_pid.items()):
        primary = endpoints[0]
        targets.append(
            KillTarget(
                pid=pid,
                process_name=primary.process_name,
                process_path=primary.process_path,
                endpoints=tuple(endpoints),
            )
        )
    return targets


def _is_self(pid: int) -> bool:
    """True when ``pid`` is this CLI process (or would suicide the shell tool)."""
    try:
        return pid == psutil.Process().pid
    except psutil.Error:
        return False


def kill_targets(
    targets: list[KillTarget],
    *,
    force: bool = False,
    timeout: float = 3.0,
) -> tuple[list[KillTarget], list[tuple[KillTarget, str]], list[tuple[KillTarget, str]]]:
    """Terminate each target; return ``(killed, failed, skipped)``.

    Args:
        targets: Processes resolved for the port.
        force: Prefer an immediate hard kill (``kill()``) instead of a polite
            ``terminate()`` + wait. On Windows both paths use TerminateProcess;
            force mainly short-circuits the wait.
        timeout: Seconds to wait after ``terminate()`` before escalating.
    """
    killed: list[KillTarget] = []
    failed: list[tuple[KillTarget, str]] = []
    skipped: list[tuple[KillTarget, str]] = []

    for target in targets:
        if target.pid in _PROTECTED_PIDS:
            skipped.append(
                (
                    target,
                    f"refusing to kill protected system PID {target.pid}",
                )
            )
            continue
        if _is_self(target.pid):
            skipped.append((target, "refusing to kill the portsight process itself"))
            continue

        try:
            proc = psutil.Process(target.pid)
            # Capture name again in case the scanner cache was stale.
            try:
                live_name = proc.name()
            except psutil.Error:
                live_name = target.process_name

            if force:
                proc.kill()
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout)
                except psutil.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=timeout)

            killed.append(
                KillTarget(
                    pid=target.pid,
                    process_name=live_name or target.process_name,
                    process_path=target.process_path,
                    endpoints=target.endpoints,
                )
            )
        except psutil.NoSuchProcess:
            # Race: process exited between discovery and kill — treat as success.
            killed.append(target)
        except psutil.AccessDenied:
            failed.append(
                (
                    target,
                    "access denied - re-run from an elevated (Administrator) shell",
                )
            )
        except psutil.Error as exc:
            failed.append((target, str(exc) or exc.__class__.__name__))

    return killed, failed, skipped


def free_port(
    port: int,
    *,
    include_udp: bool = True,
    force: bool = False,
    timeout: float = 3.0,
    targets: list[KillTarget] | None = None,
) -> KillOutcome:
    """Kill every non-protected process listening on ``port``.

    Pass ``targets`` when the caller already showed them to the user and
    got confirmation. Re-resolving here would let a process that bound the
    port after the prompt be killed without ever being previewed.
    """
    if targets is None:
        try:
            targets = find_targets_on_port(port, include_udp=include_udp)
        except ValueError as exc:
            return KillOutcome(port=port, message=str(exc))

    if not targets:
        scan = collect_socket_scan(include_udp=include_udp)
        if scan.incomplete:
            # An unreadable socket table is not evidence the port is free.
            return KillOutcome(port=port, message=f"cannot tell who owns port {port}: {scan.note}")

        # Also catch the case where sockets exist but PID was withheld.
        orphan_listeners = [
            service for service in scan.listeners if service.port == port and service.pid is None
        ]
        if orphan_listeners:
            return KillOutcome(
                port=port,
                message=(
                    f"port {port} has listener(s) but no PID was reported "
                    "(insufficient privileges to identify the owner)"
                ),
            )

        # Docker Desktop (WSL2 / VM backends) often publishes ports with no
        # host LISTEN socket — surface the container so the user can stop it.
        from portsight.docker_ports import collect_docker_published_ports

        docker_hits = [
            service for service in collect_docker_published_ports() if service.port == port
        ]
        if docker_hits:
            names = sorted({service.process_name for service in docker_hits})
            name_list = ", ".join(names)
            return KillOutcome(
                port=port,
                message=(
                    f"port {port} is published by Docker ({name_list}) - "
                    "there is no host process to kill. "
                    f"Stop it with: portsight --stop {port} (or docker stop {names[0]})"
                ),
            )

        return KillOutcome(
            port=port,
            message=f"port {port} is already free (no listening process found)",
            already_free=True,
        )

    killed, failed, skipped = kill_targets(
        targets,
        force=force,
        timeout=timeout,
    )
    outcome = KillOutcome(
        port=port,
        targets=targets,
        killed=killed,
        failed=failed,
        skipped=skipped,
    )
    if outcome.ok:
        outcome.message = f"freed port {port}"
    elif killed and failed:
        outcome.message = f"partially freed port {port}"
    elif skipped and not killed and not failed:
        outcome.message = f"could not free port {port} (protected process)"
    else:
        outcome.message = f"failed to free port {port}"
    return outcome
