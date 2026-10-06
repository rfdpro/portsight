"""Discover local sockets and attribute them to processes.

Uses ``psutil.net_connections`` for a netstat-like inventory, then resolves
PIDs to process name, command line, and parent. On Windows this typically
works without elevation for user-owned listeners; system services may still
appear with a PID but a restricted name if access is denied.

Two collections are produced from one pass:

* **listeners** — TCP LISTEN and bound UDP. These occupy a port for the
  free-range math.
* **held** — every other TCP state on a local port (TIME_WAIT, CLOSE_WAIT,
  ESTABLISHED, …). They are not folded into free ranges, because outbound
  ephemeral clients would otherwise erase the dynamic band. Port lookup and
  ``--check`` still see them: TIME_WAIT is a common reason Windows says the
  address is already in use when nothing is listening.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from functools import lru_cache

import psutil

from portsight.models import ListeningService

# Connection.type is a socket.SocketKind value; map to short protocol labels.
_PROTO_BY_TYPE = {
    socket.SOCK_STREAM: "TCP",
    socket.SOCK_DGRAM: "UDP",
}

_ELEVATION_NOTE = (
    "Socket scan was incomplete (access denied). "
    "Re-run from an elevated shell to see listeners owned by system services."
)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Best-effort description of the process that owns a socket."""

    name: str
    path: str
    cmdline: str
    parent_pid: int | None
    parent_name: str


@dataclass(frozen=True, slots=True)
class SocketScan:
    """One pass over the OS socket table.

    Attributes:
        listeners: TCP LISTEN and bound UDP endpoints.
        held: Non-listen TCP sockets, kept for port lookup / ``--check``.
        incomplete: True when the OS refused the table entirely.
        note: Why the scan is incomplete, empty otherwise.
    """

    listeners: list[ListeningService]
    held: list[ListeningService]
    incomplete: bool = False
    note: str = ""


def _empty_identity(name: str) -> ProcessIdentity:
    return ProcessIdentity(name=name, path="", cmdline="", parent_pid=None, parent_name="")


@lru_cache(maxsize=512)
def _process_identity(pid: int | None) -> ProcessIdentity:
    """Resolve name, path, command line, and parent for a PID.

    Caching matters because many sockets share one process (System,
    svchost, a single node process). AccessDenied / NoSuchProcess are
    common for protected PIDs; we keep the PID-shaped name so the row
    is still useful.
    """
    if pid is None or pid <= 0:
        return _empty_identity("unknown")

    try:
        proc = psutil.Process(pid)
        name = proc.name() or f"pid:{pid}"
        try:
            path = proc.exe() or ""
        except (psutil.AccessDenied, psutil.Error):
            path = ""
        try:
            parts = proc.cmdline() or []
            cmdline = " ".join(parts)
        except (psutil.AccessDenied, psutil.Error):
            cmdline = ""

        parent_pid: int | None = None
        parent_name = ""
        try:
            parent = proc.parent()
        except (psutil.AccessDenied, psutil.Error):
            parent = None
        if parent is not None:
            parent_pid = int(parent.pid)
            try:
                parent_name = parent.name() or ""
            except (psutil.AccessDenied, psutil.Error):
                parent_name = ""

        return ProcessIdentity(
            name=name,
            path=path,
            cmdline=cmdline,
            parent_pid=parent_pid,
            parent_name=parent_name,
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return _empty_identity(f"pid:{pid}")
    except psutil.Error:
        return _empty_identity("unknown")


def _service_from_conn(
    *,
    protocol: str,
    address: str,
    port: int,
    pid: int | None,
    state: str,
) -> ListeningService:
    """Build a listener/held row, attaching whatever process detail we can."""
    identity = _process_identity(pid)
    return ListeningService(
        protocol=protocol,
        address=address,
        port=port,
        pid=pid,
        process_name=identity.name,
        process_path=identity.path,
        cmdline=identity.cmdline,
        parent_pid=identity.parent_pid,
        parent_name=identity.parent_name,
        state=state,
    )


def collect_socket_scan(*, include_udp: bool = True) -> SocketScan:
    """Read the OS socket table once and split listeners from other states.

    Args:
        include_udp: When True, bound UDP sockets count as listeners.
            UDP has no LISTEN state; a bound local address is "in use".
    """
    kind = "inet" if include_udp else "tcp"

    try:
        connections = psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        # Empty listeners plus this flag must not be rendered as "nothing
        # is listening" — the CLI prints ``note`` instead.
        return SocketScan(
            listeners=[],
            held=[],
            incomplete=True,
            note=_ELEVATION_NOTE,
        )

    listeners: list[ListeningService] = []
    held: list[ListeningService] = []
    seen_listen: set[tuple[str, str, int, int | None]] = set()
    seen_held: set[tuple[str, str, int, int | None, str]] = set()

    for conn in connections:
        if not conn.laddr:
            continue

        sock_type = int(conn.type)
        is_tcp = sock_type == socket.SOCK_STREAM
        is_udp = sock_type == socket.SOCK_DGRAM
        if not is_tcp and not is_udp:
            continue
        if is_udp and not include_udp:
            continue

        protocol = _PROTO_BY_TYPE.get(sock_type, str(conn.type))
        address = conn.laddr.ip
        port = int(conn.laddr.port)
        pid = conn.pid
        status = str(conn.status or "")

        if is_udp:
            key = (protocol, address, port, pid)
            if key in seen_listen:
                continue
            seen_listen.add(key)
            listeners.append(
                _service_from_conn(
                    protocol=protocol,
                    address=address,
                    port=port,
                    pid=pid,
                    state="BOUND",
                )
            )
            continue

        if status == psutil.CONN_LISTEN:
            key = (protocol, address, port, pid)
            if key in seen_listen:
                continue
            seen_listen.add(key)
            listeners.append(
                _service_from_conn(
                    protocol=protocol,
                    address=address,
                    port=port,
                    pid=pid,
                    state="LISTEN",
                )
            )
            continue

        # Anything else on a local TCP port (TIME_WAIT, ESTABLISHED, …).
        state = status or "UNKNOWN"
        held_key = (protocol, address, port, pid, state)
        if held_key in seen_held:
            continue
        seen_held.add(held_key)
        held.append(
            _service_from_conn(
                protocol=protocol,
                address=address,
                port=port,
                pid=pid,
                state=state,
            )
        )

    listeners.sort(key=lambda s: (s.port, s.protocol, s.address, s.pid or 0))
    held.sort(key=lambda s: (s.port, s.state, s.protocol, s.address, s.pid or 0))
    return SocketScan(listeners=listeners, held=held)


def collect_listening_services(
    *,
    include_udp: bool = True,
) -> list[ListeningService]:
    """Return unique listening endpoints sorted by port then address.

    Thin wrapper over :func:`collect_socket_scan` so existing callers
    (kill, tests) keep the listener-only contract. Prefer the scan object
    when you also need TIME_WAIT rows or the elevation flag.
    """
    return collect_socket_scan(include_udp=include_udp).listeners


def listening_ports(services: list[ListeningService]) -> set[int]:
    """Unique port numbers currently held by at least one listener."""
    return {service.port for service in services}
