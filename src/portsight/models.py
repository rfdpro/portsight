"""Shared data models for port inventory and range reporting.

Keeping these as plain dataclasses (rather than dicts) makes the scanner,
Windows exclusion parser, free-range calculator, and Rich report layer
share one clear contract without stringly-typed keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# States that can make ``bind()`` fail on Windows even though nothing is
# accepting connections. ESTABLISHED is intentionally absent: it is reported
# on the port, but a lone established socket is usually the client side of
# an outbound connection and should not by itself fail ``--check``.
BIND_BLOCKING_STATES = frozenset(
    {
        "TIME_WAIT",
        "CLOSE_WAIT",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "LAST_ACK",
        "CLOSE",
        "CLOSING",
    }
)


@dataclass(frozen=True, slots=True)
class ListeningService:
    """A single local endpoint that is currently accepting connections.

    Attributes:
        protocol: Transport label such as ``TCP`` or ``UDP``.
        address: Bound local IP (``0.0.0.0``, ``::``, loopback, etc.).
        port: Local port number in the 0–65535 space.
        pid: Owning process id when known; ``None`` if the OS withheld it.
        process_name: Executable basename, or Docker container name.
        process_path: Full image path, or Docker container id.
        source: ``host`` for OS sockets, ``docker`` for published container
            ports discovered via ``docker ps`` (needed on Docker Desktop
            WSL2 where host netstat often shows nothing).
        detail: Extra label such as a container mapping (``->8080/tcp``).
        cmdline: Full process command line when the OS allowed us to read it.
            This is what distinguishes one ``node.exe`` from another.
        parent_pid / parent_name: Parent process, same reason.
        state: Socket state. Listeners use ``LISTEN`` (TCP) or ``BOUND``
            (UDP). Non-listen rows (``TIME_WAIT``, ``CLOSE_WAIT``, …) use
            the OS status so a port lookup can explain bind failures.
    """

    protocol: str
    address: str
    port: int
    pid: int | None
    process_name: str
    process_path: str = ""
    source: str = "host"
    detail: str = ""
    cmdline: str = ""
    parent_pid: int | None = None
    parent_name: str = ""
    state: str = "LISTEN"


def endpoint_label(address: str, port: object) -> str:
    """``host:port``, with brackets around bare IPv6.

    ``::`` joined with ``:3000`` would read as ``:::3000``, which hides
    the port separator. ``[::]:3000`` matches Docker's published-port
    text. An address that is already bracketed (``[::]``) is left alone.
    """
    if ":" in address and not (address.startswith("[") and address.endswith("]")):
        return f"[{address}]:{port}"
    return f"{address}:{port}"


@dataclass(frozen=True, slots=True)
class PortRange:
    """Inclusive port interval used for reserved, dynamic, or free spans.

    Attributes:
        start: First port in the range (inclusive).
        end: Last port in the range (inclusive).
        kind: Semantic tag — ``reserved``, ``dynamic``, ``free``, etc.
        administered: Windows marks some exclusions as admin-managed
            (shown with ``*`` in ``netsh`` output).
        note: Optional human-readable detail for the report.
    """

    start: int
    end: int
    kind: str = "range"
    administered: bool = False
    note: str = ""

    @property
    def size(self) -> int:
        """Number of ports covered by this inclusive interval."""
        return self.end - self.start + 1

    def label(self) -> str:
        """Compact display form: ``8080`` or ``8000-8099``."""
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"


@dataclass(slots=True)
class PortInventory:
    """Complete snapshot used to render the CLI report.

    Attributes:
        listening: Host OS listeners with process attribution.
        docker: Published Docker host ports (may be invisible to netstat).
        reserved: Windows excluded / Hyper-V / admin reserved ranges.
        dynamic: OS ephemeral (dynamic) port pool description.
        free: Contiguous gaps not held by host, Docker, or reserved ranges.
        well_known_free: Free gaps that intersect the classic 0–1023 band
            (often useful when looking for privileged service ports).
        registered_free: Free gaps in 1024–49151.
        ephemeral_free: Free gaps in 49152–65535 (outside reserved blocks).
        docker_available: Whether ``docker ps`` answered this run. False
            when Docker was skipped, the CLI is missing, or the daemon is
            not running.
        scan_incomplete: True when the OS refused the socket table (access
            denied). An empty listener list in that case means "we could
            not see", not "nothing is listening".
        scan_note: Human explanation when ``scan_incomplete`` is set.
        held: TCP sockets on a local port that are not LISTEN (TIME_WAIT,
            CLOSE_WAIT, ESTABLISHED, …). They are omitted from the free-range
            math so outbound ephemeral clients do not shred that table, but
            port lookup and ``--check`` still consult them.
    """

    listening: list[ListeningService] = field(default_factory=list)
    docker: list[ListeningService] = field(default_factory=list)
    reserved: list[PortRange] = field(default_factory=list)
    dynamic: list[PortRange] = field(default_factory=list)
    free: list[PortRange] = field(default_factory=list)
    well_known_free: list[PortRange] = field(default_factory=list)
    registered_free: list[PortRange] = field(default_factory=list)
    ephemeral_free: list[PortRange] = field(default_factory=list)
    docker_available: bool = False
    scan_incomplete: bool = False
    scan_note: str = ""
    held: list[ListeningService] = field(default_factory=list)
