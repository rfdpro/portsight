"""Classify one port against an already-built inventory.

``lookup_port`` does not rescan the OS. Socket collection, Windows exclusion
queries, and Docker discovery stay in their own modules; this one only reads
a ``PortInventory`` and answers "can this port be bound, and why not?"

That split matters for two reasons:

* ``PortInventory.free`` is the wrong source for a single-port answer. Free
  ranges ignore every non-listen socket so outbound clients do not shred the
  ephemeral band. A port lookup still has to treat TIME_WAIT (and the other
  bind-blocking states) as occupying the port, while leaving ESTABLISHED
  visible but non-blocking.
* Callers such as ``--port`` and unit tests can hand in a snapshot they
  already built. Re-reading netstat or ``netsh`` here would make the answer
  depend on a second, possibly different, moment in time.

The dynamic / ephemeral pool (``inventory.dynamic``) is intentionally not
consulted. A port inside that pool is still bindable until something
listens, Docker publishes it, Windows excludes it, or a bind-blocking
socket is sitting on it.
"""

from __future__ import annotations

from dataclasses import dataclass

from portsight.models import (
    BIND_BLOCKING_STATES,
    ListeningService,
    PortInventory,
    PortRange,
    endpoint_label,
)
from portsight.windows import exclusion_advice as windows_exclusion_advice
from portsight.windows import find_exclusion

# Occupancy sentences name a process, a container, an exclusion, or a TCP
# state. The incomplete-scan note is not one of those: it must stay
# recognizable so plain-text formatting can append it without repeating
# every listener row that ``reasons`` also describes.
_SCAN_NOTE_PREFIX = "Scan incomplete: "


@dataclass(slots=True)
class PortLookup:
    """One port's bind decision plus the rows a caller should print.

    ``free`` is the decision. It is True only when nothing in this snapshot
    would stop a bind: no host listener, no Docker publish, no Windows
    exclusion, and no held socket in ``BIND_BLOCKING_STATES``.

    ``reasons`` explains a negative decision in short sentences. It is empty
    when the port is free, with one exception: an incomplete socket scan
    still records its note here so the caller can show the caveat. That note
    does not, by itself, flip ``free`` to False.
    """

    port: int
    free: bool
    # Host listeners on this port (inventory.listening filtered to ``port``).
    listeners: list[ListeningService]
    # Docker publishes on this port (inventory.docker filtered to ``port``).
    docker: list[ListeningService]
    # Non-listen sockets on this port, including ESTABLISHED. Filtering to
    # bind-blocking states happens later, when deciding ``free``.
    held: list[ListeningService]
    exclusion: PortRange | None
    exclusion_advice: str | None
    reasons: list[str]


def lookup_port(port: int, inventory: PortInventory) -> PortLookup:
    """Classify one port from an already-built inventory. Do not rescan the OS.

    A port is free only when all of these are true:

    * no host listener on that port
    * no Docker publish on that port
    * not inside a Windows reserved / exclusion range
    * no held socket whose state is in ``BIND_BLOCKING_STATES``

    ESTABLISHED alone does not make the port unfree (it is usually the client
    side of an outbound connection) but the socket stays in ``held`` so the
    caller can show it.

    When ``inventory.scan_incomplete`` is set, whatever rows the snapshot
    does contain are still classified. The scan note is prefixed onto
    ``reasons`` and the port is not marked unfree solely because the scan
    was incomplete.
    """
    checked = _validate_port(port)

    # Trust the inventory's buckets. ``build_inventory`` already split host
    # listeners from Docker publishes; re-classifying by ``source`` here would
    # hide a row the collector deliberately placed in one list or the other.
    listeners = _on_port(inventory.listening, checked)
    docker = _on_port(inventory.docker, checked)
    # Every non-listen socket on this port, blocking or not. ESTABLISHED must
    # survive this filter so the report can show the client connection.
    held = _on_port(inventory.held, checked)

    # Both helpers walk the same reserved list. Calling them (instead of
    # reimplementing the range test) keeps the WinNAT wording in one place.
    exclusion = find_exclusion(checked, inventory.reserved)
    advice = windows_exclusion_advice(checked, inventory.reserved)

    blocking = [service for service in held if _blocks_bind(service)]

    # Scan completeness is deliberately absent. An empty snapshot from an
    # access-denied scan is "we could not see", not "this port is taken".
    free = not listeners and not docker and exclusion is None and not blocking

    reasons: list[str] = []
    scan_reason = _incomplete_scan_reason(inventory)
    if scan_reason is not None:
        # Prefix, including when the port is otherwise free, so the caveat
        # is not dropped on the only path that has no occupancy sentences.
        reasons.append(scan_reason)
    if not free:
        reasons.extend(_occupancy_reasons(checked, listeners, docker, exclusion, blocking))

    return PortLookup(
        port=checked,
        free=free,
        listeners=listeners,
        docker=docker,
        held=held,
        exclusion=exclusion,
        exclusion_advice=advice,
        reasons=reasons,
    )


def format_lookup_lines(lookup: PortLookup) -> list[str]:
    """Plain text lines for stdout (no Rich).

    The first line is exactly ``free`` or ``in use``, taken from
    ``lookup.free``. A scan-incomplete note must not change that word: an
    empty port stays ``free`` and the note follows the rows.

    After the status line comes one line per host listener, Docker publish,
    and held socket (protocol, address, pid, name, parent, command line,
    state), then the exclusion-advice paragraph when the port sits in a
    reserved range, then the incomplete-scan note when one was recorded.
    Suitable for human ``--port`` output and for tests.
    """
    # Key off ``free``, not "reasons is empty". The incomplete-scan note
    # lives in ``reasons`` even when the port is still free.
    lines = ["free" if lookup.free else "in use"]
    for service in lookup.listeners:
        lines.append(_endpoint_line("listen", service))
    for service in lookup.docker:
        lines.append(_endpoint_line("docker", service))
    for service in lookup.held:
        lines.append(_endpoint_line("held", service))
    if lookup.exclusion_advice:
        lines.append(lookup.exclusion_advice)
    for reason in lookup.reasons:
        if reason.startswith(_SCAN_NOTE_PREFIX):
            lines.append(reason)
    return lines


def _validate_port(port: int) -> int:
    """Reject anything outside the concrete 1–65535 bind space.

    Port 0 is the OS wildcard for "choose an ephemeral port", not an endpoint
    we can classify. Booleans are ``int`` subclasses (``True == 1``); they
    are rejected so a mistaken flag does not silently classify port 1.
    The message matches ``kill.find_targets_on_port`` so callers can surface
    either error the same way.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"port must be in 1-65535, got {port}")
    return port


def _on_port(services: list[ListeningService], port: int) -> list[ListeningService]:
    """Rows whose local port is ``port``, in inventory order.

    Order is preserved so a dual-stack pair (``0.0.0.0`` then ``::``) prints
    the way the collector sorted it, rather than being reshuffled here.
    """
    return [service for service in services if service.port == port]


def _blocks_bind(service: ListeningService) -> bool:
    """True when this held socket can make ``bind()`` fail on Windows.

    Comparison is case-insensitive. ``psutil`` reports the uppercase names
    in ``BIND_BLOCKING_STATES``; a hand-built inventory or a future collector
    might not. ESTABLISHED is absent from that set on purpose — see
    ``scanner.BIND_BLOCKING_STATES``.
    """
    state = (service.state or "").strip().upper()
    return state in BIND_BLOCKING_STATES


def _incomplete_scan_reason(inventory: PortInventory) -> str | None:
    """The scan caveat, or None when the socket table was fully read.

    ``scan_note`` is used when the collector supplied one (the usual
    elevation message). A set flag with a blank note still produces a
    sentence, so the incomplete bit cannot disappear. A leftover note with
    the flag clear is ignored: the flag is the switch.
    """
    if not inventory.scan_incomplete:
        return None
    note = inventory.scan_note.strip()
    if not note:
        note = "the socket table was not fully readable."
    return f"{_SCAN_NOTE_PREFIX}{note}"


def _occupancy_reasons(
    port: int,
    listeners: list[ListeningService],
    docker: list[ListeningService],
    exclusion: PortRange | None,
    blocking: list[ListeningService],
) -> list[str]:
    """Short sentences for everything that actually makes the port unfree.

    Order matches the plain-text rows: host listeners, Docker publishes,
    the exclusion, then bind-blocking held sockets. ESTABLISHED rows are
    not passed in ``blocking``, so they never become a reason.
    """
    reasons: list[str] = []
    for service in listeners:
        reasons.append(_listener_reason(service))
    for service in docker:
        reasons.append(_docker_reason(service))
    if exclusion is not None:
        # Shorter than ``exclusion_advice`` (that paragraph is stored on the
        # lookup and printed separately). The range label is enough to see
        # which exclusion fired; the WinNAT remediation stays in the advice.
        admin = "administered " if exclusion.administered else ""
        reasons.append(f"Windows {admin}exclusion {exclusion.label()} reserves port {port}.")
    for service in blocking:
        reasons.append(_held_reason(service))
    return reasons


def _listener_reason(service: ListeningService) -> str:
    """Host listener sentence: process name, pid, and command line.

    The command line is what distinguishes one ``node.exe`` from another
    when several Node processes are listening. It is omitted when the OS
    withheld it, rather than printing an empty pair of parentheses.
    """
    name = service.process_name or "unknown process"
    pid = "unknown" if service.pid is None else str(service.pid)
    where = f"{service.protocol} {endpoint_label(service.address, service.port)}"
    cmdline = _single_line(service.cmdline)
    if cmdline:
        return f"{name} (pid {pid}) is listening on {where} ({cmdline})."
    return f"{name} (pid {pid}) is listening on {where}."


def _docker_reason(service: ListeningService) -> str:
    """Docker sentence naming the container (``process_name`` on these rows)."""
    name = service.process_name or "unknown container"
    where = f"{service.protocol} {endpoint_label(service.address, service.port)}"
    detail = service.detail.strip()
    if detail:
        return f"Docker container {name} publishes {where} ({detail})."
    return f"Docker container {name} publishes {where}."


def _held_reason(service: ListeningService) -> str:
    """Bind-blocking held socket, leading with the state name.

    The state is the fact that matters for ``bind()``; the process is extra
    context when the socket still has one (TIME_WAIT often does not).
    """
    state = (service.state or "UNKNOWN").strip().upper() or "UNKNOWN"
    name = service.process_name or "unknown process"
    pid = "unknown" if service.pid is None else str(service.pid)
    where = f"{service.protocol} {endpoint_label(service.address, service.port)}"
    return f"{state} on {where} ({name}, pid {pid}) blocks bind."


def _endpoint_line(kind: str, service: ListeningService) -> str:
    """One stdout row: kind, proto, address, pid, name, parent, cmdline, state.

    ``kind`` is ``listen``, ``docker``, or ``held`` so a dual-stack port with
    both a publisher and a TIME_WAIT socket stays unambiguous. Missing pid,
    parent, or command line become ``-`` so every row has the same fields.
    Command lines are collapsed to a single line; a newline in a cmdline
    would otherwise break the one-row-per-socket contract.
    """
    pid = "-" if service.pid is None else str(service.pid)
    parent = _parent_token(service)
    cmdline = _single_line(service.cmdline) or "-"
    name = service.process_name or "-"
    state = service.state or "-"
    protocol = service.protocol or "-"
    address = service.address or "-"
    return (
        f"{kind} {protocol} {address} pid={pid} name={name} "
        f"parent={parent} cmdline={cmdline} state={state}"
    )


def _parent_token(service: ListeningService) -> str:
    """``pid/name`` when both are known, either one alone, or ``-``."""
    if service.parent_pid is None and not service.parent_name:
        return "-"
    if service.parent_pid is None:
        return service.parent_name
    if not service.parent_name:
        return str(service.parent_pid)
    return f"{service.parent_pid}/{service.parent_name}"


def _single_line(text: str) -> str:
    """Collapse whitespace so a command line stays on one stdout row."""
    return " ".join(text.split())
