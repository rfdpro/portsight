"""Serialize a PortInventory to schema-v1 JSON and diff two snapshots.

The CLI calls this module for ``--json``, ``--snapshot``, ``--diff``, and
``--watch``. There is no watch loop here: the loop (sleep, rescan, print)
belongs in the CLI. Every function below is pure data in, data out, so it
can be tested with a hand-built :class:`~portsight.models.PortInventory`
and never touches netstat, Docker, or the clock.

Document shape (schema version 1)
----------------------------------
:func:`inventory_to_dict` writes exactly these top-level keys:

    schema_version, scan_incomplete, scan_note, docker_available,
    listening, docker, held, reserved, dynamic, free

Key order is insertion order (the list above) but is not part of the
contract. Consumers must look keys up by name.

Derived free-band views on :class:`~portsight.models.PortInventory`
(``well_known_free``, ``registered_free``, ``ephemeral_free``) are left
out on purpose. They are recomputed from listeners and reserved ranges,
so storing them would duplicate data and drift from the source lists.

``dynamic`` and ``free`` are stored so ``--json`` is a complete picture.
They are not part of :class:`SnapshotDiff`. Free spans move whenever any
listener moves, and a watch view that printed them would be noise.

The diff also skips socket churn from outbound traffic: UDP binds and
held TCP sockets inside the dynamic pool, and held sockets whose state
does not block ``bind()`` (ESTABLISHED, SYN_SENT). The snapshot file
still records every row; only the comparison ignores them.

Dependencies are the stdlib (``json``, ``pathlib``, ``dataclasses``,
``collections``) plus the project models. This module does not import
Rich; plain lines from :func:`format_diff_lines` are safe to print from
a watch loop that has not set up a console theme.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from portsight.models import (
    BIND_BLOCKING_STATES,
    ListeningService,
    PortInventory,
    PortRange,
    endpoint_label,
)

# Bump only when a reader of an older file would misinterpret a field.
# loads_snapshot rejects every other value, including the string "1" and
# the boolean True (bool is a subclass of int, so a bare ``== 1`` check
# would accept it).
SCHEMA_VERSION = 1

# Closed set written by inventory_to_dict. Loaders require each of these
# and still accept unknown extra keys so a newer writer that adds an
# optional field does not make an older reader refuse the file outright.
_DOCUMENT_KEYS = (
    "schema_version",
    "scan_incomplete",
    "scan_note",
    "docker_available",
    "listening",
    "docker",
    "held",
    "reserved",
    "dynamic",
    "free",
)

_SERVICE_LIST_KEYS = ("listening", "docker", "held")
_RANGE_LIST_KEYS = ("reserved", "dynamic", "free")

# Field-by-field mapping, not dataclasses.asdict. The JSON schema is a
# closed set; a new attribute on the dataclass must not leak into a v1
# document until SCHEMA_VERSION changes and the keys below are updated.
_SERVICE_KEYS = (
    "protocol",
    "address",
    "port",
    "pid",
    "process_name",
    "process_path",
    "source",
    "detail",
    "cmdline",
    "parent_pid",
    "parent_name",
    "state",
)

_SERVICE_STRING_KEYS = (
    "protocol",
    "address",
    "process_name",
    "process_path",
    "source",
    "detail",
    "cmdline",
    "parent_name",
    "state",
)

_RANGE_KEYS = ("start", "end", "kind", "administered", "note")

# Identity used to decide "same row" across two snapshots.
# Command line, path, parent, detail, and range notes are deliberately
# excluded: they are attribution that can flicker (a process whose
# command line we could not read on one scan) without the endpoint
# itself appearing or disappearing. State is included so a port that
# leaves LISTEN and becomes TIME_WAIT is a real change. Administered is
# included so an exclusion flipping the netsh "*" flag is a real change.
_SERVICE_IDENTITY_KEYS = (
    "source",
    "protocol",
    "address",
    "port",
    "pid",
    "process_name",
    "state",
)

_RANGE_IDENTITY_KEYS = ("kind", "start", "end", "administered")


def service_to_dict(service: ListeningService) -> dict:
    """Map one endpoint to the v1 service object.

    ``pid`` and ``parent_pid`` are JSON ``null`` when the OS withheld
    them (Docker publishes are the common case: ``pid`` is ``None``).
    """
    return {
        "protocol": service.protocol,
        "address": service.address,
        "port": service.port,
        "pid": service.pid,
        "process_name": service.process_name,
        "process_path": service.process_path,
        "source": service.source,
        "detail": service.detail,
        "cmdline": service.cmdline,
        "parent_pid": service.parent_pid,
        "parent_name": service.parent_name,
        "state": service.state,
    }


def range_to_dict(port_range: PortRange) -> dict:
    """Map one inclusive interval to the v1 range object.

    ``size`` and :meth:`PortRange.label` are display helpers, not stored.
    A reader rebuilds the label from ``start`` and ``end``.
    """
    return {
        "start": port_range.start,
        "end": port_range.end,
        "kind": port_range.kind,
        "administered": port_range.administered,
        "note": port_range.note,
    }


def inventory_to_dict(inventory: PortInventory) -> dict:
    """Map a full inventory to a schema-v1 document.

    The three derived free-band lists are omitted; see the module
    docstring. ``held`` is placed with the other service lists (before
    the range lists) even though the dataclass declares it last, so the
    document groups endpoints together and ranges together.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_incomplete": inventory.scan_incomplete,
        "scan_note": inventory.scan_note,
        "docker_available": inventory.docker_available,
        "listening": [service_to_dict(service) for service in inventory.listening],
        "docker": [service_to_dict(service) for service in inventory.docker],
        "held": [service_to_dict(service) for service in inventory.held],
        "reserved": [range_to_dict(port_range) for port_range in inventory.reserved],
        "dynamic": [range_to_dict(port_range) for port_range in inventory.dynamic],
        "free": [range_to_dict(port_range) for port_range in inventory.free],
    }


def dumps_inventory(inventory: PortInventory) -> str:
    """JSON text, indent=2, ensure_ascii=False, trailing newline.

    ``ensure_ascii=False`` keeps process names and scan notes as raw
    UTF-8 characters instead of ``\\u`` escapes. The trailing newline
    makes the file a normal text file (editors and ``cat`` expect one).
    """
    return json.dumps(inventory_to_dict(inventory), indent=2, ensure_ascii=False) + "\n"


def loads_snapshot(text: str) -> dict:
    """Parse JSON into a schema-v1 document dict.

    Raises:
        ValueError: the text is not JSON, the root is not an object,
            ``schema_version`` is not the integer 1, a required key is
            missing, or a service/range row is not an object with the
            v1 keys.

    The return value is the parsed dict. ``free`` and ``dynamic`` stay
    lists of dicts; this function does not rebuild :class:`PortRange`.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"snapshot is not valid JSON: {exc.msg}") from exc
    return _validate_document(data)


def save_snapshot(inventory: PortInventory, path: Path) -> None:
    """Write :func:`dumps_inventory` to ``path`` as UTF-8.

    ``newline="\\n"`` stops Windows text mode from turning the trailing
    newline into ``\\r\\n``, so the file bytes match the string
    ``dumps_inventory`` returned. ``path`` may be a :class:`~pathlib.Path`
    or a string (argparse hands the CLI a string).
    """
    Path(path).write_text(dumps_inventory(inventory), encoding="utf-8", newline="\n")


def load_snapshot(path: Path) -> dict:
    """Read UTF-8 text from ``path`` and :func:`loads_snapshot` it."""
    return loads_snapshot(Path(path).read_text(encoding="utf-8"))


@dataclass(slots=True)
class SnapshotDiff:
    """Rows that appeared or disappeared between two schema-v1 documents.

    ``before`` is the older snapshot. ``*_added`` rows are present in the
    newer document only; ``*_removed`` rows are present in the older
    document only. Each entry is the service or range dict from the
    document that owns it, not a reconstructed model, so callers still
    have command line, path, and notes when they want them.

    ``dynamic`` and ``free`` are intentionally absent. See the module
    docstring.

    Defaults are empty lists so a watch tick with nothing to report can
    use :class:`SnapshotDiff` and :attr:`empty` without eight arguments.
    Field order is the order :func:`format_diff_lines` prints.
    """

    listeners_added: list[dict] = field(default_factory=list)
    listeners_removed: list[dict] = field(default_factory=list)
    docker_added: list[dict] = field(default_factory=list)
    docker_removed: list[dict] = field(default_factory=list)
    held_added: list[dict] = field(default_factory=list)
    held_removed: list[dict] = field(default_factory=list)
    reserved_added: list[dict] = field(default_factory=list)
    reserved_removed: list[dict] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        """True when every added and removed collection is empty."""
        return not (
            self.listeners_added
            or self.listeners_removed
            or self.docker_added
            or self.docker_removed
            or self.held_added
            or self.held_removed
            or self.reserved_added
            or self.reserved_removed
        )


def diff_snapshots(before: dict, after: dict) -> SnapshotDiff:
    """Compare two schema-v1 documents. ``before`` is the older snapshot.

    Equality is multiset equality on the identity tuples documented at
    ``_SERVICE_IDENTITY_KEYS`` and ``_RANGE_IDENTITY_KEYS``. Two rows
    with the same identity count as unchanged even if command line,
    path, or note differ. A duplicate identity (two sockets that share
    source, protocol, address, port, pid, name, and state) is counted,
    not collapsed: if both copies disappear, both are reported removed.

    Added rows keep the order they have in ``after``. Removed rows keep
    the order they have in ``before``.

    Raises:
        ValueError: either argument is not a schema-v1 document.
    """
    older = _validate_document(before)
    newer = _validate_document(after)

    listeners_added, listeners_removed = _multiset_diff(
        _relevant_listeners(older), _relevant_listeners(newer), _service_identity
    )
    docker_added, docker_removed = _multiset_diff(
        older["docker"], newer["docker"], _service_identity
    )
    held_added, held_removed = _multiset_diff(
        _relevant_held(older), _relevant_held(newer), _service_identity
    )
    reserved_added, reserved_removed = _multiset_diff(
        older["reserved"], newer["reserved"], _range_identity
    )
    return SnapshotDiff(
        listeners_added=listeners_added,
        listeners_removed=listeners_removed,
        docker_added=docker_added,
        docker_removed=docker_removed,
        held_added=held_added,
        held_removed=held_removed,
        reserved_added=reserved_added,
        reserved_removed=reserved_removed,
    )


def diff_inventory(before: dict, current: PortInventory) -> SnapshotDiff:
    """Convenience: diff_snapshots(before, inventory_to_dict(current))."""
    return diff_snapshots(before, inventory_to_dict(current))


def format_diff_lines(diff: SnapshotDiff) -> list[str]:
    """Plain watch/diff lines. No ANSI codes.

    An empty diff is a single line, ``no changes``. Otherwise one line
    per row, additions before removals inside each category, categories
    in the order listen, docker, held, reserved::

        + listen TCP 0.0.0.0:3000 node.exe pid=1
        - docker TCP 0.0.0.0:5432 postgres
        + held TCP 127.0.0.1:443 chrome.exe pid=9 TIME_WAIT
        + reserved 200
        - reserved 50000-50059 *

    ``pid=`` is omitted when pid is null (Docker publishes). Held rows
    end with the socket state so TIME_WAIT is not printed like a
    listener. Reserved rows use :meth:`PortRange.label` (``1462`` or
    ``100-110``). A trailing ``*`` marks an administered exclusion, the
    same marker ``netsh`` and the Rich report use.
    """
    if diff.empty:
        return ["no changes"]

    lines: list[str] = []
    # Service categories share one renderer. Held is the only one that
    # appends state; listen and docker examples in the CLI contract do
    # not print LISTEN/BOUND because that is already implied by the bucket.
    _append_service_lines(lines, "+", "listen", diff.listeners_added, with_state=False)
    _append_service_lines(lines, "-", "listen", diff.listeners_removed, with_state=False)
    _append_service_lines(lines, "+", "docker", diff.docker_added, with_state=False)
    _append_service_lines(lines, "-", "docker", diff.docker_removed, with_state=False)
    _append_service_lines(lines, "+", "held", diff.held_added, with_state=True)
    _append_service_lines(lines, "-", "held", diff.held_removed, with_state=True)
    for port_range in diff.reserved_added:
        lines.append(_format_range_line("+", port_range))
    for port_range in diff.reserved_removed:
        lines.append(_format_range_line("-", port_range))
    return lines


def _append_service_lines(
    lines: list[str],
    sign: str,
    bucket: str,
    rows: list[dict],
    *,
    with_state: bool,
) -> None:
    """Extend ``lines`` with one formatted row per service dict."""
    for row in rows:
        lines.append(_format_service_line(sign, bucket, row, with_state=with_state))


def _format_service_line(
    sign: str,
    bucket: str,
    row: dict,
    *,
    with_state: bool,
) -> str:
    """Render one endpoint.

    Tokens, in order: sign, bucket, protocol, ``address:port``, process
    name when non-empty, ``pid=N`` when pid is not null, and for held
    rows the state. Empty process names are skipped so a withheld name
    does not leave a double space. Pid 0 is real and must be printed;
    only ``None`` (JSON null) is omitted.
    """
    parts = [
        sign,
        bucket,
        str(row["protocol"]),
        endpoint_label(str(row["address"]), row["port"]),
    ]
    name = row.get("process_name") or ""
    if name != "":
        parts.append(str(name))
    pid = row.get("pid")
    if pid is not None:
        parts.append(f"pid={pid}")
    if with_state:
        parts.append(str(row.get("state", "")))
    return " ".join(parts)


def _format_range_line(sign: str, row: dict) -> str:
    """Render one reserved-range change.

    The label goes through :class:`PortRange` so a single port and a
    span match the tables in the Rich report. ``*`` is appended only
    when ``administered`` is true.
    """
    label = PortRange(start=int(row["start"]), end=int(row["end"])).label()
    text = f"{sign} reserved {label}"
    if row.get("administered"):
        text += " *"
    return text


def _dynamic_pools(document: dict) -> list[tuple[int, int]]:
    return [(int(row["start"]), int(row["end"])) for row in document["dynamic"]]


def _in_pools(port: int, pools: list[tuple[int, int]]) -> bool:
    return any(start <= port <= end for start, end in pools)


def _relevant_listeners(document: dict) -> list[dict]:
    """Listener rows worth reporting as a change.

    UDP has no LISTEN state, so every DNS lookup or QUIC client binds a
    fresh UDP socket on an ephemeral port. Those rows are dropped when the
    port is inside the document's dynamic pool. TCP listeners are always
    kept, even on high ports.
    """
    pools = _dynamic_pools(document)
    return [
        row
        for row in document["listening"]
        if not (str(row["protocol"]).upper() == "UDP" and _in_pools(row["port"], pools))
    ]


def _relevant_held(document: dict) -> list[dict]:
    """Held rows worth reporting as a change.

    Every outbound connection leaves ESTABLISHED, SYN_SENT, and then
    TIME_WAIT sockets on an ephemeral port. Diffing those would make
    ``--diff`` exit 1 on any machine with network traffic. What matters is
    a bind-blocking socket on a port someone might choose (a dev server
    that just died leaves TIME_WAIT on 3000), so rows are kept only when
    the state blocks ``bind()`` and the port is outside the dynamic pool.
    """
    pools = _dynamic_pools(document)
    return [
        row
        for row in document["held"]
        if str(row["state"]).upper() in BIND_BLOCKING_STATES and not _in_pools(row["port"], pools)
    ]


def _service_identity(row: dict) -> tuple:
    """Hash key for one service row. See ``_SERVICE_IDENTITY_KEYS``."""
    return tuple(row[key] for key in _SERVICE_IDENTITY_KEYS)


def _range_identity(row: dict) -> tuple:
    """Hash key for one range row. See ``_RANGE_IDENTITY_KEYS``."""
    return tuple(row[key] for key in _RANGE_IDENTITY_KEYS)


def _multiset_diff(
    before_rows: list[dict],
    after_rows: list[dict],
    identity,
) -> tuple[list[dict], list[dict]]:
    """Return ``(added, removed)`` by counting identity tuples.

    Walking each side in order and emitting a row only once its running
    count exceeds the other side's total keeps document order and treats
    duplicates as a multiset. A set difference would drop the second
    copy of an identical publish.
    """
    before_counts = Counter(identity(row) for row in before_rows)
    after_counts = Counter(identity(row) for row in after_rows)

    added: list[dict] = []
    seen_after: Counter = Counter()
    for row in after_rows:
        key = identity(row)
        seen_after[key] += 1
        if seen_after[key] > before_counts[key]:
            added.append(row)

    removed: list[dict] = []
    seen_before: Counter = Counter()
    for row in before_rows:
        key = identity(row)
        seen_before[key] += 1
        if seen_before[key] > after_counts[key]:
            removed.append(row)

    return added, removed


def _validate_document(data: object) -> dict:
    """Return ``data`` if it is a schema-v1 document, else raise ValueError.

    Called from both the loader and the differ so a hand-built dict passed
    to :func:`diff_snapshots` fails the same way a bad file does. Unknown
    top-level keys are kept; missing required keys are not.
    """
    if not isinstance(data, dict):
        raise ValueError("snapshot must be a JSON object")

    missing = [key for key in _DOCUMENT_KEYS if key not in data]
    if missing:
        raise ValueError("snapshot is missing required keys: " + ", ".join(missing))

    version = data["schema_version"]
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValueError(f"snapshot schema_version must be 1, got {version!r}")

    _expect_bool(data["scan_incomplete"], "scan_incomplete")
    if not isinstance(data["scan_note"], str):
        raise ValueError("scan_note must be a string")
    _expect_bool(data["docker_available"], "docker_available")

    for key in _SERVICE_LIST_KEYS:
        _validate_row_list(data[key], key, _validate_service_row)
    for key in _RANGE_LIST_KEYS:
        _validate_row_list(data[key], key, _validate_range_row)
    return data


def _validate_row_list(rows: object, key: str, validate_row) -> None:
    """Require ``rows`` to be a list and validate each element in place."""
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be a list")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{key}[{index}] must be an object")
        validate_row(row, f"{key}[{index}]")


def _validate_service_row(row: dict, where: str) -> None:
    """Require the closed service key set and the int-or-null pid fields."""
    _require_keys(row, _SERVICE_KEYS, where)
    for key in _SERVICE_STRING_KEYS:
        if not isinstance(row[key], str):
            raise ValueError(f"{where}.{key} must be a string")
    _expect_int(row["port"], f"{where}.port")
    _expect_optional_int(row["pid"], f"{where}.pid")
    _expect_optional_int(row["parent_pid"], f"{where}.parent_pid")


def _validate_range_row(row: dict, where: str) -> None:
    """Require the closed range key set. Does not build a PortRange."""
    _require_keys(row, _RANGE_KEYS, where)
    _expect_int(row["start"], f"{where}.start")
    _expect_int(row["end"], f"{where}.end")
    if not isinstance(row["kind"], str):
        raise ValueError(f"{where}.kind must be a string")
    _expect_bool(row["administered"], f"{where}.administered")
    if not isinstance(row["note"], str):
        raise ValueError(f"{where}.note must be a string")


def _require_keys(row: dict, keys: tuple[str, ...], where: str) -> None:
    """Raise ValueError listing every required key absent from ``row``."""
    missing = [key for key in keys if key not in row]
    if missing:
        raise ValueError(f"{where} is missing required keys: " + ", ".join(missing))


def _expect_bool(value: object, where: str) -> None:
    """Reject ints. JSON true/false must stay bools, not 0/1."""
    if type(value) is not bool:
        raise ValueError(f"{where} must be a bool")


def _expect_int(value: object, where: str) -> None:
    """Reject bool (a subclass of int) and floats such as ``80.0``."""
    if type(value) is not int:
        raise ValueError(f"{where} must be an int")


def _expect_optional_int(value: object, where: str) -> None:
    """Pid fields are an int or JSON null. A missing key is a different error."""
    if value is None:
        return
    _expect_int(value, where)


__all__ = [
    "SCHEMA_VERSION",
    "SnapshotDiff",
    "diff_inventory",
    "diff_snapshots",
    "dumps_inventory",
    "format_diff_lines",
    "inventory_to_dict",
    "load_snapshot",
    "loads_snapshot",
    "range_to_dict",
    "save_snapshot",
    "service_to_dict",
]
