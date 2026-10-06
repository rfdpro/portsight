"""Ports the user expects to use, and whether each one is actually free.

``lookup_port`` answers "can I bind this one number?". This module answers
a different question: "of the ports I planned to use, what is each one
doing right now?" A status table needs one label per port, so classification
picks a single winner instead of listing every overlapping reason.

The expected set comes from three places, in this order:

* an explicit spec (``--expect`` text, origin ``flag``)
* ``.portsight`` in the working directory
* the first Compose file that exists

Nothing here scans the OS. ``classify_expected`` only reads a
``PortInventory`` the caller already built, so a test can hand in rows and
a second netstat snapshot cannot disagree with the report.

Compose files are read as text. PyYAML is intentionally not used: the
handful of publish lines we care about are regular enough to scrape, and a
real parser would pull in a dependency plus YAML 1.1 surprises (base-60
``60:60``, anchors, merge keys) for mappings we still could not fully
resolve without walking ``extends`` / ``include``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from portsight.models import BIND_BLOCKING_STATES, ListeningService, PortInventory, PortRange
from portsight.windows import find_exclusion

# Same inclusive window as ``portsight.ranges``. Port 0 is the OS wildcard
# for "pick an ephemeral port", not a port someone puts in an expect list.
_PORT_MIN = 1
_PORT_MAX = 65535

# A token is one concrete port or an inclusive range. The label, if any,
# is never part of this token — see ``parse_expect_spec``.
_PORT_OR_RANGE = re.compile(r"\d+(?:-\d+)?\Z")

# Comma and semicolon separate items. Whitespace also separates items, but
# only between port tokens; a non-port word starts a label. See the parser.
_ITEM_SEPARATORS = re.compile(r"[,;]")

# A service-level ``ports:`` key. Leading indent is allowed; an inline
# flow value (``ports: ["3000:80"]``) is not, and is ignored on purpose.
_PORTS_KEY = re.compile(r"^[ \t]*ports:[ \t]*\Z")

# ``9100:9100/tcp`` is a host publish. ``80/tcp`` (no colon) is an expose.
_PROTO_SUFFIX = re.compile(r"/(tcp|udp|sctp)\Z", re.IGNORECASE)

# ``.openports`` is the file name from before the project was renamed.
# Only the first one found is read.
_PROJECT_FILENAMES = (".portsight", ".openports")

# First hit wins. Later names are not merged in, so a repo that carries
# both a legacy ``docker-compose.yml`` and a ``compose.yaml`` does not
# silently union two different publish lists.
_COMPOSE_FILENAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)


@dataclass(frozen=True, slots=True)
class ExpectedPort:
    """One concrete port the user said they care about.

    Ranges are expanded before this object exists, so ``port`` is always a
    single number. ``label`` is optional human text (``""`` when the source
    gave none). ``origin`` records where the expectation came from so a
    duplicate port can keep the earlier source and drop the later one.
    """

    port: int
    label: str  # optional human label; "" when the source had none
    origin: str  # "flag", or a filename such as ".portsight" / "docker-compose.yml"


@dataclass(frozen=True, slots=True)
class ExpectedStatus:
    """``expected`` classified against one inventory snapshot.

    ``status`` is exactly one of ``free``, ``host``, ``docker``,
    ``reserved``, ``held``. ``detail`` is a short explanation of the winning
    reason (process, container, exclusion range, or socket state). It is
    ``""`` when the port is free — the status word already says that.
    """

    expected: ExpectedPort
    status: str  # "free", "host", "docker", "reserved", or "held"
    detail: str  # process, container, exclusion range, state, or ""


def parse_expect_spec(text: str, *, origin: str = "flag") -> list[ExpectedPort]:
    """Parse a flag spec into one ``ExpectedPort`` per concrete port.

    Items are separated by commas or semicolons. Inside an item, whitespace
    separates port tokens (``3000 5432`` is two ports). A token is ``PORT``
    or ``PORT-PORT``. The first word that is not a port token starts the
    label, and the label is the rest of that comma-separated item — so
    ``3000 vite dev`` is port 3000 labeled ``vite dev``, while
    ``3000 vite 5432`` is still one port (label ``vite 5432``). Put the
    next port after a comma or semicolon if it should not be part of the
    label (``3000 vite, 5432``).

    Empty items (``3000,,5432`` or a blank string) are ignored. Ranges
    expand inclusively and the same label is copied onto every port in the
    range. Ports outside 1..65535 and inverted ranges (``3002-3000``) raise
    ``ValueError``. This function does not dedupe: ``3000 a, 3000 b``
    returns two rows so the caller can see both labels. ``discover_expected``
    is what collapses them.
    """
    expected: list[ExpectedPort] = []
    for raw_item in _ITEM_SEPARATORS.split(text):
        item = raw_item.strip()
        if not item:
            continue
        expected.extend(_parse_spec_item(item, origin))
    return expected


def load_portsight_file(path: Path) -> list[ExpectedPort]:
    """Load ``.portsight``: one spec item per line, ``#`` comments, blanks skipped.

    ``#`` starts a comment wherever it sits outside a quote, through the
    end of the line, so ``8080-8082 api  # preview`` keeps the label
    ``api``. Each remaining line uses the same grammar as
    ``parse_expect_spec`` (a bare port, a range, or ``PORT label``). The
    origin of every row is ``path.name`` (``.portsight``), not the
    directory, so two projects can both contribute a file of that name and
    still be told apart by the caller if they ever merge lists.

    A bad token raises ``ValueError``. This file is an explicit list the
    user wrote, so a typo should be loud. Compose scraping is the opposite:
    it skips lines it does not understand.
    """
    origin = path.name
    # utf-8-sig drops a Notepad BOM so it does not glue onto the first port.
    text = path.read_text(encoding="utf-8-sig")
    expected: list[ExpectedPort] = []
    for raw_line in text.splitlines():
        line = _strip_unquoted_comment(raw_line).strip()
        if not line:
            continue
        # Per line, so a label on line 1 cannot swallow a port on line 2.
        expected.extend(parse_expect_spec(line, origin=origin))
    return expected


def load_compose_ports(path: Path) -> list[ExpectedPort]:
    """Scrape published host ports from a Compose file. Not a YAML parser.

    A line that is only ``ports:`` (leading space ignored, trailing comments
    allowed) opens a section. Following lines that are indented deeper are
    list items. The section ends when indentation returns to the ``ports:``
    key or less — a sibling ``volumes:`` or the next service key — so a
    short list does not swallow the rest of the file. Blank lines and
    comments do not end the section.

    On those deeper lines the host port is the number immediately before
    the last ``:port`` (``3000:80``, ``127.0.0.1:5432:5432``,
    ``[::1]:8080:80``, ``3000-3002:3000-3002``). A line with no colon and a
    single number or range is that host port (``3000``, ``3000-3002``).
    ``80/tcp`` with a slash and no colon is an expose, not a host bind, and
    is ignored. ``/tcp``, ``/udp``, and ``/sctp`` suffixes on a real mapping
    are stripped before the split. Ranges expand to one row per host port.
    The label is the container port (paired by offset when the two ranges
    are the same width, otherwise the single container port), or ``""``
    for a bare host port. Origin is ``path.name``.

    Heuristic limits — these are not resolved or even detected beyond
    "that line did not look like a publish":

    * YAML anchors, aliases, and merge keys (``&``, ``*``, ``<<``).
    * ``extends``, ``include``, and custom tags.
    * Flow sequences on the ``ports:`` line itself
      (``ports: ["3000:80"]``).
    * Block scalars and quoted multiline strings (``|``, ``>``).
    * Long syntax (``published:`` / ``target:`` mappings). A ``published``
      key is just another nested line and is not read as a host port.
    * ``${VAR}`` interpolation. A non-numeric host token is skipped.
    * List items must be indented deeper than ``ports:``. A dash sitting
      in the same column as the key ends the section.
    * IPv6 literals need brackets (``[::1]``). Bare ``::1`` colons look
      like extra port fields.
    * A lone number is treated as the host port. Compose's own short
      syntax uses a lone number as the *container* port (ephemeral host).
      This tool's job is "ports I expect to bind", so the only number on
      the line is the one we report.
    * Malformed or out-of-range mappings are skipped, not raised. One bad
      line must not hide every other publish in the file.
    """
    origin = path.name
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    expected: list[ExpectedPort] = []
    index = 0
    total = len(lines)
    while index < total:
        key_indent = _ports_section_indent(lines[index])
        if key_indent is None:
            index += 1
            continue
        # The key line itself is not a mapping. Start on the next line.
        index += 1
        while index < total:
            content = _strip_unquoted_comment(lines[index]).rstrip()
            if not content.strip():
                # A blank line or a comment-only line stays inside the list.
                index += 1
                continue
            # ``<=`` so a sibling key at the same column (``volumes:``,
            # the next service) ends the list. A strictly-less check would
            # keep reading that sibling's children and treat ``- "9999:9999"``
            # under ``volumes:`` as another publish.
            if _indent_columns(content) <= key_indent:
                break
            expected.extend(_publish_ports_from_line(content, origin))
            index += 1
        # ``index`` still points at the line that ended the section (or
        # past the end). The outer loop must see that line — it may be
        # the next service's ``ports:`` key.
    return expected


def discover_expected(
    cwd: Path,
    expect_spec: str | None = None,
    *,
    use_project_files: bool = False,
) -> list[ExpectedPort]:
    """Build the expected-port list for one working directory.

    When ``expect_spec`` is non-blank it is parsed first with origin
    ``flag``. When ``use_project_files`` is set, ``cwd / '.portsight'`` is
    loaded if it is a file, then the first existing Compose file in
    ``_COMPOSE_FILENAMES`` order. Parent directories are not searched; the
    caller passes the directory that should be consulted.

    Dedup is by port number, keeping the first row. Flag text is parsed
    before files, so an explicit spec wins over ``.portsight``, which wins
    over Compose. Later labels for the same port are dropped, not merged.
    ``None`` and whitespace-only specs add no flag rows. Files are not
    read when ``use_project_files`` is false, even if they exist.
    """
    ordered: list[ExpectedPort] = []
    if expect_spec is not None and expect_spec.strip():
        ordered.extend(parse_expect_spec(expect_spec, origin="flag"))
    if use_project_files:
        for name in _PROJECT_FILENAMES:
            project_path = cwd / name
            if project_path.is_file():
                ordered.extend(load_portsight_file(project_path))
                break
        for name in _COMPOSE_FILENAMES:
            compose_path = cwd / name
            if compose_path.is_file():
                ordered.extend(load_compose_ports(compose_path))
                break
    return _dedupe_first_port(ordered)


def classify_expected(
    expected: list[ExpectedPort],
    inventory: PortInventory,
) -> list[ExpectedStatus]:
    """Classify each expected port. Do not scan the OS.

    First match wins, most specific occupancy first:

    1. ``host`` — a row in ``inventory.listening`` (a real listener).
    2. ``docker`` — a row in ``inventory.docker`` (a published container).
    3. ``held`` — a row in ``inventory.held`` whose state is in
       ``BIND_BLOCKING_STATES`` (``TIME_WAIT``, ``CLOSE_WAIT``, …).
    4. ``reserved`` — ``find_exclusion`` hits a Windows exclusion range.
    5. ``free`` — none of the above.

    A host listener stays ``host`` even when Docker also publishes the port
    or an exclusion covers it. The listener is the thing the user would
    kill or move; the exclusion is the fallback when nothing is actually
    bound. Bind-blocking held sockets beat an exclusion for the same
    reason: TIME_WAIT is a concrete socket, the range is only a netsh
    interval. ESTABLISHED is not in ``BIND_BLOCKING_STATES`` (it is usually
    the client side of an outbound connection) so it does not produce
    ``held`` and does not block ``free`` or ``reserved``.

    Buckets are trusted as ``build_inventory`` filled them. A row's
    ``source`` field is not consulted again.

    ``scan_incomplete`` is intentionally ignored. There is no sixth status
    for "we could not see", and an empty listener list must not be rewritten
    into "taken". Callers that need the caveat read ``inventory.scan_note``.

    Detail text, for the winning bucket only:

    * host: ``name (pid N)``, or just ``name`` when the pid is missing.
      Several listeners on the port are joined with ``; `` after identical
      phrases are collapsed (dual-stack ``0.0.0.0`` / ``::``).
    * docker: ``name`` plus the row's ``detail`` mapping when it has one
      (``web ->80/tcp``).
    * held: ``STATE name`` (state uppercased). The state is the fact that
      blocks ``bind()``.
    * reserved: ``exclusion START-END`` from ``PortRange.label()``, with
      the range note in parentheses when it is non-empty.
    * free: ``""``.
    """
    listeners = _group_by_port(inventory.listening)
    publishers = _group_by_port(inventory.docker)
    blocking = _group_blocking_held(inventory.held)

    statuses: list[ExpectedStatus] = []
    for item in expected:
        host_rows = listeners.get(item.port)
        if host_rows:
            detail = _unique_join(_host_phrase(service) for service in host_rows)
            statuses.append(ExpectedStatus(item, "host", detail))
            continue

        docker_rows = publishers.get(item.port)
        if docker_rows:
            detail = _unique_join(_docker_phrase(service) for service in docker_rows)
            statuses.append(ExpectedStatus(item, "docker", detail))
            continue

        held_rows = blocking.get(item.port)
        if held_rows:
            detail = _unique_join(_held_phrase(service) for service in held_rows)
            statuses.append(ExpectedStatus(item, "held", detail))
            continue

        # Shared with lookup / exclusion_advice so an inclusive bound cannot
        # drift (port == range.end is inside the exclusion).
        exclusion = find_exclusion(item.port, inventory.reserved)
        if exclusion is not None:
            statuses.append(ExpectedStatus(item, "reserved", _reserved_phrase(exclusion)))
            continue

        statuses.append(ExpectedStatus(item, "free", ""))
    return statuses


def _parse_spec_item(item: str, origin: str) -> list[ExpectedPort]:
    """Expand one comma-separated item into expected ports.

    Port tokens keep being read until a word that is not ``PORT`` or
    ``PORT-PORT`` appears. That word and everything after it in the item
    are the label. This is what makes ``3000 5432`` two ports and
    ``3000 vite dev`` one labeled port inside the same whitespace rules.
    """
    tokens = item.split()
    expected: list[ExpectedPort] = []
    index = 0
    while index < len(tokens):
        spec = tokens[index]
        if _PORT_OR_RANGE.fullmatch(spec) is None:
            raise ValueError(
                f"invalid port token {spec!r} "
                "(expected PORT or PORT-PORT, optionally followed by a label)"
            )
        start, end = _port_bounds(spec)
        index += 1
        label = ""
        if index < len(tokens) and _PORT_OR_RANGE.fullmatch(tokens[index]) is None:
            label = " ".join(tokens[index:])
            index = len(tokens)
        expected.extend(_expected_span(start, end, label, origin))
    return expected


def _port_bounds(spec: str) -> tuple[int, int]:
    """Inclusive ``(start, end)`` for a token that already matches ``_PORT_OR_RANGE``.

    Inverted ranges are reported separately from out-of-range endpoints so
    ``3002-3000`` is not misdiagnosed as "65535" and ``0`` is not called
    inverted.
    """
    if "-" in spec:
        left, right = spec.split("-", 1)
        start = int(left)
        end = int(right)
        if start > end:
            raise ValueError(f"inverted port range {spec!r} (start must be <= end)")
    else:
        start = end = int(spec)
    if start < _PORT_MIN or end > _PORT_MAX:
        raise ValueError(f"port {spec!r} is outside 1..65535")
    return start, end


def _expected_span(start: int, end: int, label: str, origin: str) -> list[ExpectedPort]:
    """One row per port from ``start`` through ``end``, same label and origin."""
    return [ExpectedPort(port=port, label=label, origin=origin) for port in range(start, end + 1)]


def _ports_section_indent(line: str) -> int | None:
    """Column of a ``ports:`` key, or None when this line is not one.

    Indent is measured after comments are removed so ``ports: # published``
    still counts, and a commented-out ``# ports:`` does not. Returning 0 is
    a real top-level key; callers must use ``is None``, not truthiness.
    """
    content = _strip_unquoted_comment(line).rstrip()
    if _PORTS_KEY.fullmatch(content) is None:
        return None
    return _indent_columns(content)


def _indent_columns(line: str) -> int:
    """Leading indent, counting a tab as two spaces.

    Compose files are spaces, and YAML forbids tabs, but a mixed file still
    needs a comparison that does not treat one tab as narrower than two
    spaces. Two matches the usual Compose indent step.
    """
    width = 0
    for char in line:
        if char == " ":
            width += 1
        elif char == "\t":
            width += 2
        else:
            break
    return width


def _publish_ports_from_line(content: str, origin: str) -> list[ExpectedPort]:
    """Host ports from one list line, or ``[]`` if it is not a publish.

    ``ValueError`` from an inverted or out-of-range spec is swallowed here
    only. Flag specs and ``.portsight`` still raise — those are explicit.
    A Compose file is mostly unrelated YAML, and one bad mapping should
    not discard the publishes we already understood.
    """
    parsed = _publish_host_and_container(_mapping_text(content))
    if parsed is None:
        return []
    host_spec, container_spec = parsed
    try:
        return _expand_publish(host_spec, container_spec, origin)
    except ValueError:
        return []


def _mapping_text(content: str) -> str:
    """Drop the YAML list dash so the value can be parsed on its own.

    ``- "3000:80"`` and ``-"3000:80"`` both become the quoted mapping.
    A nested key such as ``published: 4000`` has no dash and is returned
    unchanged; the publish parser then rejects it because ``published``
    is not a port token.
    """
    text = content.strip()
    if text.startswith("- ") or text.startswith("-\t"):
        return text[1:].strip()
    if len(text) > 1 and text[0] == "-" and text[1] in {"'", '"'}:
        return text[1:].strip()
    return text


def _publish_host_and_container(value: str) -> tuple[str, str] | None:
    """Return ``(host_spec, container_spec)`` or None.

    ``container_spec`` is ``""`` for a bare host port. Splitting on colons
    *outside* ``[brackets]`` is what makes ``127.0.0.1:5432:5432`` yield
    host ``5432`` instead of the last IPv4 octet. The host port is the
    field immediately before the last ``:port``; if that field is not a
    number (an IP with only one port after it), the line is not a host
    publish we can name.
    """
    text = _unquote(value.strip())
    if not text:
        return None
    # ``80/tcp`` exposes a container port. There is no host side to expect.
    if ":" not in text and "/" in text:
        return None
    proto = _PROTO_SUFFIX.search(text)
    if proto is not None and ":" in text:
        text = text[: proto.start()].rstrip()

    parts = [part.strip() for part in _split_outside_brackets(text)]
    if len(parts) == 1 and _PORT_OR_RANGE.fullmatch(parts[0]):
        return parts[0], ""
    if len(parts) >= 2:
        host, container = parts[-2], parts[-1]
        if _PORT_OR_RANGE.fullmatch(host) and _PORT_OR_RANGE.fullmatch(container):
            return host, container
    return None


def _split_outside_brackets(text: str) -> list[str]:
    """Split on ``:`` that are not inside a ``[]`` IPv6 literal."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "[":
            depth += 1
            current.append(char)
        elif char == "]":
            # A stray ``]`` should not make later colons look "inside".
            depth = max(0, depth - 1)
            current.append(char)
        elif char == ":" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _unquote(value: str) -> str:
    """Remove one matching pair of surrounding quotes, if present."""
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1].strip()
    return text


def _expand_publish(host_spec: str, container_spec: str, origin: str) -> list[ExpectedPort]:
    """Expand a host spec, labeling each port with its container port.

    Equal-width ranges pair by offset (``3000-3002:4000-4002`` → 3000
    labeled ``4000``, and so on). A single container port is reused for
    every host port in a wider range. Two ranges of different widths keep
    the raw container spec as the label rather than inventing a pairing.
    """
    host_start, host_end = _port_bounds(host_spec)
    if not container_spec:
        return _expected_span(host_start, host_end, "", origin)

    cont_start, cont_end = _port_bounds(container_spec)
    host_span = host_end - host_start
    cont_span = cont_end - cont_start
    ports: list[ExpectedPort] = []
    for offset in range(host_span + 1):
        if cont_span == host_span:
            label = str(cont_start + offset)
        elif cont_start == cont_end:
            label = str(cont_start)
        else:
            label = container_spec
        ports.append(ExpectedPort(port=host_start + offset, label=label, origin=origin))
    return ports


def _dedupe_first_port(expected: list[ExpectedPort]) -> list[ExpectedPort]:
    """Keep the first row for each port. Later origins do not replace it."""
    seen: set[int] = set()
    unique: list[ExpectedPort] = []
    for item in expected:
        if item.port in seen:
            continue
        seen.add(item.port)
        unique.append(item)
    return unique


def _group_by_port(
    services: list[ListeningService],
) -> dict[int, list[ListeningService]]:
    """Inventory order preserved so the first row is the collector's first row."""
    grouped: dict[int, list[ListeningService]] = {}
    for service in services:
        grouped.setdefault(service.port, []).append(service)
    return grouped


def _group_blocking_held(
    services: list[ListeningService],
) -> dict[int, list[ListeningService]]:
    """Held rows that can make ``bind()`` fail. ESTABLISHED is left out."""
    grouped: dict[int, list[ListeningService]] = {}
    for service in services:
        if not _blocks_bind(service):
            continue
        grouped.setdefault(service.port, []).append(service)
    return grouped


def _blocks_bind(service: ListeningService) -> bool:
    """True when ``service.state`` is in ``BIND_BLOCKING_STATES``.

    Case-insensitive on purpose. ``psutil`` emits the uppercase names in
    that set; a hand-built inventory might not. Same rule as
    ``lookup._blocks_bind``. ESTABLISHED is absent from the set so a lone
    client socket does not count as held for status.
    """
    state = (service.state or "").strip().upper()
    return state in BIND_BLOCKING_STATES


def _host_phrase(service: ListeningService) -> str:
    """Process name, plus pid when the OS told us one.

    Command lines are omitted. They are what distinguish two ``node.exe``
    processes in a full lookup, but they are too long for one status cell.
    The pid is the short discriminator.
    """
    name = service.process_name.strip() or "unknown process"
    if service.pid is None:
        return name
    return f"{name} (pid {service.pid})"


def _docker_phrase(service: ListeningService) -> str:
    """Container name plus the publish detail (``web ->80/tcp``) when set."""
    name = service.process_name.strip() or "container"
    detail = service.detail.strip()
    if detail:
        return f"{name} {detail}"
    return name


def _held_phrase(service: ListeningService) -> str:
    """Socket state first. The process name is context, not the status."""
    state = (service.state or "").strip().upper() or "HELD"
    name = service.process_name.strip()
    if name:
        return f"{state} {name}"
    return state


def _reserved_phrase(port_range: PortRange) -> str:
    """Exclusion interval, plus the collector's note when it has one.

    This stays shorter than ``exclusion_advice`` on purpose. That paragraph
    is the WinNAT remediation; a status cell only needs which range fired.
    """
    text = f"exclusion {port_range.label()}"
    note = port_range.note.strip()
    if note:
        return f"{text} ({note})"
    return text


def _unique_join(parts: Iterable[str]) -> str:
    """Join phrases with ``; ``, dropping exact duplicates and empties.

    Duplicate dual-stack rows often share a process name and pid; repeating
    them does not add information.
    """
    chosen: list[str] = []
    for part in parts:
        if part and part not in chosen:
            chosen.append(part)
    return "; ".join(chosen)


def _strip_unquoted_comment(line: str) -> str:
    """Cut a ``#`` comment that is not inside single or double quotes.

    Compose mappings and ``.portsight`` labels are both plain text.
    ``#`` inside ``"3000:80"`` must survive; ``8080 api # preview`` must not
    keep the preview note as part of the label. Backslash escapes apply
    only inside double quotes, which is how YAML double-quoted scalars work.
    Single-quoted YAML uses ``''`` and does not treat backslash specially;
    we still treat ``'`` as a toggle, which is enough for port lines.
    """
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_double:
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return line[:index]
    return line
