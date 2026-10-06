"""Compute contiguous free port ranges from occupied and reserved sets.

A port is considered *unavailable* when:
  1. Something is listening on it (any address / protocol we tracked), or
  2. Windows has an excluded/reserved range covering it.

Everything else in 1–65535 is free. We coalesce adjacent free ports into
inclusive ranges so the report stays readable (thousands of single ports
would be noise).
"""

from __future__ import annotations

from portsight.models import PortRange

# IANA-style bands used to bucket free ranges in the report.
WELL_KNOWN_END = 1023
REGISTERED_END = 49151
PORT_MAX = 65535
PORT_MIN = 1


def _occupied_mask(
    listening_ports: set[int],
    reserved: list[PortRange],
) -> list[bool]:
    """Boolean mask indexed by port number; True means unavailable.

    Index 0 is unused (port 0 is not a normal bind target). Building a dense
    mask is O(65536) and makes the subsequent free-range scan a single pass.
    """
    occupied = [False] * (PORT_MAX + 1)

    for port in listening_ports:
        if PORT_MIN <= port <= PORT_MAX:
            occupied[port] = True

    for port_range in reserved:
        start = max(PORT_MIN, port_range.start)
        end = min(PORT_MAX, port_range.end)
        for port in range(start, end + 1):
            occupied[port] = True

    return occupied


def contiguous_free_ranges(
    listening_ports: set[int],
    reserved: list[PortRange],
    *,
    min_size: int = 1,
    scan_start: int = PORT_MIN,
    scan_end: int = PORT_MAX,
) -> list[PortRange]:
    """Return inclusive free ranges within ``[scan_start, scan_end]``.

    Args:
        listening_ports: Ports with at least one active listener.
        reserved: Windows exclusion ranges (and any other blocks).
        min_size: Drop free spans smaller than this (useful for finding
            roomy blocks for multi-port apps).
        scan_start / scan_end: Limit the search window.
    """
    occupied = _occupied_mask(listening_ports, reserved)
    ranges: list[PortRange] = []

    start = max(PORT_MIN, scan_start)
    end = min(PORT_MAX, scan_end)
    cursor: int | None = None

    for port in range(start, end + 1):
        if not occupied[port]:
            if cursor is None:
                cursor = port
            continue

        # Hit an occupied port — close any open free span.
        if cursor is not None:
            span_end = port - 1
            if span_end - cursor + 1 >= min_size:
                ranges.append(
                    PortRange(
                        start=cursor,
                        end=span_end,
                        kind="free",
                        note="available to bind",
                    )
                )
            cursor = None

    if cursor is not None:
        span_end = end
        if span_end - cursor + 1 >= min_size:
            ranges.append(
                PortRange(
                    start=cursor,
                    end=span_end,
                    kind="free",
                    note="available to bind",
                )
            )

    return ranges


def clip_ranges_to_band(
    ranges: list[PortRange],
    band_start: int,
    band_end: int,
) -> list[PortRange]:
    """Intersect free ranges with an IANA band, dropping empty results."""
    clipped: list[PortRange] = []
    for port_range in ranges:
        start = max(port_range.start, band_start)
        end = min(port_range.end, band_end)
        if start <= end:
            clipped.append(
                PortRange(
                    start=start,
                    end=end,
                    kind=port_range.kind,
                    note=port_range.note,
                )
            )
    return clipped


def largest_ranges(ranges: list[PortRange], limit: int = 12) -> list[PortRange]:
    """Prefer the roomiest free blocks for a compact highlight section."""
    return sorted(ranges, key=lambda r: (-r.size, r.start))[:limit]


def summarize_free_ports(ranges: list[PortRange]) -> int:
    """Total count of free ports across all ranges."""
    return sum(port_range.size for port_range in ranges)


def take_free_ports(
    ranges: list[PortRange],
    count: int,
    *,
    contiguous: bool = False,
    window_start: int = PORT_MIN,
    window_end: int = PORT_MAX,
) -> list[int]:
    """Pick ``count`` free ports inside an inclusive window.

    Non-contiguous mode returns the lowest ``count`` free ports so scripts
    get a stable answer. Contiguous mode returns the lowest span that can
    hold ``count`` ports, expanded into an explicit list (the block a
    multi-service stack can bind in order).

    Returns an empty list when the window cannot satisfy the request,
    including when ``count`` is less than 1.
    """
    if count < 1:
        return []

    window = clip_ranges_to_band(ranges, window_start, window_end)
    if contiguous:
        for span in window:
            if span.size >= count:
                return list(range(span.start, span.start + count))
        return []

    picked: list[int] = []
    for span in window:
        for port in range(span.start, span.end + 1):
            picked.append(port)
            if len(picked) == count:
                return picked
    return []


def pick_random_free_port(
    ranges: list[PortRange],
    *,
    prefer_registered: bool = True,
    window_start: int | None = None,
    window_end: int | None = None,
) -> int | None:
    """Choose one uniformly random free port from ``ranges``.

    When ``prefer_registered`` is True, sample first from the intersection of
    free ranges with IANA registered ports (1024–49151) — the band people
    usually want for app servers. Falls back to the full free set if that
    band is empty.

    ``window_start`` / ``window_end`` restrict the sample to an inclusive
    span (either bound may be omitted). An explicit window replaces the
    registered-band preference so ``--from 4000 --to 4999`` means that
    span and nothing else.
    """
    import secrets

    candidates = ranges
    if window_start is not None or window_end is not None:
        start = PORT_MIN if window_start is None else window_start
        end = PORT_MAX if window_end is None else window_end
        candidates = clip_ranges_to_band(ranges, start, end)
        prefer_registered = False

    if prefer_registered:
        registered = clip_ranges_to_band(candidates, WELL_KNOWN_END + 1, REGISTERED_END)
        if registered:
            candidates = registered

    total = summarize_free_ports(candidates)
    if total <= 0:
        return None

    # Walk ranges with a single random offset so we never materialize 60k ints.
    offset = secrets.randbelow(total)
    for port_range in candidates:
        if offset < port_range.size:
            return port_range.start + offset
        offset -= port_range.size
    return None
