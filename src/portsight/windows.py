"""Windows-specific reserved and dynamic port range discovery.

Microsoft documents that Hyper-V, IIS, and other components reserve TCP/UDP
ranges via the Windows Filtering Platform. Those show up in:

    netsh interface ipv4 show excludedportrange protocol=tcp|udp

Dynamic (ephemeral) pools come from:

    netsh interface ipv4 show dynamicportrange protocol=tcp|udp

Parsing ``netsh`` text is intentional: there is no stable documented Win32
API that returns the same exclusion table without elevation gymnastics, and
``netsh`` is available on every supported Windows SKU.
"""

from __future__ import annotations

import re
import subprocess
from typing import Literal

from portsight.models import PortRange

ProtocolName = Literal["tcp", "udp"]

# ``netsh`` prints rows like:
#   40069       40168
#   50000       50059     *
# The trailing asterisk marks administered exclusions.
_EXCLUSION_ROW = re.compile(
    r"^\s*(\d+)\s+(\d+)(?:\s+(\*))?\s*$",
    re.MULTILINE,
)

# Dynamic range block uses labeled fields rather than a table:
#   Start Port      : 49152
#   Number of Ports : 16384
_DYNAMIC_START = re.compile(r"Start Port\s*:\s*(\d+)", re.IGNORECASE)
_DYNAMIC_COUNT = re.compile(r"Number of Ports\s*:\s*(\d+)", re.IGNORECASE)
# Localized Windows translates those labels ("Startport", "Port de départ"),
# but the block is still exactly two ``label : number`` lines in that order.
_LABELED_NUMBER = re.compile(r":\s*(\d+)\s*$", re.MULTILINE)

_NETSH_TIMEOUT = 10


def _run_netsh(args: list[str]) -> str:
    """Run ``netsh`` and return stdout as text; empty string on failure.

    We deliberately avoid raising so the CLI can still show listening
    sockets if exclusion queries fail (restricted shells, a missing
    ``netsh`` on another OS, or a hung WFP query).
    """
    try:
        completed = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_NETSH_TIMEOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout or ""


def parse_excluded_port_ranges(netsh_output: str) -> list[PortRange]:
    """Parse ``show excludedportrange`` stdout into ``PortRange`` values."""
    ranges: list[PortRange] = []
    for match in _EXCLUSION_ROW.finditer(netsh_output):
        start = int(match.group(1))
        end = int(match.group(2))
        administered = match.group(3) == "*"
        if start > end or start < 0 or end > 65535:
            continue
        note = "administered exclusion" if administered else "system exclusion"
        ranges.append(
            PortRange(
                start=start,
                end=end,
                kind="reserved",
                administered=administered,
                note=note,
            )
        )
    ranges.sort(key=lambda r: (r.start, r.end))
    return ranges


def parse_dynamic_port_range(netsh_output: str) -> PortRange | None:
    """Parse ``show dynamicportrange`` into a single inclusive ``PortRange``."""
    start_match = _DYNAMIC_START.search(netsh_output)
    count_match = _DYNAMIC_COUNT.search(netsh_output)
    if start_match and count_match:
        start = int(start_match.group(1))
        count = int(count_match.group(1))
    else:
        numbers = _LABELED_NUMBER.findall(netsh_output)
        if len(numbers) != 2:
            return None
        start, count = int(numbers[0]), int(numbers[1])

    if count <= 0 or not 1 <= start <= 65535:
        return None

    end = min(start + count - 1, 65535)
    return PortRange(
        start=start,
        end=end,
        kind="dynamic",
        note="Windows ephemeral / dynamic port pool",
    )


def collect_excluded_ranges(protocol: ProtocolName = "tcp") -> list[PortRange]:
    """Fetch Windows excluded (reserved/unallocated) ranges for a protocol."""
    output = _run_netsh(
        [
            "interface",
            "ipv4",
            "show",
            "excludedportrange",
            f"protocol={protocol}",
        ]
    )
    return parse_excluded_port_ranges(output)


def collect_dynamic_range(protocol: ProtocolName = "tcp") -> PortRange | None:
    """Fetch the Windows dynamic port pool for a protocol."""
    output = _run_netsh(
        [
            "interface",
            "ipv4",
            "show",
            "dynamicportrange",
            f"protocol={protocol}",
        ]
    )
    return parse_dynamic_port_range(output)


def collect_all_reserved(protocols: tuple[ProtocolName, ...] = ("tcp", "udp")) -> list[PortRange]:
    """Merge TCP/UDP exclusions, coalescing identical intervals.

    A range reserved on either protocol is treated as unavailable for general
    binding advice — that matches how developers usually pick a free port.
    """
    merged: dict[tuple[int, int], PortRange] = {}
    for protocol in protocols:
        for port_range in collect_excluded_ranges(protocol):
            key = (port_range.start, port_range.end)
            existing = merged.get(key)
            if existing is None:
                merged[key] = PortRange(
                    start=port_range.start,
                    end=port_range.end,
                    kind="reserved",
                    administered=port_range.administered,
                    note=f"{protocol.upper()} {port_range.note}",
                )
            else:
                # Preserve administered flag if either source marks it.
                administered = existing.administered or port_range.administered
                note = existing.note
                if protocol.upper() not in note:
                    note = f"{note}; {protocol.upper()}"
                merged[key] = PortRange(
                    start=existing.start,
                    end=existing.end,
                    kind="reserved",
                    administered=administered,
                    note=note,
                )

    return sorted(merged.values(), key=lambda r: (r.start, r.end))


def find_exclusion(port: int, reserved: list[PortRange]) -> PortRange | None:
    """Return the reserved range that contains ``port``, if any.

    Ranges are few (dozens, not thousands), so a linear scan is clearer
    than building another 65k mask just for one lookup.
    """
    for port_range in reserved:
        if port_range.start <= port <= port_range.end:
            return port_range
    return None


def exclusion_advice(port: int, reserved: list[PortRange]) -> str | None:
    """Explain why a port inside a Windows exclusion cannot be bound.

    Hyper-V and the Windows NAT driver (WinNAT) are the usual source of
    these dynamic exclusions. Recycling WinNAT from an elevated shell
    rebuilds the table; it also drops live WSL2 / Docker forwards until
    those publishers bind again, so the hint says that explicitly.
    """
    hit = find_exclusion(port, reserved)
    if hit is None:
        return None

    admin = "administered " if hit.administered else ""
    note = hit.note or "excludedportrange"
    return (
        f"port {port} is inside Windows {admin}exclusion {hit.label()} ({note}). "
        "Nothing needs to be listening for a bind to fail. "
        "Hyper-V and WinNAT often create these dynamic exclusions. "
        "From an elevated shell you can recycle the NAT driver: "
        "net stop winnat & net start winnat "
        "(existing WSL2 and Docker port forwards drop until they republish)."
    )
