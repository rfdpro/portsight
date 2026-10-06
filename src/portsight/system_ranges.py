"""Per-OS discovery of reserved (unbindable) and dynamic (ephemeral) ranges.

Only Windows has a reserved-range concept that makes ``bind()`` fail with
nothing listening: Hyper-V, WinNAT, and admins add *excluded port ranges*
through the Windows Filtering Platform. Linux ``ip_local_reserved_ports``
looks similar but only keeps ports out of automatic ephemeral assignment;
an explicit bind still succeeds, so it is deliberately not reported as
reserved here.

Every OS has an ephemeral pool, and knowing it helps explain why a port
"randomly" gets taken by outbound connections:

* Windows: ``netsh interface ipv4 show dynamicportrange``
* Linux: ``/proc/sys/net/ipv4/ip_local_port_range``
* macOS / BSD: ``sysctl net.inet.ip.portrange.first`` / ``.last``

Every collector returns empty results on failure instead of raising, so a
restricted sandbox still gets a listener report.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from portsight.models import PortRange
from portsight.windows import collect_all_reserved
from portsight.windows import collect_dynamic_range as collect_windows_dynamic_range

_LINUX_PORT_RANGE = Path("/proc/sys/net/ipv4/ip_local_port_range")
_SYSCTL_TIMEOUT = 5


def reserved_ranges_supported() -> bool:
    """True on the one OS where excluded port ranges exist (Windows)."""
    return sys.platform == "win32"


def collect_reserved_ranges() -> list[PortRange]:
    """Unbindable ranges for this OS. Empty everywhere except Windows."""
    if not reserved_ranges_supported():
        return []
    return collect_all_reserved(("tcp", "udp"))


def collect_dynamic_range() -> PortRange | None:
    """The OS ephemeral TCP port pool, or ``None`` when it cannot be read."""
    if sys.platform == "win32":
        return collect_windows_dynamic_range("tcp")
    if sys.platform.startswith("linux"):
        try:
            text = _LINUX_PORT_RANGE.read_text(encoding="ascii")
        except OSError:
            return None
        return parse_linux_port_range(text)
    if sys.platform == "darwin" or "bsd" in sys.platform:
        return _bsd_dynamic_range()
    return None


def parse_linux_port_range(text: str) -> PortRange | None:
    """Parse ``ip_local_port_range`` (two integers, e.g. ``32768\\t60999``)."""
    parts = text.split()
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return None
    return _dynamic(int(parts[0]), int(parts[1]), "Linux ip_local_port_range")


def parse_sysctl_port_range(first: str, last: str) -> PortRange | None:
    """Parse ``sysctl -n`` values for the BSD / macOS ephemeral pool."""
    first, last = first.strip(), last.strip()
    if not first.isdigit() or not last.isdigit():
        return None
    return _dynamic(int(first), int(last), "net.inet.ip.portrange")


def _bsd_dynamic_range() -> PortRange | None:
    values: list[str] = []
    for key in ("net.inet.ip.portrange.first", "net.inet.ip.portrange.last"):
        try:
            completed = subprocess.run(
                ["sysctl", "-n", key],
                capture_output=True,
                text=True,
                check=False,
                timeout=_SYSCTL_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if completed.returncode != 0:
            return None
        values.append(completed.stdout)
    return parse_sysctl_port_range(values[0], values[1])


def _dynamic(start: int, end: int, note: str) -> PortRange | None:
    if not 1 <= start <= end <= 65535:
        return None
    return PortRange(start=start, end=end, kind="dynamic", note=note)
