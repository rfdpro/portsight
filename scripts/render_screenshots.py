"""Render the README screenshots from a synthetic inventory.

Uses made-up processes and containers so no real host details end up in the
repository. Re-run after changing the report layout:

    python scripts/render_screenshots.py
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from portsight.lookup import lookup_port
from portsight.models import ListeningService, PortInventory, PortRange
from portsight.ranges import REGISTERED_END, WELL_KNOWN_END, clip_ranges_to_band
from portsight.ranges import contiguous_free_ranges as free_ranges
from portsight.report import render_compact_report, render_port_lookup

OUT = Path(__file__).resolve().parent.parent / "docs" / "assets"


def _inventory() -> PortInventory:
    listening = [
        ListeningService("TCP", "0.0.0.0", 135, 1104, "svchost.exe", parent_name="services.exe"),
        ListeningService("TCP", "0.0.0.0", 445, 4, "System"),
        ListeningService(
            "TCP",
            "127.0.0.1",
            3000,
            18244,
            "node.exe",
            cmdline="node node_modules/vite/bin/vite.js --port 3000",
            parent_name="pwsh.exe",
        ),
        ListeningService(
            "TCP",
            "0.0.0.0",
            8000,
            20516,
            "python.exe",
            cmdline="python -m uvicorn api.main:app --port 8000",
            parent_name="pwsh.exe",
        ),
        ListeningService("UDP", "0.0.0.0", 5353, 2380, "svchost.exe", parent_name="services.exe"),
    ]
    docker = [
        ListeningService(
            "TCP", "0.0.0.0", 5432, None, "db-postgres-1", source="docker", detail="->5432/tcp"
        ),
        ListeningService(
            "TCP", "0.0.0.0", 6379, None, "cache-redis-1", source="docker", detail="->6379/tcp"
        ),
    ]
    reserved = [
        PortRange(5357, 5357, "reserved", note="TCP system exclusion"),
        PortRange(50000, 50059, "reserved", administered=True, note="TCP administered exclusion"),
        PortRange(51940, 52039, "reserved", note="TCP system exclusion"),
    ]
    occupied = {service.port for service in listening + docker}
    free = free_ranges(occupied, reserved)
    held = [ListeningService("TCP", "127.0.0.1", 3001, None, "", state="TIME_WAIT")]
    return PortInventory(
        listening=listening,
        docker=docker,
        reserved=reserved,
        dynamic=[PortRange(49152, 65535, "dynamic", note="Windows ephemeral / dynamic port pool")],
        free=free,
        well_known_free=clip_ranges_to_band(free, 1, WELL_KNOWN_END),
        registered_free=clip_ranges_to_band(free, WELL_KNOWN_END + 1, REGISTERED_END),
        ephemeral_free=clip_ranges_to_band(free, REGISTERED_END + 1, 65535),
        docker_available=True,
        held=held,
    )


def _recorder() -> Console:
    # Writing to a UTF-8 buffer keeps Rich on Unicode box drawing even when
    # the invoking terminal is a legacy code page.
    return Console(record=True, width=96, file=io.StringIO(), force_terminal=True)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    inventory = _inventory()
    with patch("portsight.report.node", return_value="devbox"):
        console = _recorder()
        render_compact_report(inventory, console=console)
        console.save_svg(str(OUT / "compact.svg"), title="portsight -c")

        console = _recorder()
        render_port_lookup(lookup_port(3000, inventory), console=console)
        console.save_svg(str(OUT / "port.svg"), title="portsight --port 3000")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
