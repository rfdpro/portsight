"""Assemble a full ``PortInventory`` from scanner + OS ranges + Docker + free ranges.

This module is the orchestration seam: collectors stay pure, the report stays
presentational, and ``build_inventory`` is the single place that decides what
counts as reserved vs free for the CLI.
"""

from __future__ import annotations

from portsight.docker_ports import scan_docker_published_ports
from portsight.models import ListeningService, PortInventory, PortRange
from portsight.ranges import (
    PORT_MAX,
    REGISTERED_END,
    WELL_KNOWN_END,
    clip_ranges_to_band,
    contiguous_free_ranges,
)
from portsight.scanner import collect_socket_scan, listening_ports
from portsight.system_ranges import collect_dynamic_range, collect_reserved_ranges


def build_inventory(
    *,
    include_udp: bool = True,
    min_free_size: int = 1,
    include_docker: bool = True,
) -> PortInventory:
    """Snapshot listeners, Docker publishes, Windows exclusions, and free ranges.

    Docker published ports are merged into the occupied set even when Windows
    netstat cannot see them (Docker Desktop + WSL2). That keeps ``--random``
    and free-range suggestions from colliding with live containers.
    """
    scan = collect_socket_scan(include_udp=include_udp)
    services = scan.listeners
    docker_services: list[ListeningService] = []
    docker_ok = False
    if include_docker:
        scanned = scan_docker_published_ports()
        if scanned is not None:
            docker_ok = True
            docker_services = scanned

    reserved = collect_reserved_ranges()

    dynamic: list[PortRange] = []
    pool = collect_dynamic_range()
    if pool is not None:
        dynamic.append(pool)

    occupied = listening_ports(services) | listening_ports(docker_services)
    free = contiguous_free_ranges(
        occupied,
        reserved,
        min_size=min_free_size,
        scan_start=1,
        scan_end=PORT_MAX,
    )

    return PortInventory(
        listening=services,
        docker=docker_services,
        reserved=reserved,
        dynamic=dynamic,
        free=free,
        well_known_free=clip_ranges_to_band(free, 1, WELL_KNOWN_END),
        registered_free=clip_ranges_to_band(free, WELL_KNOWN_END + 1, REGISTERED_END),
        ephemeral_free=clip_ranges_to_band(free, REGISTERED_END + 1, PORT_MAX),
        docker_available=docker_ok,
        scan_incomplete=scan.incomplete,
        scan_note=scan.note,
        held=scan.held,
    )
