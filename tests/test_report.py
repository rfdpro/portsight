"""Every renderer runs on representative data without raising, and says what it should."""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from rich.console import Console

from portsight.docker_stop import DockerStopResult
from portsight.expect import ExpectedPort, ExpectedStatus
from portsight.inventory import build_inventory
from portsight.kill import KillOutcome, KillTarget
from portsight.lookup import lookup_port
from portsight.models import ListeningService, PortInventory, PortRange
from portsight.report import (
    render_compact_report,
    render_expected,
    render_kill_preview,
    render_kill_result,
    render_port_lookup,
    render_report,
    render_stop_result,
)
from portsight.scanner import SocketScan


def _console() -> Console:
    return Console(file=io.StringIO(), width=120, force_terminal=False, legacy_windows=False)


def _text(console: Console) -> str:
    return console.file.getvalue()


def _inventory(**overrides) -> PortInventory:
    listener = ListeningService(
        "TCP", "::", 3000, 10, "node.exe", cmdline="node vite", parent_name="pwsh.exe"
    )
    docker = ListeningService(
        "TCP", "0.0.0.0", 5432, None, "db", source="docker", detail="->5432/tcp"
    )
    free = [PortRange(1, 2999, "free"), PortRange(3001, 5431, "free")]
    values = dict(
        listening=[listener],
        docker=[docker],
        reserved=[PortRange(50000, 50059, "reserved", administered=True, note="TCP")],
        dynamic=[PortRange(49152, 65535, "dynamic")],
        free=free,
        well_known_free=[PortRange(1, 1023, "free")],
        registered_free=[PortRange(1024, 2999, "free")],
        docker_available=True,
    )
    values.update(overrides)
    return PortInventory(**values)


@pytest.mark.parametrize(
    "inventory",
    [
        _inventory(),
        PortInventory(),
        _inventory(scan_incomplete=True, scan_note="access denied"),
        _inventory(docker=[], docker_available=False),
    ],
    ids=["typical", "empty", "incomplete", "no-docker"],
)
def test_full_and_compact_reports_render(inventory: PortInventory) -> None:
    for render in (render_report, render_compact_report):
        console = _console()
        render(inventory, console=console)
        assert "PORTSIGHT" in _text(console)


def test_report_mentions_the_essentials() -> None:
    console = _console()
    render_report(_inventory(scan_incomplete=True, scan_note="access denied"), console=console)
    text = _text(console)
    for needle in ("node.exe", "db", "50000-50059", "49152-65535", "access denied"):
        assert needle in text


def test_reserved_table_explains_non_windows() -> None:
    console = _console()
    with patch("portsight.report.reserved_ranges_supported", return_value=False):
        render_report(_inventory(reserved=[]), console=console)
    assert "Windows-only" in _text(console)


def test_small_renderers() -> None:
    target = KillTarget(10, "node.exe", "", (ListeningService("TCP", "::", 3000, 10, "node"),))
    console = _console()
    render_kill_preview(3000, [target], console=console)
    render_kill_result(KillOutcome(3000, targets=[target], killed=[target]), console=console)
    render_kill_result(KillOutcome(3000, failed=[(target, "access denied")]), console=console)
    render_kill_result(KillOutcome(3000, message="free", already_free=True), console=console)
    render_port_lookup(lookup_port(3000, _inventory()), console=console)
    render_expected(
        [ExpectedStatus(ExpectedPort(3000, "web", "flag"), "host", "node.exe (pid 10)")],
        console=console,
    )
    render_expected([], console=console)
    render_stop_result(
        DockerStopResult(["db"], ["db"], [], "stopped container db"), console=console
    )
    text = _text(console)
    for needle in ("FREED", "FAILED", "ALREADY FREE", "in use", "web", "stopped container db"):
        assert needle in text


def test_build_inventory_merges_collectors() -> None:
    host = ListeningService("TCP", "0.0.0.0", 3000, 10, "node.exe")
    docker = ListeningService("TCP", "0.0.0.0", 5432, None, "db", source="docker")
    with (
        patch("portsight.inventory.collect_socket_scan", return_value=SocketScan([host], [])),
        patch("portsight.inventory.scan_docker_published_ports", return_value=[docker]),
        patch(
            "portsight.inventory.collect_reserved_ranges",
            return_value=[PortRange(4000, 4999, "reserved")],
        ),
        patch(
            "portsight.inventory.collect_dynamic_range",
            return_value=PortRange(49152, 65535, "dynamic"),
        ),
    ):
        inventory = build_inventory()
    assert inventory.docker_available
    free_ports = {p for r in inventory.free for p in range(r.start, r.end + 1)}
    assert not {3000, 5432, 4000, 4999} & free_ports
    assert {2999, 3001, 5000} <= free_ports
    assert inventory.registered_free[0].start == 1024


def test_build_inventory_without_docker() -> None:
    with (
        patch("portsight.inventory.collect_socket_scan", return_value=SocketScan([], [])),
        patch("portsight.inventory.scan_docker_published_ports", return_value=None),
        patch("portsight.inventory.collect_reserved_ranges", return_value=[]),
        patch("portsight.inventory.collect_dynamic_range", return_value=None),
    ):
        inventory = build_inventory()
    assert not inventory.docker_available
    assert inventory.dynamic == []
