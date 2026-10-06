"""Lightweight unit tests for parsers, free-range math, and kill helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from portsight.kill import KillTarget, find_targets_on_port, free_port, kill_targets
from portsight.models import ListeningService, PortRange
from portsight.ranges import clip_ranges_to_band, contiguous_free_ranges
from portsight.scanner import SocketScan
from portsight.windows import parse_dynamic_port_range, parse_excluded_port_ranges


def test_parse_excluded_port_ranges() -> None:
    sample = """
Protocol tcp Port Exclusion Ranges

Start Port    End Port
----------    --------
      1462        1462
     40069       40168
     50000       50059     *
"""
    ranges = parse_excluded_port_ranges(sample)
    assert len(ranges) == 3
    assert ranges[0] == PortRange(
        start=1462,
        end=1462,
        kind="reserved",
        administered=False,
        note="system exclusion",
    )
    assert ranges[2].administered is True
    assert ranges[2].start == 50000


def test_parse_dynamic_port_range() -> None:
    sample = """
Protocol tcp Dynamic Port Range
---------------------------------
Start Port      : 49152
Number of Ports : 16384
"""
    pool = parse_dynamic_port_range(sample)
    assert pool is not None
    assert pool.start == 49152
    assert pool.end == 65535
    assert pool.size == 16384


def test_contiguous_free_ranges_skips_listeners_and_reserved() -> None:
    reserved = [PortRange(start=100, end=102, kind="reserved")]
    free = contiguous_free_ranges({80, 443}, reserved, scan_start=78, scan_end=105)
    labels = [r.label() for r in free]
    assert "78-79" in labels
    assert "81-99" in labels
    assert "103-105" in labels
    # Occupied / reserved ports must not appear as free singles.
    assert "80" not in labels
    assert "100-102" not in labels


def test_clip_ranges_to_band() -> None:
    ranges = [PortRange(start=1000, end=2000, kind="free")]
    clipped = clip_ranges_to_band(ranges, 1024, 1500)
    assert clipped == [PortRange(start=1024, end=1500, kind="free", note="")]


def test_find_targets_groups_dual_stack_by_pid() -> None:
    services = [
        ListeningService("TCP", "0.0.0.0", 8080, 4242, "node.exe"),
        ListeningService("TCP", "::", 8080, 4242, "node.exe"),
        ListeningService("TCP", "127.0.0.1", 8080, 9999, "python.exe"),
    ]
    with patch(
        "portsight.kill.collect_socket_scan",
        return_value=SocketScan(listeners=services, held=[]),
    ):
        targets = find_targets_on_port(8080)

    assert len(targets) == 2
    assert targets[0].pid == 4242
    assert len(targets[0].endpoints) == 2
    assert targets[1].pid == 9999


def test_find_targets_rejects_invalid_port() -> None:
    with pytest.raises(ValueError):
        find_targets_on_port(0)
    with pytest.raises(ValueError):
        find_targets_on_port(70000)


def test_kill_targets_skips_protected_system_pid() -> None:
    target = KillTarget(
        pid=4,
        process_name="System",
        process_path="",
        endpoints=(ListeningService("TCP", "0.0.0.0", 445, 4, "System"),),
    )
    killed, failed, skipped = kill_targets([target])
    assert killed == []
    assert failed == []
    assert len(skipped) == 1
    assert "protected" in skipped[0][1]


def test_kill_targets_terminates_user_process() -> None:
    target = KillTarget(
        pid=12345,
        process_name="node.exe",
        process_path="C:\\node.exe",
        endpoints=(ListeningService("TCP", "127.0.0.1", 3000, 12345, "node.exe"),),
    )
    mock_proc = MagicMock()
    mock_proc.name.return_value = "node.exe"
    mock_proc.wait.return_value = 0

    with (
        patch("portsight.kill.psutil.Process", return_value=mock_proc),
        patch("portsight.kill._is_self", return_value=False),
    ):
        killed, failed, skipped = kill_targets([target])

    assert len(killed) == 1
    assert failed == []
    assert skipped == []
    mock_proc.terminate.assert_called_once()


def test_free_port_already_free() -> None:
    with (
        patch("portsight.kill.collect_socket_scan", return_value=SocketScan([], [])),
        patch(
            "portsight.docker_ports.collect_docker_published_ports",
            return_value=[],
        ),
    ):
        outcome = free_port(55555)
    assert "already free" in outcome.message
    assert outcome.already_free
    assert outcome.targets == []


def test_parse_docker_published_ports() -> None:
    from portsight.docker_ports import parse_published_ports

    sample = """
open-webui|0.0.0.0:3000->8080/tcp, [::]:3000->8080/tcp|abc123
edge-discovery-minio|0.0.0.0:9000-9001->9000-9001/tcp|def456
edge-source-hybrid|5302/tcp|ghi789
"""
    services = parse_published_ports(sample)
    ports = {(s.port, s.address, s.process_name) for s in services}
    assert (3000, "0.0.0.0", "open-webui") in ports
    assert (3000, "::", "open-webui") in ports
    assert (9000, "0.0.0.0", "edge-discovery-minio") in ports
    assert (9001, "0.0.0.0", "edge-discovery-minio") in ports
    # Exposed-but-not-published must not appear.
    assert all(s.port != 5302 for s in services)
    assert all(s.source == "docker" for s in services)


def test_take_free_ports_lowest_and_contiguous() -> None:
    from portsight.ranges import take_free_ports

    ranges = [
        PortRange(start=3000, end=3002, kind="free"),
        PortRange(start=4000, end=4010, kind="free"),
    ]
    assert take_free_ports(ranges, 4) == [3000, 3001, 3002, 4000]
    assert take_free_ports(ranges, 3, contiguous=True) == [3000, 3001, 3002]
    assert take_free_ports(ranges, 5, contiguous=True) == list(range(4000, 4005))
    assert take_free_ports(ranges, 2, window_start=4005, window_end=4006) == [4005, 4006]
    assert take_free_ports(ranges, 3, contiguous=True, window_start=3000, window_end=3002) == [
        3000,
        3001,
        3002,
    ]
    assert take_free_ports(ranges, 4, contiguous=True, window_start=3000, window_end=3002) == []


def test_exclusion_advice_names_winnat() -> None:
    from portsight.windows import exclusion_advice, find_exclusion

    reserved = [
        PortRange(
            start=50000,
            end=50059,
            kind="reserved",
            administered=True,
            note="TCP administered exclusion",
        ),
    ]
    assert find_exclusion(50010, reserved) is not None
    assert find_exclusion(80, reserved) is None
    advice = exclusion_advice(50010, reserved)
    assert advice is not None
    assert "winnat" in advice
    assert "50000-50059" in advice


def test_filter_exposed_and_process() -> None:
    from portsight.filters import filter_services, is_exposed_address

    assert is_exposed_address("0.0.0.0") is True
    assert is_exposed_address("::") is True
    assert is_exposed_address("127.0.0.1") is False
    assert is_exposed_address("::1") is False

    rows = [
        ListeningService("TCP", "127.0.0.1", 3000, 1, "node.exe", cmdline="node vite"),
        ListeningService("TCP", "0.0.0.0", 3000, 1, "node.exe", cmdline="node vite"),
        ListeningService("TCP", "0.0.0.0", 5432, 2, "postgres.exe"),
    ]
    exposed = filter_services(rows, exposed_only=True)
    assert [row.port for row in exposed] == [3000, 5432]
    node = filter_services(rows, process="vite")
    assert len(node) == 2
    assert filter_services(rows, process="postgres", exposed_only=True)[0].port == 5432


def test_pick_random_free_port_stays_in_ranges() -> None:
    from portsight.ranges import pick_random_free_port

    ranges = [
        PortRange(start=2000, end=2002, kind="free"),
        PortRange(start=5000, end=5000, kind="free"),
    ]
    picks = {pick_random_free_port(ranges, prefer_registered=True) for _ in range(40)}
    assert picks <= {2000, 2001, 2002, 5000}
    assert None not in picks


def test_free_port_reports_docker_owner() -> None:
    docker_svc = ListeningService(
        protocol="TCP",
        address="0.0.0.0",
        port=3000,
        pid=None,
        process_name="open-webui",
        source="docker",
        detail="->8080/tcp",
    )
    with (
        patch("portsight.kill.collect_socket_scan", return_value=SocketScan([], [])),
        patch(
            "portsight.docker_ports.collect_docker_published_ports",
            return_value=[docker_svc],
        ),
    ):
        outcome = free_port(3000)
    assert "Docker" in outcome.message
    assert "open-webui" in outcome.message
    assert "docker stop" in outcome.message
