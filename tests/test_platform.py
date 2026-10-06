"""OS range parsers, Docker reachability, and kill edge cases. No real OS calls."""

from __future__ import annotations

from unittest.mock import patch

from portsight.docker_ports import collect_docker_published_ports, scan_docker_published_ports
from portsight.kill import KillTarget, free_port
from portsight.lookup import lookup_port
from portsight.models import ListeningService, PortInventory, endpoint_label
from portsight.scanner import SocketScan
from portsight.system_ranges import parse_linux_port_range, parse_sysctl_port_range
from portsight.windows import parse_dynamic_port_range


def test_linux_port_range() -> None:
    pool = parse_linux_port_range("32768\t60999\n")
    assert pool is not None
    assert (pool.start, pool.end, pool.kind) == (32768, 60999, "dynamic")


def test_linux_port_range_rejects_garbage() -> None:
    assert parse_linux_port_range("") is None
    assert parse_linux_port_range("abc def") is None
    assert parse_linux_port_range("60999 32768") is None


def test_sysctl_port_range() -> None:
    pool = parse_sysctl_port_range("49152\n", "65535\n")
    assert pool is not None
    assert (pool.start, pool.end) == (49152, 65535)
    assert parse_sysctl_port_range("", "65535") is None


def test_netsh_dynamic_range_localized() -> None:
    """German Windows translates the labels; the two numbers still parse."""
    sample = """
Protokoll tcp Dynamischer Portbereich
---------------------------------
Startport       : 49152
Anzahl der Ports: 16384
"""
    pool = parse_dynamic_port_range(sample)
    assert pool is not None
    assert (pool.start, pool.end) == (49152, 65535)


def test_endpoint_label_brackets_ipv6() -> None:
    assert endpoint_label("::", 135) == "[::]:135"
    assert endpoint_label("[::1]", 80) == "[::1]:80"
    assert endpoint_label("0.0.0.0", 80) == "0.0.0.0:80"


def test_lookup_reason_brackets_ipv6() -> None:
    inventory = PortInventory(listening=[ListeningService("TCP", "::", 135, 7, "svchost.exe")])
    assert "TCP [::]:135" in lookup_port(135, inventory).reasons[0]


def test_docker_unreachable_is_none_not_empty() -> None:
    with patch("portsight.docker_ports._run_docker_ps", return_value=None):
        assert scan_docker_published_ports() is None
        assert collect_docker_published_ports() == []
    with patch("portsight.docker_ports._run_docker_ps", return_value=""):
        assert scan_docker_published_ports() == []


def test_free_port_with_incomplete_scan_is_not_already_free() -> None:
    scan = SocketScan(listeners=[], held=[], incomplete=True, note="access denied")
    with patch("portsight.kill.collect_socket_scan", return_value=scan):
        outcome = free_port(3000)
    assert not outcome.already_free
    assert not outcome.ok
    assert "access denied" in outcome.message


def test_free_port_with_targets_does_not_rescan() -> None:
    target = KillTarget(pid=999_999, process_name="gone", process_path="", endpoints=())
    with (
        patch("portsight.kill.collect_socket_scan") as scan,
        patch("portsight.kill.kill_targets", return_value=([target], [], [])),
    ):
        outcome = free_port(3000, targets=[target])
    scan.assert_not_called()
    assert outcome.ok
