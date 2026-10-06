"""Socket-scan behavior that the report and --check depend on."""

from __future__ import annotations

import socket
from types import SimpleNamespace
from unittest.mock import patch

import psutil

from portsight.scanner import ProcessIdentity, collect_socket_scan


def _conn(ip: str, port: int, status: str, pid: int | None, sock_type: int = socket.SOCK_STREAM):
    """Minimal stand-in for a psutil connection namedtuple."""
    return SimpleNamespace(
        laddr=SimpleNamespace(ip=ip, port=port),
        raddr=(),
        type=sock_type,
        status=status,
        pid=pid,
    )


def test_scan_keeps_listeners_and_time_wait_apart() -> None:
    connections = [
        _conn("127.0.0.1", 3000, psutil.CONN_LISTEN, 10),
        _conn("127.0.0.1", 3000, psutil.CONN_TIME_WAIT, 10),
        _conn("0.0.0.0", 53, psutil.CONN_NONE, 4, socket.SOCK_DGRAM),
    ]
    identity = ProcessIdentity(
        name="node.exe",
        path="C:\\node.exe",
        cmdline="node vite dev",
        parent_pid=9,
        parent_name="pwsh.exe",
    )
    with (
        patch("portsight.scanner.psutil.net_connections", return_value=connections),
        patch("portsight.scanner._process_identity", return_value=identity),
    ):
        scan = collect_socket_scan()

    assert scan.incomplete is False
    assert [(row.port, row.state) for row in scan.listeners] == [(53, "BOUND"), (3000, "LISTEN")]
    assert scan.held[0].state == "TIME_WAIT"
    assert scan.held[0].cmdline == "node vite dev"
    assert scan.listeners[1].parent_name == "pwsh.exe"


def test_scan_access_denied_is_incomplete_not_empty_success() -> None:
    with patch(
        "portsight.scanner.psutil.net_connections",
        side_effect=psutil.AccessDenied(),
    ):
        scan = collect_socket_scan()

    assert scan.listeners == []
    assert scan.held == []
    assert scan.incomplete is True
    assert "elevated" in scan.note
