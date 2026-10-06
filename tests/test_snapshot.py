"""Unit tests for snapshot JSON and pure diff helpers.

Inventories are built by hand. Nothing here scans the OS, calls Docker,
or renders Rich.
"""

from __future__ import annotations

import json

import pytest

from portsight.models import ListeningService, PortInventory, PortRange
from portsight.snapshot import (
    SCHEMA_VERSION,
    SnapshotDiff,
    diff_inventory,
    diff_snapshots,
    dumps_inventory,
    format_diff_lines,
    inventory_to_dict,
    load_snapshot,
    loads_snapshot,
    save_snapshot,
    service_to_dict,
)

_DOCUMENT_KEYS = {
    "schema_version",
    "scan_incomplete",
    "scan_note",
    "docker_available",
    "listening",
    "docker",
    "held",
    "reserved",
    "dynamic",
    "free",
}

_SERVICE_KEYS = {
    "protocol",
    "address",
    "port",
    "pid",
    "process_name",
    "process_path",
    "source",
    "detail",
    "cmdline",
    "parent_pid",
    "parent_name",
    "state",
}

_RANGE_KEYS = {"start", "end", "kind", "administered", "note"}


def _host(**overrides) -> ListeningService:
    """A host listener. Override only the fields a test cares about."""
    fields = dict(
        protocol="TCP",
        address="127.0.0.1",
        port=80,
        pid=4,
        process_name="httpd.exe",
        process_path=r"C:\Windows\System32\httpd.exe",
        source="host",
        detail="",
        cmdline="httpd -k run",
        parent_pid=None,
        parent_name="",
        state="LISTEN",
    )
    fields.update(overrides)
    return ListeningService(**fields)


def _round_trip_inventory() -> PortInventory:
    """Small inventory that exercises null pids, unicode, and every list."""
    return PortInventory(
        listening=[
            _host(
                process_name="café.exe",
                cmdline="café --port 80",
                parent_pid=1000,
                parent_name="services.exe",
            )
        ],
        docker=[
            ListeningService(
                protocol="TCP",
                address="0.0.0.0",
                port=5432,
                pid=None,
                process_name="postgres",
                process_path="abc123def",
                source="docker",
                detail="->5432/tcp",
                cmdline="",
                parent_pid=None,
                parent_name="",
                state="LISTEN",
            )
        ],
        held=[
            _host(
                port=443,
                pid=9,
                process_name="chrome.exe",
                process_path=r"C:\chrome.exe",
                cmdline="",
                state="TIME_WAIT",
            )
        ],
        reserved=[
            PortRange(
                start=50000,
                end=50059,
                kind="reserved",
                administered=True,
                note="hyper-v",
            )
        ],
        dynamic=[PortRange(start=49152, end=65535, kind="dynamic", note="ephemeral")],
        free=[PortRange(start=1, end=79, kind="free", note="available")],
        # Derived bands must not leak into the document even when set.
        well_known_free=[PortRange(start=1, end=79, kind="free")],
        docker_available=True,
        scan_incomplete=True,
        scan_note="accès refusé",
    )


def _changed_pair() -> tuple[PortInventory, PortInventory]:
    """Older and newer inventories covering the diff cases the CLI needs.

    The httpd row stays, but its command line changes. That must not
    show up: identity ignores cmdline. The reserved single port 1462
    stays too, with only its note changed. Free and dynamic spans also
    change and must stay out of the diff.
    """
    staying_listen = _host()
    before = PortInventory(
        listening=[staying_listen],
        docker=[
            ListeningService(
                protocol="TCP",
                address="0.0.0.0",
                port=5432,
                pid=None,
                process_name="postgres",
                process_path="abc",
                source="docker",
                detail="->5432/tcp",
            )
        ],
        reserved=[
            PortRange(start=1462, end=1462, kind="reserved", administered=True, note="old"),
            PortRange(
                start=50000,
                end=50059,
                kind="reserved",
                administered=True,
                note="hyper-v",
            ),
        ],
        dynamic=[PortRange(start=49152, end=65535, kind="dynamic")],
        free=[PortRange(start=81, end=1000, kind="free")],
        docker_available=True,
    )
    after = PortInventory(
        listening=[
            _host(cmdline="httpd -k restart"),
            _host(
                address="0.0.0.0",
                port=3000,
                pid=1,
                process_name="node.exe",
                process_path=r"C:\node.exe",
                cmdline="node server.js",
                parent_pid=400,
                parent_name="powershell.exe",
            ),
        ],
        docker=[],
        held=[
            _host(
                port=443,
                pid=9,
                process_name="chrome.exe",
                process_path=r"C:\chrome.exe",
                cmdline="",
                state="TIME_WAIT",
            )
        ],
        reserved=[
            PortRange(start=1462, end=1462, kind="reserved", administered=True, note="new"),
            PortRange(start=200, end=200, kind="reserved", administered=False, note="added"),
        ],
        dynamic=[PortRange(start=50000, end=65535, kind="dynamic")],
        free=[PortRange(start=81, end=199, kind="free")],
        docker_available=True,
    )
    return before, after


def test_dumps_and_loads_round_trip_inventory() -> None:
    inventory = _round_trip_inventory()
    text = dumps_inventory(inventory)

    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    assert text.splitlines()[1].startswith("  ")
    # ensure_ascii=False: the characters themselves, not \\u escapes.
    assert "café.exe" in text
    assert "accès refusé" in text
    assert "\\u00e9" not in text
    assert "well_known_free" not in text
    assert "registered_free" not in text
    assert "ephemeral_free" not in text

    loaded = loads_snapshot(text)
    assert loaded == inventory_to_dict(inventory)
    assert set(loaded) == _DOCUMENT_KEYS
    assert loaded["schema_version"] == SCHEMA_VERSION == 1
    assert loaded["scan_incomplete"] is True
    assert loaded["scan_note"] == "accès refusé"
    assert loaded["docker_available"] is True

    listener = loaded["listening"][0]
    assert set(listener) == _SERVICE_KEYS
    assert listener["process_name"] == "café.exe"
    assert listener["pid"] == 4
    assert listener["parent_pid"] == 1000

    docker = loaded["docker"][0]
    assert docker["pid"] is None
    assert docker["parent_pid"] is None
    assert docker["source"] == "docker"
    assert docker["port"] == 5432

    assert set(loaded["reserved"][0]) == _RANGE_KEYS
    assert loaded["reserved"][0]["administered"] is True
    assert loaded["reserved"][0]["start"] == 50000
    assert loaded["free"][0]["kind"] == "free"
    assert loaded["dynamic"][0]["end"] == 65535
    # Still plain dicts, not PortRange instances.
    assert type(loaded["free"][0]) is dict
    assert type(loaded["dynamic"][0]) is dict


def test_service_and_range_dicts_use_null_for_missing_pids() -> None:
    service = service_to_dict(
        ListeningService("UDP", "::", 53, None, "dns.exe", source="host", state="BOUND")
    )
    assert service["pid"] is None
    assert service["parent_pid"] is None
    assert service["protocol"] == "UDP"
    encoded = json.dumps(service)
    assert '"pid": null' in encoded
    assert '"parent_pid": null' in encoded


def test_save_and_load_snapshot_utf8(tmp_path) -> None:
    inventory = _round_trip_inventory()
    path = tmp_path / "ports.json"
    save_snapshot(inventory, path)

    raw = path.read_bytes()
    assert b"\r" not in raw
    assert "café.exe".encode() in raw
    assert "accès refusé".encode() in raw
    assert load_snapshot(path) == loads_snapshot(dumps_inventory(inventory))


def test_loads_snapshot_rejects_bad_documents() -> None:
    good = json.loads(dumps_inventory(_round_trip_inventory()))

    with pytest.raises(ValueError):
        loads_snapshot("{")
    with pytest.raises(ValueError):
        loads_snapshot("[]")

    wrong_version = dict(good)
    wrong_version["schema_version"] = 2
    with pytest.raises(ValueError, match="schema_version"):
        loads_snapshot(json.dumps(wrong_version))

    # True == 1, but schema_version must be the integer 1, not a boolean.
    boolean_version = dict(good)
    boolean_version["schema_version"] = True
    with pytest.raises(ValueError, match="schema_version"):
        loads_snapshot(json.dumps(boolean_version))

    missing = dict(good)
    del missing["held"]
    with pytest.raises(ValueError, match="held"):
        loads_snapshot(json.dumps(missing))

    broken_row = json.loads(dumps_inventory(_round_trip_inventory()))
    del broken_row["listening"][0]["state"]
    with pytest.raises(ValueError, match="state"):
        loads_snapshot(json.dumps(broken_row))


def test_diff_detects_added_listener_removed_docker_and_reserved() -> None:
    before, after = _changed_pair()
    diff = diff_inventory(inventory_to_dict(before), after)

    assert [row["port"] for row in diff.listeners_added] == [3000]
    assert diff.listeners_added[0]["process_name"] == "node.exe"
    assert diff.listeners_added[0]["pid"] == 1
    # Full service object, not a projection, so the CLI can still read path.
    assert diff.listeners_added[0]["process_path"] == r"C:\node.exe"
    assert diff.listeners_removed == []

    assert len(diff.docker_removed) == 1
    assert diff.docker_removed[0]["port"] == 5432
    assert diff.docker_removed[0]["process_name"] == "postgres"
    assert diff.docker_removed[0]["pid"] is None
    assert diff.docker_added == []

    assert [row["port"] for row in diff.held_added] == [443]
    assert diff.held_added[0]["state"] == "TIME_WAIT"
    assert diff.held_removed == []

    assert [(row["start"], row["end"]) for row in diff.reserved_added] == [(200, 200)]
    assert [(row["start"], row["end"]) for row in diff.reserved_removed] == [(50000, 50059)]
    assert diff.reserved_removed[0]["administered"] is True
    assert diff.empty is False

    # Same result through the dict-to-dict entry point.
    assert diff_snapshots(inventory_to_dict(before), inventory_to_dict(after)) == diff


def test_format_diff_lines_for_listener_docker_held_and_reserved() -> None:
    before, after = _changed_pair()
    lines = format_diff_lines(diff_inventory(inventory_to_dict(before), after))
    assert lines == [
        "+ listen TCP 0.0.0.0:3000 node.exe pid=1",
        "- docker TCP 0.0.0.0:5432 postgres",
        "+ held TCP 127.0.0.1:443 chrome.exe pid=9 TIME_WAIT",
        "+ reserved 200",
        "- reserved 50000-50059 *",
    ]
    assert all("\x1b" not in line for line in lines)
    # Command-line-only edit of the staying httpd listener, the note-only
    # edit of port 1462, and the free/dynamic span edits are not lines.
    assert all("httpd" not in line for line in lines)
    assert all("1462" not in line for line in lines)


def test_format_diff_lines_empty_snapshot() -> None:
    inventory = _round_trip_inventory()
    diff = diff_inventory(inventory_to_dict(inventory), inventory)
    assert diff == SnapshotDiff()
    assert diff.empty is True
    assert format_diff_lines(diff) == ["no changes"]
    assert format_diff_lines(SnapshotDiff()) == ["no changes"]


def test_duplicate_docker_rows_are_counted_not_collapsed() -> None:
    row = service_to_dict(
        ListeningService(
            "TCP",
            "0.0.0.0",
            5432,
            None,
            "postgres",
            source="docker",
            process_path="abc",
            detail="->5432/tcp",
        )
    )
    before = inventory_to_dict(PortInventory())
    after = inventory_to_dict(PortInventory())
    before["docker"] = [row, dict(row)]
    after["docker"] = [dict(row)]

    diff = diff_snapshots(before, after)
    assert len(diff.docker_removed) == 1
    assert diff.docker_added == []
    assert format_diff_lines(diff) == ["- docker TCP 0.0.0.0:5432 postgres"]


def test_ipv6_endpoint_is_bracketed() -> None:
    diff = SnapshotDiff(
        listeners_added=[
            service_to_dict(ListeningService("TCP", "::", 3000, 1, "node.exe", source="host"))
        ]
    )
    assert format_diff_lines(diff) == ["+ listen TCP [::]:3000 node.exe pid=1"]


def test_diff_snapshots_rejects_incomplete_document() -> None:
    good = inventory_to_dict(PortInventory())
    with pytest.raises(ValueError, match="missing required keys"):
        diff_snapshots({"schema_version": 1}, good)


def test_diff_ignores_ephemeral_and_client_socket_churn() -> None:
    """Outbound traffic must not make ``--diff`` report a change."""
    pool = [PortRange(start=49152, end=65535, kind="dynamic")]
    churn = [
        ListeningService("TCP", "10.0.0.5", 58000, 9, "chrome.exe", state="ESTABLISHED"),
        ListeningService("TCP", "10.0.0.5", 58001, None, "", state="TIME_WAIT"),
        ListeningService("TCP", "10.0.0.5", 3001, 9, "chrome.exe", state="SYN_SENT"),
    ]
    before = PortInventory(dynamic=pool)
    after = PortInventory(dynamic=pool, held=churn)
    assert diff_inventory(inventory_to_dict(before), after).empty

    # A TIME_WAIT left on a dev port outside the pool is a real change.
    after.held.append(ListeningService("TCP", "0.0.0.0", 3000, None, "", state="TIME_WAIT"))
    diff = diff_inventory(inventory_to_dict(before), after)
    assert [row["port"] for row in diff.held_added] == [3000]


def test_diff_ignores_udp_client_binds_in_dynamic_pool() -> None:
    pool = [PortRange(start=49152, end=65535, kind="dynamic")]
    before = PortInventory(dynamic=pool)
    after = PortInventory(
        dynamic=pool,
        listening=[
            ListeningService("UDP", "0.0.0.0", 58602, 5, "dns-client.exe", state="BOUND"),
            ListeningService("TCP", "0.0.0.0", 58603, 5, "high-port-server.exe"),
            ListeningService("UDP", "0.0.0.0", 5353, 5, "mdns.exe", state="BOUND"),
        ],
    )
    diff = diff_inventory(inventory_to_dict(before), after)
    assert sorted(row["port"] for row in diff.listeners_added) == [5353, 58603]
