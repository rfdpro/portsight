"""Port lookup against hand-built inventories. No OS scan and no network."""

from __future__ import annotations

import pytest

from portsight.lookup import format_lookup_lines, lookup_port
from portsight.models import ListeningService, PortInventory, PortRange
from portsight.windows import exclusion_advice


def _service(
    *,
    port: int = 8080,
    protocol: str = "TCP",
    address: str = "127.0.0.1",
    pid: int | None = 4242,
    process_name: str = "node.exe",
    state: str = "LISTEN",
    source: str = "host",
    cmdline: str = "node server.js",
    parent_pid: int | None = 1000,
    parent_name: str = "python.exe",
    detail: str = "",
    process_path: str = r"C:\app\node.exe",
) -> ListeningService:
    """One socket row with the fields lookup actually prints."""
    return ListeningService(
        protocol=protocol,
        address=address,
        port=port,
        pid=pid,
        process_name=process_name,
        process_path=process_path,
        source=source,
        detail=detail,
        cmdline=cmdline,
        parent_pid=parent_pid,
        parent_name=parent_name,
        state=state,
    )


def test_free_port() -> None:
    """Other ports' listeners, publishes, exclusions, and TIME_WAIT do not count."""
    inventory = PortInventory(
        listening=[_service(port=80, process_name="httpd.exe", pid=4, cmdline="")],
        docker=[
            _service(
                port=3000,
                source="docker",
                process_name="web",
                pid=None,
                cmdline="",
                parent_pid=None,
                parent_name="",
                state="LISTEN",
            )
        ],
        reserved=[
            PortRange(start=50000, end=50059, kind="reserved", note="TCP system exclusion"),
        ],
        held=[_service(port=9, state="TIME_WAIT", process_name="chrome.exe", cmdline="")],
    )

    lookup = lookup_port(8080, inventory)

    assert lookup.port == 8080
    assert lookup.free is True
    assert lookup.listeners == []
    assert lookup.docker == []
    assert lookup.held == []
    assert lookup.exclusion is None
    assert lookup.exclusion_advice is None
    assert lookup.reasons == []
    assert format_lookup_lines(lookup) == ["free"]

    # Edges of the legal port space are classified, not rejected.
    assert lookup_port(1, PortInventory()).free is True
    assert lookup_port(65535, PortInventory()).free is True


def test_host_listener_makes_port_not_free() -> None:
    service = _service(process_name="node.exe", pid=4242, cmdline="node server.js")
    lookup = lookup_port(8080, PortInventory(listening=[service]))

    assert lookup.free is False
    assert lookup.listeners == [service]
    assert lookup.docker == []
    assert any("node.exe" in reason and "4242" in reason for reason in lookup.reasons)
    assert any("node server.js" in reason for reason in lookup.reasons)

    lines = format_lookup_lines(lookup)
    assert lines[0] == "in use"
    assert lines[1] == (
        "listen TCP 127.0.0.1 pid=4242 name=node.exe "
        "parent=1000/python.exe cmdline=node server.js state=LISTEN"
    )


def test_docker_publish_makes_port_not_free() -> None:
    service = _service(
        port=3000,
        address="0.0.0.0",
        source="docker",
        process_name="open-webui",
        process_path="abc123",
        pid=None,
        cmdline="",
        parent_pid=None,
        parent_name="",
        detail="->8080/tcp",
        state="LISTEN",
    )
    lookup = lookup_port(3000, PortInventory(docker=[service]))

    assert lookup.free is False
    assert lookup.listeners == []
    assert lookup.docker == [service]
    assert any("open-webui" in reason for reason in lookup.reasons)

    lines = format_lookup_lines(lookup)
    assert lines[0] == "in use"
    assert lines[1] == ("docker TCP 0.0.0.0 pid=- name=open-webui parent=- cmdline=- state=LISTEN")


def test_reserved_exclusion_makes_port_not_free() -> None:
    reserved = [
        PortRange(
            start=50000,
            end=50059,
            kind="reserved",
            administered=True,
            note="TCP administered exclusion",
        )
    ]
    lookup = lookup_port(50010, PortInventory(reserved=reserved))

    assert lookup.free is False
    assert lookup.listeners == []
    assert lookup.exclusion == reserved[0]
    assert lookup.exclusion_advice == exclusion_advice(50010, reserved)
    assert lookup.exclusion_advice is not None
    assert "winnat" in lookup.exclusion_advice
    assert any("50000-50059" in reason for reason in lookup.reasons)

    lines = format_lookup_lines(lookup)
    assert lines[0] == "in use"
    assert any("winnat" in line for line in lines)


def test_time_wait_held_socket_makes_port_not_free() -> None:
    held = _service(
        state="TIME_WAIT",
        process_name="chrome.exe",
        pid=55,
        cmdline="",
        parent_pid=None,
        parent_name="",
    )
    lookup = lookup_port(8080, PortInventory(held=[held]))

    assert lookup.free is False
    assert lookup.held == [held]
    assert any("TIME_WAIT" in reason for reason in lookup.reasons)

    lines = format_lookup_lines(lookup)
    assert lines[0] == "in use"
    assert any("TIME_WAIT" in line and "chrome.exe" in line for line in lines)


def test_established_held_socket_stays_free_but_is_listed() -> None:
    held = _service(
        state="ESTABLISHED",
        process_name="chrome.exe",
        pid=77,
        cmdline="chrome.exe --type=utility",
        parent_pid=70,
        parent_name="chrome.exe",
    )
    lookup = lookup_port(8080, PortInventory(held=[held]))

    assert lookup.free is True
    assert lookup.held == [held]
    assert lookup.reasons == []

    lines = format_lookup_lines(lookup)
    assert lines[0] == "free"
    assert lines[1] == (
        "held TCP 127.0.0.1 pid=77 name=chrome.exe "
        "parent=70/chrome.exe cmdline=chrome.exe --type=utility state=ESTABLISHED"
    )


@pytest.mark.parametrize("port", [0, -1, 65536, 100000])
def test_invalid_port_raises_value_error(port: int) -> None:
    with pytest.raises(ValueError, match="1-65535"):
        lookup_port(port, PortInventory())


def test_scan_incomplete_adds_note_but_empty_port_stays_free() -> None:
    note = (
        "Socket scan was incomplete (access denied). "
        "Re-run from an elevated shell to see listeners owned by system services."
    )
    lookup = lookup_port(
        8080,
        PortInventory(scan_incomplete=True, scan_note=note),
    )

    assert lookup.free is True
    assert lookup.listeners == []
    assert lookup.docker == []
    assert lookup.held == []
    assert any(note in reason for reason in lookup.reasons)

    lines = format_lookup_lines(lookup)
    assert lines[0] == "free"
    assert any(note in line for line in lines)

    # The flag is the switch: a leftover note without it is not a reason,
    # and a blank note with the flag set still surfaces a sentence.
    stale = lookup_port(9, PortInventory(scan_incomplete=False, scan_note=note))
    assert stale.free is True
    assert stale.reasons == []

    blank = lookup_port(9, PortInventory(scan_incomplete=True, scan_note="   "))
    assert blank.free is True
    assert any(reason.startswith("Scan incomplete:") for reason in blank.reasons)
