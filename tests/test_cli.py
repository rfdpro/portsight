"""CLI dispatch for the modes that print a machine-readable answer."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from portsight.cli import main
from portsight.docker_stop import DockerStopResult
from portsight.models import ListeningService, PortInventory, PortRange


def _inventory() -> PortInventory:
    """A snapshot with one host listener and a small free window."""
    return PortInventory(
        listening=[
            ListeningService(
                "TCP",
                "0.0.0.0",
                3000,
                10,
                "node.exe",
                cmdline="node vite",
                parent_name="pwsh.exe",
            )
        ],
        docker=[
            ListeningService(
                "TCP",
                "0.0.0.0",
                5432,
                None,
                "postgres",
                source="docker",
                detail="->5432/tcp",
            )
        ],
        free=[PortRange(start=4000, end=4005, kind="free")],
        docker_available=True,
    )


def test_check_free_and_in_use(capsys: pytest.CaptureFixture[str]) -> None:
    inventory = _inventory()
    with patch("portsight.cli.build_inventory", return_value=inventory):
        assert main(["--check", "4000"]) == 0
        assert main(["--check", "3000"]) == 1
    captured = capsys.readouterr()
    assert "free" in captured.out
    assert "in use" in captured.out


def test_take_prints_lowest_ports(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        assert main(["--take", "3", "--from", "4000", "--to", "4005"]) == 0
    assert capsys.readouterr().out.strip().splitlines() == ["4000", "4001", "4002"]


def test_random_window_stays_inside(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        assert main(["--random", "--from", "4000", "--to", "4002"]) == 0
    port = int(capsys.readouterr().out.strip())
    assert 4000 <= port <= 4002


def test_port_json_includes_command(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        assert main(["--port", "3000", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["free"] is False
    assert payload["listeners"][0]["cmdline"] == "node vite"
    assert payload["listeners"][0]["parent_name"] == "pwsh.exe"


def test_json_report_is_schema_v1(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        assert main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["listening"][0]["port"] == 3000


def test_exposed_filter_hides_loopback_in_json(capsys: pytest.CaptureFixture[str]) -> None:
    inventory = _inventory()
    inventory.listening.append(ListeningService("TCP", "127.0.0.1", 9, 1, "local.exe"))
    with patch("portsight.cli.build_inventory", return_value=inventory):
        assert main(["--json", "--exposed"]) == 0
    ports = [row["port"] for row in json.loads(capsys.readouterr().out)["listening"]]
    assert 3000 in ports
    assert 9 not in ports


def test_from_without_take_or_random_is_an_error() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--from", "80"])
    assert caught.value.code == 2


def test_stop_runs_planned_container() -> None:
    result = DockerStopResult(
        containers=["postgres"],
        stopped=["postgres"],
        failed=[],
        message="stopped postgres",
    )
    with (
        patch("portsight.cli.build_inventory", return_value=_inventory()),
        patch("portsight.cli.stop_containers", return_value=result) as stop,
    ):
        assert main(["--stop", "5432", "-y", "--no-color"]) == 0
    stop.assert_called_once_with(["postgres"])


def test_diff_exit_code(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    from portsight.snapshot import save_snapshot

    before = PortInventory()
    path = tmp_path / "snap.json"
    save_snapshot(before, path)
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        code = main(["--diff", str(path), "--no-color"])
    assert code == 1
    assert "listen" in capsys.readouterr().out


def test_diff_reads_baseline_before_snapshot_overwrites_it(tmp_path) -> None:
    """``--snapshot f --diff f`` compares against the old file, then updates it."""
    from portsight.snapshot import load_snapshot, save_snapshot

    path = tmp_path / "state.json"
    save_snapshot(PortInventory(), path)
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        assert main(["--snapshot", str(path), "--diff", str(path)]) == 1
        # The file now holds the current scan, so a second run is quiet.
        assert main(["--snapshot", str(path), "--diff", str(path)]) == 0
    assert load_snapshot(path)["listening"][0]["port"] == 3000


def test_unreadable_snapshot_is_exit_2_on_stderr(tmp_path, capsys) -> None:
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        assert main(["--diff", str(tmp_path / "missing.json")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err


def test_random_with_no_free_port_fails_cleanly(capsys) -> None:
    with patch("portsight.cli.build_inventory", return_value=_inventory()):
        assert main(["--random", "--from", "3000", "--to", "3000"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no free ports" in captured.err


@pytest.mark.parametrize("argv", [["--port", "0"], ["--check", "70000"], ["--take", "0"]])
def test_out_of_range_values_are_usage_errors(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2


def test_kill_without_terminal_declines_instead_of_crashing(monkeypatch) -> None:
    from portsight.kill import KillTarget

    target = KillTarget(pid=999, process_name="node.exe", process_path="", endpoints=())
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    with (
        patch("portsight.cli.find_targets_on_port", return_value=[target]),
        patch("portsight.cli.free_port") as free,
    ):
        assert main(["--kill", "3000", "--no-color"]) == 130
    free.assert_not_called()


def test_kill_uses_the_previewed_targets() -> None:
    from portsight.kill import KillOutcome, KillTarget

    target = KillTarget(pid=999, process_name="node.exe", process_path="", endpoints=())
    outcome = KillOutcome(port=3000, targets=[target], killed=[target])
    with (
        patch("portsight.cli.find_targets_on_port", return_value=[target]),
        patch("portsight.cli.free_port", return_value=outcome) as free,
    ):
        assert main(["--kill", "3000", "-y", "--no-color"]) == 0
    assert free.call_args.kwargs["targets"] == [target]


def test_help_lists_examples_and_exit_codes(capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0
    out = capsys.readouterr().out
    assert "examples:" in out
    assert "exit codes:" in out
    assert "query one port" in out
