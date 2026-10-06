"""Unit tests for docker stop planning and execution.

No test invokes a real Docker CLI. ``stop_containers`` always receives a
fake runner, except the one case that patches ``subprocess.run`` to prove
the default runner builds an argv list and does not use a shell.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from portsight.docker_stop import (
    plan_docker_stop,
    stop_containers,
    validate_container_name,
)
from portsight.models import ListeningService


def _docker(
    port: int,
    name: str,
    *,
    address: str = "0.0.0.0",
    container_id: str = "abc123",
) -> ListeningService:
    """A published-port row shaped like ``docker_ports.parse_published_ports``."""
    return ListeningService(
        protocol="TCP",
        address=address,
        port=port,
        pid=None,
        process_name=name,
        process_path=container_id,
        source="docker",
        detail="->8080/tcp",
    )


def _host(port: int, name: str = "node.exe", pid: int = 4242) -> ListeningService:
    """A normal Windows listener that must never be selected for docker stop."""
    return ListeningService(
        protocol="TCP",
        address="127.0.0.1",
        port=port,
        pid=pid,
        process_name=name,
        process_path=r"C:\node.exe",
        source="host",
    )


def test_validate_container_name_accepts_docker_alphabet() -> None:
    assert validate_container_name("web") == "web"
    assert validate_container_name("  Ab_1.ok-name  ") == "Ab_1.ok-name"
    assert validate_container_name("a" * 128) == "a" * 128


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "has space", "-leading", ".dot", "semi;colon", "a" * 129, "path/name"],
)
def test_validate_container_name_rejects_surprising_values(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_container_name(bad)


def test_plan_by_port_finds_container_and_ignores_host_listeners() -> None:
    services = [
        _host(3000),
        _docker(3000, "open-webui", address="0.0.0.0"),
        # Dual-stack publish is two rows, one container.
        _docker(3000, "open-webui", address="::"),
        _docker(3001, "other-port"),
        # Wrong source must not be treated as a container even if the name looks like one.
        ListeningService(
            "TCP",
            "0.0.0.0",
            3000,
            9,
            "looks-like-container",
            source="host",
        ),
    ]
    plan = plan_docker_stop(port=3000, services=services, docker_available=True)

    assert plan.containers == ["open-webui"]
    assert plan.port == 3000
    assert plan.ok_to_run is True
    assert "open-webui" in plan.message
    assert "3000" in plan.message


def test_plan_by_port_unique_names_are_sorted() -> None:
    services = [
        _docker(80, "zeta"),
        _docker(80, "alpha"),
        _docker(80, "alpha", address="::"),
        _docker(80, "  ", container_id="blank"),  # blank name is not a target
    ]
    # Blank process_name is stored as given; the planner strips and drops it.
    services.append(
        ListeningService(
            "TCP",
            "0.0.0.0",
            80,
            None,
            "   ",
            source="docker",
            detail="->80/tcp",
        )
    )
    plan = plan_docker_stop(port=80, services=services, docker_available=True)
    assert plan.containers == ["alpha", "zeta"]
    assert plan.ok_to_run is True


def test_plan_by_name_does_not_require_inventory_row() -> None:
    plan = plan_docker_stop(
        name="  my-app  ",
        services=[_host(3000), _docker(3000, "someone-else")],
        docker_available=True,
    )
    assert plan.containers == ["my-app"]
    assert plan.port is None
    assert plan.ok_to_run is True
    assert plan.message == "stop container my-app"


def test_plan_by_name_wins_over_port() -> None:
    plan = plan_docker_stop(
        port=3000,
        name="explicit",
        services=[_docker(3000, "from-inventory")],
        docker_available=True,
    )
    assert plan.containers == ["explicit"]
    assert plan.port == 3000
    assert plan.ok_to_run is True


def test_plan_invalid_name_raises_and_does_not_use_port() -> None:
    with pytest.raises(ValueError):
        plan_docker_stop(
            port=3000,
            name="bad name",
            services=[_docker(3000, "from-inventory")],
            docker_available=True,
        )


def test_plan_missing_docker_cli() -> None:
    plan = plan_docker_stop(
        port=3000,
        services=[_docker(3000, "open-webui")],
        docker_available=False,
    )
    assert plan.containers == ["open-webui"]
    assert plan.ok_to_run is False
    assert plan.message.startswith("Docker is not reachable")


def test_plan_missing_docker_cli_by_name() -> None:
    plan = plan_docker_stop(name="open-webui", services=[], docker_available=False)
    assert plan.containers == ["open-webui"]
    assert plan.ok_to_run is False
    assert "Docker is not reachable" in plan.message


def test_plan_port_with_no_container_publisher() -> None:
    services = [
        _host(3000, name="node.exe"),
        _docker(3001, "other"),
    ]
    plan = plan_docker_stop(port=3000, services=services, docker_available=True)
    assert plan.containers == []
    assert plan.ok_to_run is False
    assert plan.port == 3000
    assert "no container publishes port 3000" in plan.message
    assert "host process" in plan.message


def test_plan_neither_port_nor_name() -> None:
    plan = plan_docker_stop(services=[_docker(3000, "web")], docker_available=True)
    assert plan.containers == []
    assert plan.ok_to_run is False
    assert "nothing to stop" in plan.message


@pytest.mark.parametrize("port", [0, -1, 65536, 70000])
def test_plan_rejects_port_out_of_range(port: int) -> None:
    with pytest.raises(ValueError):
        plan_docker_stop(port=port, services=[], docker_available=True)


def test_plan_rejects_bool_port() -> None:
    with pytest.raises(ValueError):
        plan_docker_stop(port=True, services=[], docker_available=True)  # type: ignore[arg-type]


def test_plan_accepts_edge_ports() -> None:
    low = plan_docker_stop(
        port=1,
        services=[_docker(1, "low")],
        docker_available=True,
    )
    high = plan_docker_stop(
        port=65535,
        services=[_docker(65535, "high")],
        docker_available=True,
    )
    assert low.ok_to_run is True and low.containers == ["low"]
    assert high.ok_to_run is True and high.containers == ["high"]


def test_stop_containers_success_uses_argv_and_timeout() -> None:
    calls: list[tuple[list[str], int]] = []

    def runner(argv: list[str], timeout: int) -> SimpleNamespace:
        calls.append((argv, timeout))
        return SimpleNamespace(returncode=0, stderr="")

    result = stop_containers(["  open-webui  "], timeout=15, runner=runner)

    assert calls == [(["docker", "stop", "open-webui"], 15)]
    assert result.containers == ["open-webui"]
    assert result.stopped == ["open-webui"]
    assert result.failed == []
    assert result.ok is True
    assert "open-webui" in result.message


def test_stop_containers_records_stderr_on_failure() -> None:
    def runner(argv: list[str], timeout: int) -> SimpleNamespace:
        return SimpleNamespace(returncode=1, stderr="No such container: missing\n")

    result = stop_containers(["missing"], runner=runner)

    assert result.ok is False
    assert result.stopped == []
    assert result.failed == [("missing", "No such container: missing")]
    assert "missing" in result.message


def test_stop_containers_empty_stderr_uses_fallback() -> None:
    def runner(argv: list[str], timeout: int) -> SimpleNamespace:
        return SimpleNamespace(returncode=2, stderr=b"   ")

    result = stop_containers(["web"], runner=runner)
    assert result.failed == [("web", "docker stop failed")]
    assert result.ok is False


def test_stop_containers_records_oserror_and_timeout() -> None:
    def runner(argv: list[str], timeout: int) -> SimpleNamespace:
        name = argv[-1]
        if name == "gone":
            raise OSError("docker executable not found")
        raise subprocess.TimeoutExpired(argv, timeout)

    result = stop_containers(["gone", "slow"], timeout=3, runner=runner)

    assert result.stopped == []
    assert result.ok is False
    assert result.failed[0][0] == "gone"
    assert "docker executable not found" in result.failed[0][1]
    assert result.failed[1][0] == "slow"
    assert result.failed[1][1]


def test_stop_containers_does_not_execute_invalid_names() -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str], timeout: int) -> SimpleNamespace:
        calls.append(list(argv))
        return SimpleNamespace(returncode=0, stderr="")

    result = stop_containers(
        ["ok-name", "not a name", "", "ok-name", "  ok-name  "],
        runner=runner,
    )

    # Invalid names never become argv. The valid name is stopped once.
    assert calls == [["docker", "stop", "ok-name"]]
    assert result.stopped == ["ok-name"]
    assert result.ok is False
    assert [name for name, _error in result.failed] == ["not a name", ""]
    assert all("invalid container name" in error for _name, error in result.failed)


def test_stop_containers_partial_success_is_not_ok() -> None:
    def runner(argv: list[str], timeout: int) -> SimpleNamespace:
        if argv[-1] == "good":
            return SimpleNamespace(returncode=0, stderr="")
        return SimpleNamespace(returncode=1, stderr="permission denied")

    result = stop_containers(["good", "bad"], runner=runner)
    assert result.stopped == ["good"]
    assert result.failed == [("bad", "permission denied")]
    assert result.ok is False
    assert "stopped" in result.message and "failed" in result.message


def test_stop_containers_empty_list() -> None:
    def runner(argv: list[str], timeout: int) -> SimpleNamespace:  # pragma: no cover - must not run
        raise AssertionError("runner should not be called")

    result = stop_containers([], runner=runner)
    assert result.containers == []
    assert result.stopped == []
    assert result.failed == []
    assert result.ok is False
    assert result.message == "nothing to stop"


def test_default_runner_is_argv_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch subprocess.run so the default path is proven without Docker."""
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = stop_containers(["web"])

    assert result.ok is True
    assert captured["argv"] == ["docker", "stop", "web"]
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert "shell" not in kwargs or kwargs["shell"] is False
    assert kwargs["timeout"] == 10
    assert kwargs["check"] is False
    create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", None)
    if create_no_window is not None:
        assert kwargs["creationflags"] == create_no_window
