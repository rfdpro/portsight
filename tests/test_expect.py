"""Expected-port parsing and classification. Inventories are hand-built.

No OS scan, no Docker CLI, no ``netsh``. Compose files and ``.portsight``
live under ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portsight.expect import (
    ExpectedPort,
    ExpectedStatus,
    classify_expected,
    discover_expected,
    load_compose_ports,
    load_portsight_file,
    parse_expect_spec,
)
from portsight.models import ListeningService, PortInventory, PortRange


def _service(
    port: int,
    process_name: str,
    *,
    pid: int | None = 4242,
    state: str = "LISTEN",
    source: str = "host",
    detail: str = "",
    protocol: str = "TCP",
    address: str = "127.0.0.1",
) -> ListeningService:
    """One inventory row. Fields ``classify_expected`` does not read stay default."""
    return ListeningService(
        protocol=protocol,
        address=address,
        port=port,
        pid=pid,
        process_name=process_name,
        source=source,
        detail=detail,
        state=state,
    )


def test_parse_expect_spec_separators_and_labels() -> None:
    """Commas, semicolons, and whitespace separate ports; a word starts a label."""
    assert parse_expect_spec("3000,5432,6379") == [
        ExpectedPort(3000, "", "flag"),
        ExpectedPort(5432, "", "flag"),
        ExpectedPort(6379, "", "flag"),
    ]
    assert parse_expect_spec("3000 5432") == [
        ExpectedPort(3000, "", "flag"),
        ExpectedPort(5432, "", "flag"),
    ]
    assert parse_expect_spec("3000 vite, 5432 postgres") == [
        ExpectedPort(3000, "vite", "flag"),
        ExpectedPort(5432, "postgres", "flag"),
    ]
    assert parse_expect_spec("3000 vite dev") == [
        ExpectedPort(3000, "vite dev", "flag"),
    ]
    # Once the label starts, the rest of the comma-item stays the label.
    assert parse_expect_spec("3000 vite 5432") == [
        ExpectedPort(3000, "vite 5432", "flag"),
    ]
    assert parse_expect_spec("3000 5432 vite") == [
        ExpectedPort(3000, "", "flag"),
        ExpectedPort(5432, "vite", "flag"),
    ]
    assert parse_expect_spec("  , ;  ") == []
    assert parse_expect_spec("") == []
    # The parser does not dedupe. discover_expected does.
    assert parse_expect_spec("3000 a, 3000 b") == [
        ExpectedPort(3000, "a", "flag"),
        ExpectedPort(3000, "b", "flag"),
    ]
    assert parse_expect_spec("80", origin="custom") == [
        ExpectedPort(80, "", "custom"),
    ]
    assert [port.port for port in parse_expect_spec("1,65535")] == [1, 65535]


def test_parse_expect_spec_expands_ranges() -> None:
    """An inclusive range becomes one row per port, label copied onto each."""
    assert parse_expect_spec("3000-3002 vite") == [
        ExpectedPort(3000, "vite", "flag"),
        ExpectedPort(3001, "vite", "flag"),
        ExpectedPort(3002, "vite", "flag"),
    ]
    assert parse_expect_spec("8080-8080") == [ExpectedPort(8080, "", "flag")]


def test_parse_expect_spec_rejects_bad_ports() -> None:
    """Out of range, inverted ranges, and non-ports are ValueError."""
    with pytest.raises(ValueError, match=r"outside 1..65535"):
        parse_expect_spec("0")
    with pytest.raises(ValueError, match=r"outside 1..65535"):
        parse_expect_spec("65536")
    with pytest.raises(ValueError, match=r"outside 1..65535"):
        parse_expect_spec("65535-65536")
    with pytest.raises(ValueError, match="inverted"):
        parse_expect_spec("3002-3000")
    with pytest.raises(ValueError, match="invalid"):
        parse_expect_spec("vite")
    with pytest.raises(ValueError, match="invalid"):
        parse_expect_spec("3000-")


def test_load_portsight_file_comments_and_ranges(tmp_path: Path) -> None:
    """``#`` comments and blank lines are ignored; ranges expand; origin is the filename."""
    path = tmp_path / ".portsight"
    path.write_text(
        """\
# dev servers

3000 vite
8080-8082 api  # preview
   # indented comment
5432
""",
        encoding="utf-8",
    )
    assert load_portsight_file(path) == [
        ExpectedPort(3000, "vite", ".portsight"),
        ExpectedPort(8080, "api", ".portsight"),
        ExpectedPort(8081, "api", ".portsight"),
        ExpectedPort(8082, "api", ".portsight"),
        ExpectedPort(5432, "", ".portsight"),
    ]


def test_load_compose_ports_extracts_host_ports(tmp_path: Path) -> None:
    """Host side of common publish forms, including IP:host:container and ranges.

    ``80/tcp`` is an expose. Out-of-range and inverted mappings are skipped.
    A sibling key after the list is not part of the publish section.
    """
    path = tmp_path / "docker-compose.yml"
    path.write_text(
        """\
services:
  app:
    ports:
      - "3000:80"

      - '5440:5440'
      # still inside the list
      - 5450:5450
      - "127.0.0.1:5432:5432"
      - "[::1]:8080:80"
      - 6000
      - "7000-7002:7000-7002"
      - "80/tcp"
      - "9100:9100/tcp"
      - "70000:80"
      - "3002-3000:80"
    environment:
      POSTGRES_PASSWORD: secret
      - "6666:6666"
""",
        encoding="utf-8",
    )
    assert load_compose_ports(path) == [
        ExpectedPort(3000, "80", "docker-compose.yml"),
        ExpectedPort(5440, "5440", "docker-compose.yml"),
        ExpectedPort(5450, "5450", "docker-compose.yml"),
        ExpectedPort(5432, "5432", "docker-compose.yml"),
        ExpectedPort(8080, "80", "docker-compose.yml"),
        ExpectedPort(6000, "", "docker-compose.yml"),
        ExpectedPort(7000, "7000", "docker-compose.yml"),
        ExpectedPort(7001, "7001", "docker-compose.yml"),
        ExpectedPort(7002, "7002", "docker-compose.yml"),
        ExpectedPort(9100, "9100", "docker-compose.yml"),
    ]


def test_load_compose_ports_does_not_swallow_next_service_key(tmp_path: Path) -> None:
    """A short ``ports:`` list stops at the next same-indent key and the next service.

    ``volumes:`` is a sibling of ``ports:``. Its ``9999:9999`` mapping must
    not be read as a publish. The following service's own ``ports:`` section
    still counts. Long syntax (``published:``) is not a host port.
    """
    path = tmp_path / "compose.yaml"
    path.write_text(
        """\
services:
  web:
    ports:
      - "127.0.0.1:5432:5432"
      - target: 80
        published: 4000
      - "5000:50"
    volumes:
      - "9999:9999"
  api:
    image: nginx
    ports:
      - "8080:80"
""",
        encoding="utf-8",
    )
    assert load_compose_ports(path) == [
        ExpectedPort(5432, "5432", "compose.yaml"),
        ExpectedPort(5000, "50", "compose.yaml"),
        ExpectedPort(8080, "80", "compose.yaml"),
    ]


def test_classify_expected_priority() -> None:
    """Host beats docker, docker beats held, held beats reserved, ESTABLISHED does not.

    Port 3000 is also published, in TIME_WAIT, and inside an exclusion — status
    is still host. Port 2222 is docker plus held plus reserved. Port 7070 is
    only a bind-blocking hold (lowercase state, to match the set
    case-insensitively) plus an exclusion. Port 9090 is ESTABLISHED inside an
    exclusion, so the exclusion wins. Port 8080 is ESTABLISHED alone, so it
    is free.
    """
    expected = [
        ExpectedPort(3000, "vite", "flag"),
        ExpectedPort(5432, "db", "flag"),
        ExpectedPort(2222, "", "flag"),
        ExpectedPort(7070, "", "flag"),
        ExpectedPort(9090, "", "flag"),
        ExpectedPort(6379, "", "flag"),
        ExpectedPort(8080, "", "flag"),
        ExpectedPort(53, "", "flag"),
        ExpectedPort(54, "", "flag"),
    ]
    inventory = PortInventory(
        listening=[
            _service(3000, "node.exe", pid=4242),
            _service(53, "dns.exe", pid=10, protocol="UDP", state="BOUND"),
            _service(54, "svchost.exe", pid=None),
        ],
        docker=[
            _service(3000, "web", source="docker", detail="->80/tcp", pid=None),
            _service(
                5432,
                "postgres",
                source="docker",
                detail="->5432/tcp",
                pid=None,
            ),
            _service(2222, "redis", source="docker", detail="->6379/tcp", pid=None),
        ],
        reserved=[
            PortRange(3000, 3010, kind="reserved", note="TCP exclusion"),
            PortRange(5432, 5432, kind="reserved", note="TCP exclusion"),
            PortRange(2222, 2222, kind="reserved"),
            PortRange(7070, 7070, kind="reserved", note="TCP exclusion"),
            PortRange(9090, 9099, kind="reserved"),
            PortRange(6379, 6379, kind="reserved", note="system exclusion"),
        ],
        held=[
            _service(3000, "old.exe", state="TIME_WAIT", pid=1),
            _service(2222, "old.exe", state="TIME_WAIT", pid=2),
            _service(7070, "python.exe", state="time_wait", pid=77),
            _service(9090, "chrome.exe", state="ESTABLISHED", pid=88),
            _service(8080, "curl.exe", state="ESTABLISHED", pid=99),
        ],
    )
    assert classify_expected(expected, inventory) == [
        ExpectedStatus(expected[0], "host", "node.exe (pid 4242)"),
        ExpectedStatus(expected[1], "docker", "postgres ->5432/tcp"),
        ExpectedStatus(expected[2], "docker", "redis ->6379/tcp"),
        ExpectedStatus(expected[3], "held", "TIME_WAIT python.exe"),
        ExpectedStatus(expected[4], "reserved", "exclusion 9090-9099"),
        ExpectedStatus(expected[5], "reserved", "exclusion 6379 (system exclusion)"),
        ExpectedStatus(expected[6], "free", ""),
        ExpectedStatus(expected[7], "host", "dns.exe (pid 10)"),
        ExpectedStatus(expected[8], "host", "svchost.exe"),
    ]


def test_discover_expected_dedupes_flag_then_files(tmp_path: Path) -> None:
    """Flag wins over ``.portsight``, which wins over the first Compose file.

    ``docker-compose.yml`` is preferred to later candidates, so ports that
    exist only in ``docker-compose.yaml`` / ``compose.yaml`` are not loaded.
    """
    (tmp_path / ".portsight").write_text(
        "3000 fromfile\n4000 onlyfile\n4000 second\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        """\
services:
  web:
    ports:
      - "3000:80"
      - "5000:80"
""",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yaml").write_text(
        """\
services:
  other:
    ports:
      - "8888:80"
""",
        encoding="utf-8",
    )
    (tmp_path / "compose.yaml").write_text(
        """\
services:
  other:
    ports:
      - "7777:80"
""",
        encoding="utf-8",
    )
    found = discover_expected(
        tmp_path,
        "3000 fromflag, 3000 later, 6000",
        use_project_files=True,
    )
    assert found == [
        ExpectedPort(3000, "fromflag", "flag"),
        ExpectedPort(6000, "", "flag"),
        ExpectedPort(4000, "onlyfile", ".portsight"),
        ExpectedPort(5000, "80", "docker-compose.yml"),
    ]


def test_discover_expected_skips_project_files_unless_asked(tmp_path: Path) -> None:
    """``use_project_files`` is the switch. A blank spec adds no flag rows."""
    (tmp_path / ".portsight").write_text("4000 file\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text(
        """\
services:
  web:
    ports:
      - "3000:80"
""",
        encoding="utf-8",
    )
    assert discover_expected(tmp_path, "3000 cli", use_project_files=False) == [
        ExpectedPort(3000, "cli", "flag"),
    ]
    assert discover_expected(tmp_path, None, use_project_files=True) == [
        ExpectedPort(4000, "file", ".portsight"),
        ExpectedPort(3000, "80", "docker-compose.yml"),
    ]
    assert discover_expected(tmp_path, "   ", use_project_files=False) == []
