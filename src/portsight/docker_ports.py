"""Discover Docker published host ports via the Docker CLI.

Why this exists
---------------
Docker Desktop on Windows with the WSL2 engine often forwards published ports
*without* creating a normal Windows LISTENING socket. ``netstat`` /
``psutil.net_connections`` therefore miss containers like ``0.0.0.0:3000->...``
even though ``http://127.0.0.1:3000`` works. Querying ``docker ps`` is the
reliable way to surface those bindings and treat them as occupied.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from portsight.models import ListeningService

# Published mapping examples from ``docker ps``:
#   0.0.0.0:3001->3000/tcp
#   [::]:3001->3000/tcp
#   0.0.0.0:9000-9001->9000-9001/tcp
#   127.0.0.1:8080->80/tcp
# Exposed-but-not-published (no host bind) looks like ``5302/tcp`` and is ignored.
_PUBLISHED = re.compile(
    r"(?P<addr>\[[^\]]+\]|[^:\s]+):"
    r"(?P<host_start>\d+)(?:-(?P<host_end>\d+))?"
    r"->"
    r"(?P<cont_start>\d+)(?:-(?P<cont_end>\d+))?"
    r"/(?P<proto>\w+)"
)


def docker_available() -> bool:
    """True when a ``docker`` executable is on PATH."""
    return shutil.which("docker") is not None


def _run_docker_ps() -> str | None:
    """Return ``docker ps`` port listing text, or ``None`` on any failure.

    ``None`` (not ``""``) lets callers tell "no containers publish
    anything" apart from "the CLI is installed but the daemon is down".
    """
    if not docker_available():
        return None
    try:
        completed = subprocess.run(
            [
                "docker",
                "ps",
                "--format",
                "{{.Names}}|{{.Ports}}|{{.ID}}",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if completed.returncode != 0:
        return None
    return completed.stdout or ""


def parse_published_ports(
    docker_ps_output: str,
) -> list[ListeningService]:
    """Parse ``name|ports|id`` lines into host-side ``ListeningService`` rows.

    Dual-stack publishes (``0.0.0.0`` + ``::``) become separate rows so the
    report matches how Docker lists them. Port ranges expand to one row per
    host port with a shared container note.
    """
    services: list[ListeningService] = []
    seen: set[tuple[str, str, int, str]] = set()

    for raw_line in docker_ps_output.splitlines():
        line = raw_line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 2)
        if len(parts) < 2:
            continue
        name = parts[0].strip() or "container"
        ports_field = parts[1].strip()
        container_id = parts[2].strip() if len(parts) > 2 else ""

        for match in _PUBLISHED.finditer(ports_field):
            address = match.group("addr")
            # Normalize IPv6 bracket form from Docker's ``[::]`` display.
            if address.startswith("[") and address.endswith("]"):
                address = address[1:-1]

            host_start = int(match.group("host_start"))
            host_end = int(match.group("host_end") or host_start)
            cont_start = int(match.group("cont_start"))
            cont_end = int(match.group("cont_end") or cont_start)
            proto = match.group("proto").upper()

            if host_start > host_end or host_start < 1 or host_end > 65535:
                continue

            span = host_end - host_start
            for offset in range(span + 1):
                host_port = host_start + offset
                # Map host offset onto container range when widths match;
                # otherwise keep the container start (Docker range publishes
                # are almost always equal-width).
                if cont_end - cont_start == span:
                    cont_port = cont_start + offset
                else:
                    cont_port = cont_start

                key = (proto, address, host_port, name)
                if key in seen:
                    continue
                seen.add(key)

                detail = f"->{cont_port}/{proto.lower()}"
                services.append(
                    ListeningService(
                        protocol=proto,
                        address=address,
                        port=host_port,
                        pid=None,
                        process_name=name,
                        process_path=container_id,
                        source="docker",
                        detail=detail,
                    )
                )

    services.sort(key=lambda s: (s.port, s.protocol, s.address, s.process_name))
    return services


def scan_docker_published_ports() -> list[ListeningService] | None:
    """Live Docker published host ports, or ``None`` if Docker is unreachable."""
    output = _run_docker_ps()
    if output is None:
        return None
    return parse_published_ports(output)


def collect_docker_published_ports() -> list[ListeningService]:
    """Live Docker published host ports, or ``[]`` if Docker is unreachable."""
    return scan_docker_published_ports() or []
