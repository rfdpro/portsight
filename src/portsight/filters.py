"""Pure filters for listener rows.

Kept separate from the Rich report so ``--exposed`` and ``--process`` can
be unit-tested without rendering, and so JSON output can apply the same
rules as the tables.
"""

from __future__ import annotations

from portsight.models import ListeningService

# Addresses that are not reachable from another machine. IPv6 loopback is
# matched both in compressed form and in the fully expanded form some
# stacks print.
_LOOPBACK = frozenset(
    {
        "127.0.0.1",
        "::1",
        "localhost",
        "0:0:0:0:0:0:0:1",
    }
)


def is_exposed_address(address: str) -> bool:
    """True when a bind is reachable beyond this machine.

    Loopback is private. Wildcards (``0.0.0.0``, ``::``) and any concrete
    interface address are exposed: they accept traffic that is not from
    the host itself.
    """
    normalized = address.strip().lower()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    return normalized not in _LOOPBACK


def service_matches_process(service: ListeningService, needle: str) -> bool:
    """Case-insensitive substring match against name, path, command, parent.

    ``node`` should hit ``node.exe``, a path ending in ``node``, and a
    command line that launches ``node``, because Windows process names
    alone are ambiguous.
    """
    query = needle.strip().lower()
    if not query:
        return True
    haystack = " ".join(
        (
            service.process_name,
            service.process_path,
            service.cmdline,
            service.parent_name,
            service.detail,
        )
    ).lower()
    return query in haystack


def filter_services(
    services: list[ListeningService],
    *,
    process: str | None = None,
    exposed_only: bool = False,
) -> list[ListeningService]:
    """Apply optional process and exposure filters, preserving order."""
    selected: list[ListeningService] = []
    for service in services:
        if exposed_only and not is_exposed_address(service.address):
            continue
        if process and not service_matches_process(service, process):
            continue
        selected.append(service)
    return selected
