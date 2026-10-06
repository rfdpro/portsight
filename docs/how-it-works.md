# How portsight works

Each run takes one snapshot of the machine and answers every question from it. That way the report, `--check`, and `--json` never disagree about the same moment.

## Data sources

| Data | Source | Module |
|------|--------|--------|
| Sockets (listeners and held) | `psutil.net_connections()` | `scanner.py` |
| Process name, path, command line, parent | `psutil.Process` | `scanner.py` |
| Docker publishes | `docker ps --format '{{.Names}}\|{{.Ports}}\|{{.ID}}'` | `docker_ports.py` |
| Windows excluded ranges | `netsh interface ipv4 show excludedportrange` (TCP and UDP) | `windows.py` |
| Ephemeral pool | `netsh` / `/proc` / `sysctl` | `system_ranges.py` |

Every collector fails soft. A missing `netsh`, a stopped Docker daemon, or a hung command (each has a timeout) produces an empty section, never a crash.

## Free-range math

`ranges.py` builds a 65,536-entry occupancy mask from three sources: listener ports, Docker host ports, and reserved ranges. It then walks the mask once to emit contiguous free spans. The report shows those spans bucketed into the IANA bands: well-known 1–1023, registered 1024–49151, and dynamic 49152–65535.

Held sockets (`TIME_WAIT`, `ESTABLISHED`, and others) are deliberately left out of the mask. Every outbound connection creates one on an ephemeral port, and counting them would shred the dynamic band. Single-port questions (`--check`, `--port`, `--expect`) do consult the bind-blocking states, because those can make `bind()` fail.

## Module map

```
cli.py            argument parsing, mode dispatch, exit codes
inventory.py      builds one PortInventory from all collectors
scanner.py        psutil socket scan and process attribution
docker_ports.py   docker ps parsing
windows.py        netsh parsing and WinNAT advice
system_ranges.py  per-OS reserved and ephemeral discovery
ranges.py         free-range math, --random, --take
lookup.py         single-port classification (--port, --check)
expect.py         --expect / .portsight / compose parsing and classification
filters.py        --exposed and --process
snapshot.py       JSON schema, --snapshot, --diff
kill.py           --kill
docker_stop.py    --stop / --stop-container
report.py         Rich rendering
```

Everything below `inventory.py` takes plain data in and returns plain data out. The tests build `PortInventory` objects by hand and never touch the real OS, Docker, or `netsh`.
