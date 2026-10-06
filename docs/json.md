# JSON output

Every mode accepts `--json`. Output is UTF-8 and pretty-printed, except `--watch --json`, which prints one compact document per line ([JSON Lines](https://jsonlines.org/)).

Look up keys by name. Key order is not part of the contract.

## Inventory document (`--json`, `--snapshot`, `--watch --json`)

`--snapshot FILE` writes the same document. Snapshots always hold the full, unfiltered scan. With plain `--json`, the `--exposed` and `--process` filters apply to the three service lists.

```json
{
  "schema_version": 1,
  "scan_incomplete": false,
  "scan_note": "",
  "docker_available": true,
  "listening": [ /* service */ ],
  "docker":    [ /* service */ ],
  "held":      [ /* service */ ],
  "reserved":  [ /* range */ ],
  "dynamic":   [ /* range */ ],
  "free":      [ /* range */ ],
  "expected":  [ /* expected, only with --expect / --project */ ]
}
```

| Key | Type | Meaning |
|-----|------|---------|
| `schema_version` | int | Always `1` for this format. Readers reject other values. |
| `scan_incomplete` | bool | `true` when the OS refused the socket table. Empty lists then mean "could not see", not "nothing there". |
| `scan_note` | string | Human explanation when `scan_incomplete` is set. |
| `docker_available` | bool | `true` when `docker ps` answered this run. |
| `listening` | service[] | Host TCP `LISTEN` and bound UDP sockets. |
| `docker` | service[] | Published container ports (`source` is `"docker"`, `pid` is `null`). |
| `held` | service[] | Non-listening TCP sockets on a local port (`TIME_WAIT`, `ESTABLISHED`, ...). |
| `reserved` | range[] | Windows excluded port ranges. Always empty on other OSes. |
| `dynamic` | range[] | The OS ephemeral port pool (zero or one entry). |
| `free` | range[] | Contiguous free spans, honoring `--min-size`. |

### Service object

| Key | Type | Notes |
|-----|------|-------|
| `protocol` | string | `"TCP"` or `"UDP"` |
| `address` | string | Bound address, such as `"0.0.0.0"`, `"::"`, `"127.0.0.1"` |
| `port` | int | Local port |
| `pid` | int \| null | `null` when the OS withheld it, and for Docker rows |
| `process_name` | string | Executable name, or the container name for Docker rows |
| `process_path` | string | Executable path, or the container ID for Docker rows |
| `source` | string | `"host"` or `"docker"` |
| `detail` | string | Docker mapping such as `"->8080/tcp"`; empty for host rows |
| `cmdline` | string | Full command line when readable |
| `parent_pid` | int \| null | |
| `parent_name` | string | |
| `state` | string | `"LISTEN"`, `"BOUND"` (UDP), or a TCP state such as `"TIME_WAIT"` |

### Range object

| Key | Type | Notes |
|-----|------|-------|
| `start`, `end` | int | Inclusive bounds |
| `kind` | string | `"reserved"`, `"dynamic"`, or `"free"` |
| `administered` | bool | Windows marks admin-added exclusions with `*` in `netsh` |
| `note` | string | Such as `"TCP system exclusion"` |

### Expected object

| Key | Type | Notes |
|-----|------|-------|
| `port` | int | |
| `label` | string | From the spec, or the container port for Compose rows |
| `origin` | string | `"flag"`, `".portsight"`, or the Compose file name |
| `status` | string | `"free"`, `"host"`, `"docker"`, `"held"`, or `"reserved"` |
| `detail` | string | What holds the port; empty when free |

## Single-answer modes

| Mode | Shape |
|------|-------|
| `--port P --json` | `{"port", "free", "reasons": [string], "exclusion_advice": string\|null, "listeners": [service], "docker": [service], "held": [service]}` |
| `--check P --json` | `{"port", "free", "reasons": [string]}` |
| `-r --json` | `{"port": int}` |
| `--take N --json` | `{"ports": [int], "contiguous": bool}` |
| `--diff F --json` | `{"changed": bool, "lines": [string]}` |

Exit codes match the non-JSON modes (see the [README](../README.md#exit-codes)).

## Compatibility

New optional keys may appear in schema version 1. Readers should ignore keys they don't know. Renaming or removing a key, or changing its meaning, bumps `schema_version`.
