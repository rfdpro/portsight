# Expected ports and project files

`--expect` and `--project` check a planned set of ports against the current scan. Each port gets exactly one status:

| Status | Meaning |
|--------|---------|
| `host` | A host process is listening on it. |
| `docker` | A container publishes it. |
| `held` | A socket in `TIME_WAIT`, `CLOSE_WAIT`, or a similar state blocks binding it. |
| `reserved` | A Windows excluded port range covers it. |
| `free` | None of the above. |

If several reasons apply, the first one in that order wins. A listener is what you would kill or move, so it beats an exclusion.

The expected table goes on top of the normal report. It also works with `--json` (as the `expected` key) and with `--watch`.

## `--expect SPEC`

```sh
portsight --expect 3000
portsight --expect "3000,5432"
portsight --expect "8080-8082"
portsight --expect "3000 web, 5432 db, 8080-8082 api"
```

- Separate items with commas or semicolons.
- Within an item, whitespace separates ports: `3000 5432` is two ports.
- The first word that isn't a port or range starts the label. The label runs to the end of the item, so `3000 vite dev` is port 3000 labeled `vite dev`.
- Ranges are inclusive and expand to one row per port. Every port in the range gets the same label.
- Ports must be 1–65535. A bad token is an error (exit code 2).

## `.portsight`

Put this file in the project root and run `portsight --project` from that directory. Each line uses the `--expect` grammar, and `#` starts a comment.

```text
# .portsight
3000 web          # Vite dev server
5432 db
8080-8082 api
9229              # Node inspector
```

portsight also reads `.openports`, the file name used before the project was renamed. When both exist, only `.portsight` is read.

## Compose files

`--project` also reads the first of these that exists: `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`. It collects the host side of each short-syntax `ports:` entry:

```yaml
services:
  web:
    ports:
      - "3000:80"            # 3000, labeled 80
      - "127.0.0.1:5432:5432"
      - "[::1]:8080:80"
      - "9000-9001:9000-9001/tcp"
```

The file is scanned as text rather than fully parsed, which keeps the tool dependency-free. The parser skips:

- long syntax (`published:` / `target:`)
- flow lists on the key line (`ports: ["3000:80"]`)
- `${VAR}` interpolation, anchors, `extends`, and `include`

A line it doesn't understand is skipped rather than treated as an error. If your Compose file relies on any of these, list the ports in `.portsight` instead.

## Precedence

Rows are collected in this order: `--expect`, then `.portsight`, then the Compose file. If the same port appears more than once, the first row wins and later labels are dropped.
