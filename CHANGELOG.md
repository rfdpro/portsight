# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.0] - 2026-10-06

First public release. Earlier versions were a private tool named `openports`.

### Changed

- **Renamed to `portsight`.** The package, import, and command all changed, because `openports` is taken on PyPI. Project files are now `.portsight`; `.openports` is still read as a fallback.
- `--help` is grouped by task and includes examples, exit codes, and environment variables.
- Color now follows the terminal: piped output no longer contains ANSI escapes. `NO_COLOR` and `FORCE_COLOR` are honored.
- `--diff` and `--watch` ignore outbound-traffic churn: client sockets, and UDP binds inside the ephemeral pool. `--diff` no longer reports a change on every run of a busy machine.
- `--watch` prints the report once, then only timestamped changes. `--watch --json` emits JSON Lines.
- Errors go to stderr with a non-zero exit code instead of mixing into stdout.
- Out-of-range ports and counts are rejected while parsing arguments, and the error names the bad value.

### Added

- Linux and macOS support for the ephemeral pool (`/proc`, `sysctl`), plus platform-neutral wording throughout the report.
- `python -m portsight`.
- Localized Windows support for parsing `netsh` dynamic port ranges.
- Documentation: JSON schema, project files, troubleshooting, and internals.

### Fixed

- `--kill` could terminate a process that bound the port *after* the confirmation preview. It now kills only the processes it previewed.
- `--kill` reported "already free" when the socket table was unreadable.
- `--kill` and `--stop` crashed on EOF without a terminal. They now decline and ask for `-y`.
- `--random` crashed when no port in the window was free.
- `--snapshot F --diff F` compared the new scan against itself. The baseline is now read before the snapshot is written.
- A stopped Docker daemon was reported as "CLI reachable, no published ports".
- `portsight --json | head` raised `BrokenPipeError`.
- `netsh` calls had no timeout.
- IPv6 endpoints printed as `:::135` instead of `[::]:135`.
- Long `--port` lines were cut off instead of wrapped.

## [1.1.0] - 2026-07-10

Private release as `openports`: `--port`, `--check`, `--take`, `--expect`, `--project`, `--snapshot`, `--diff`, `--watch`, `--stop`, and the `--exposed` / `--process` filters.

## [1.0.0]

Private release as `openports`: the full report, `-r`, and `--kill`.

[Unreleased]: https://github.com/rfdpro/portsight/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/rfdpro/portsight/releases/tag/v2.0.0
