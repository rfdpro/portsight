# Contributing to portsight

Thanks for helping out. Bug reports, platform quirks (especially non-English Windows and unusual Docker setups), and pull requests are all welcome.

## Reporting bugs

Open an issue with:

- `portsight --version`, your OS, and your Python version
- the command you ran, and what you expected to see
- the relevant output. `--json` is usually the most useful. Redact host names, paths, and command lines you'd rather not share.

For anything security-sensitive, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development setup

```sh
git clone https://github.com/rfdpro/portsight
cd portsight
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install   # optional: runs ruff on commit
```

## Checks

CI runs these on Windows, Linux, and macOS:

```sh
ruff check .
ruff format --check .
pytest
```

Tests must not depend on the machine they run on. Build a `PortInventory` by hand, or patch the collectors (`portsight.cli.build_inventory`, `portsight.kill.collect_socket_scan`, `portsight.docker_ports._run_docker_ps`). Don't call the real `netsh`, `docker`, or `psutil.net_connections`. See `tests/test_cli.py` for the pattern.

## Pull requests

- Keep each PR focused on one change, and add a test that fails without it.
- Add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for any user-visible change.
- If you change `--help` text or flags, update the README too.
- If you change the report layout, regenerate the screenshots with `python scripts/render_screenshots.py`.
- Changes to the JSON schema must follow the compatibility rules in [docs/json.md](docs/json.md).

## Releasing (maintainers)

1. Bump `__version__` in `src/portsight/__init__.py`.
2. Move the `Unreleased` changelog entries under the new version heading, with today's date.
3. Commit, tag `vX.Y.Z`, and push the tag. The release workflow builds, publishes to PyPI through trusted publishing, and creates a GitHub release.
