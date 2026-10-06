# Security policy

## Supported versions

Security fixes go into the latest release only.

## Reporting a vulnerability

Please don't open a public issue. Report the problem privately through GitHub's [private vulnerability reporting](https://github.com/rfdpro/portsight/security/advisories/new).

Include the version, your OS, and the steps to reproduce. Expect an acknowledgement within a week.

## Scope

portsight runs with your privileges. It can terminate processes (`--kill`) and stop containers (`--stop`). Issues of interest include:

- a kill or stop that targets a process or container the user wasn't shown
- an injection through container names, project files, or snapshot files
- a crash or hang triggered by crafted `netsh`, `docker`, or Compose output
