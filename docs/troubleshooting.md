# Troubleshooting

## "Address already in use", but nothing is listening (Windows)

Run `portsight --port <PORT>`. There are two common causes.

**1. The port is inside a Windows excluded range.** Hyper-V, WSL2, Docker Desktop, and the Windows NAT driver (WinNAT) reserve blocks of ports. A bind into one of those blocks fails even though no process owns the port. The report lists the ranges under *Reserved / excluded*. You can also check directly:

```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

To release dynamic exclusions, restart WinNAT from an elevated shell:

```powershell
net stop winnat
net start winnat
```

This drops existing WSL2 and Docker port forwards until those services republish them. To stop Windows from claiming a port you need, reserve it yourself while it's free:

```powershell
netsh int ipv4 add excludedportrange protocol=tcp startport=3000 numberofports=1
```

Administered exclusions like this show up with `*` in portsight.

**2. A socket is still in `TIME_WAIT` or `CLOSE_WAIT`.** A server that just exited can leave these behind. `--port` lists them under `held`. They clear on their own, usually within a minute or two. Servers that set `SO_REUSEADDR` can rebind immediately.

## A Docker container's port doesn't show in `netstat`

That's expected with Docker Desktop. Its WSL2 or VM backend forwards published ports without a normal host `LISTEN` socket. portsight reads `docker ps` instead, so make sure:

- the `docker` CLI is on `PATH`
- the daemon is running (`docker ps` works in the same shell)

The report says `Docker: not scanned` when either check fails. Docker rows have no PID, so `--kill` can't free them. Use `--stop PORT` instead.

## "Scan incomplete (access denied)"

The OS refused to list sockets. When that happens, portsight still shows what it could gather. It won't say "nothing is listening", and `--kill` won't claim a port is free.

- **Windows:** run from an elevated terminal to see sockets owned by system services.
- **macOS:** listing other processes' sockets requires `sudo portsight`.
- **Linux:** sockets owned by other users appear without a PID or process name unless you use `sudo`.

## `--kill` says access denied

The process belongs to another user, or to SYSTEM on Windows. Re-run from an elevated shell, or with `sudo` on Linux and macOS. portsight never kills PID 0, PID 1, the Windows System process (PID 4), or itself.

## `--kill` or `--stop` does nothing in a script

Without a terminal there's no one to answer the confirmation prompt, so portsight declines and exits with code 130. Pass `-y` to confirm non-interactively.

## Colors or box characters look wrong

- Color turns off automatically when output is piped. Force it with `FORCE_COLOR=1`, or turn it off with `--no-color` or `NO_COLOR=1`.
- On old Windows consoles, use Windows Terminal or set a UTF-8 code page (`chcp 65001`) for box-drawing characters.

## The ephemeral pool says "unavailable"

portsight reads the pool from `netsh` on Windows, `/proc/sys/net/ipv4/ip_local_port_range` on Linux, and `sysctl net.inet.ip.portrange.*` on macOS and BSD. Sandboxed environments sometimes block all three. The rest of the report is unaffected.
