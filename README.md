# et.rs

A Rust port of [Eternal Terminal](https://github.com/MisterTea/EternalTerminal) — a remote shell that
automatically reconnects without interrupting the session.

Wire-compatible with upstream protocol version 6: an et.rs client can talk to a C++ `etserver`, and a
C++ `et` client can talk to an et.rs server, in both terminal and port-forwarding modes.

Windows is a first-class target. Upstream builds only its client there, so hosting a session on
Windows meant running the POSIX server inside WSL and landing in a WSL shell. et.rs runs the server
and the per-session terminal natively on Windows using ConPTY, so `et` gives you a real `cmd.exe` or
PowerShell — no WSL involved.

## Build

```sh
cargo build --release                                  # host
cargo build --release --target x86_64-pc-windows-gnu -p et   # et.exe
```

## Roles

One binary provides every role, selected by `argv[0]` (busybox-style symlinks) or by a leading
subcommand:

| Upstream binary | et.rs invocation                 | Windows |
| --------------- | -------------------------------- | ------- |
| `et`            | `et <host>` / `et client <host>` | yes     |
| `etserver`      | `etserver` / `et server`         | yes     |
| `etterminal`    | `etterminal` / `et terminal`     | yes     |
| `htm`           | `htm` / `et htm`                 | no      |
| `htmd`          | `htmd` / `et htmd`               | no      |

```sh
ln -s et etserver && ln -s et etterminal && ln -s et htm && ln -s et htmd
```

## Usage

```sh
et user@host
et -c 'uptime' user@host:2022
et -t 8080:80 -r 9000:9000 user@host          # forward and reverse tunnels
et -f user@host                                # forward the ssh-agent socket
et --jumphost jump.example --jport 2022 \
   --jserverfifo /tmp/etserver.fifo1 dst:2022  # ET-native jumphost relay
etserver --daemon --pidfile /var/run/etserver.pid
htm                                            # headless terminal multiplexer
```

### Connecting to a Windows host

```powershell
# on the Windows machine (needs Windows 10 1809+ for ConPTY)
et.exe server --daemon --port 2022 --pidfile "%LOCALAPPDATA%\etserver\etserver.pid"
netsh advfirewall firewall add rule name="et" dir=in action=allow protocol=TCP localport=2022
```

```sh
# from anywhere
et --winserver user@windows-host:2022                   # cmd.exe session
et --remote-shell powershell user@windows-host:2022     # PowerShell session
```

`--winserver` selects a `cmd.exe`-compatible ssh bootstrap (no `printf`, CRLF lines, `&` separator)
and defaults `--terminal-path` to `et.exe`. The session shell follows `%COMSPEC%`, or `ET_SHELL` if
set on the server. OpenSSH on Windows must be reachable and its default shell should be `cmd.exe`.

## Feature set

- Protocol v6 handshake, `crypto_secretbox` (XSalsa20-Poly1305) framing, sequence numbers, and
  catch-up buffers, pinned to upstream bytes by golden fixtures in `fixtures/wire.json`.
- Reconnecting client and server sessions with backed reader/writer replay.
- SSH bootstrap (`IDPASSKEY` handshake), remote PTY, window resize, keepalives, `--command`
  execution, and `--no-terminal` mode.
- Forward, reverse, Unix-socket, port-range, environment-variable named-pipe, and ssh-style
  (`bind_address:port:host:hostport`, bracketed IPv6) tunnels.
- SSH-agent forwarding via a server-created socket exported as `SSH_AUTH_SOCK`.
- ET-native jumphost relay (client, `etserver` `JUMPHOST_INIT` dispatch, and `etterminal --jump`).
- `etserver` INI configuration, daemon mode with pid file, log files honouring `--logdir`,
  `--logtostdout`, `--silent`, `--verbose`, and log rollover.
- Headless terminal multiplexer (`htm`/`htmd`) with upstream's base64 IPC framing, JSON state,
  tabs/splits/panes, and pane buffer replay.
- Native Windows server and terminal: ConPTY shells, a loopback router authenticated with a
  per-server token, job-object breakaway so sessions survive the bootstrap ssh, and a console client
  that maps keys (including navigation keys upstream drops) to ANSI sequences.
- No telemetry: `--telemetry` is accepted for compatibility and ignored.
- `#![forbid(unsafe_code)]` across every crate.

### Windows notes

- The router is a loopback TCP listener; its address and a CSPRNG token live in the `--serverfifo`
  endpoint file under `%LOCALAPPDATA%\etserver`, which takes the place of Unix socket permissions.
- Unix-socket tunnels and the `htm` multiplexer stay POSIX-only, like upstream.
- Inbound connections need a firewall rule; the server does not modify firewall state itself.

## Tests

```sh
cargo test --workspace
```

## License

Apache-2.0
