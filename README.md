# et.rs

A Rust port of [Eternal Terminal](https://github.com/MisterTea/EternalTerminal) — a remote shell that
automatically reconnects without interrupting the session.

Wire-compatible with upstream protocol version 6: an et.rs client can talk to a C++ `etserver`, and a
C++ `et` client can talk to an et.rs server, in both terminal and port-forwarding modes.

## Build

```sh
cargo build --release
```

## Roles

One binary provides every upstream role, selected by `argv[0]` (busybox-style symlinks) or by a
leading subcommand:

| Upstream binary | et.rs invocation                     |
| --------------- | ------------------------------------ |
| `et`            | `et <host>` / `et client <host>`     |
| `etserver`      | `etserver` / `et server`             |
| `etterminal`    | `etterminal` / `et terminal`         |
| `htm`           | `htm` / `et htm`                     |
| `htmd`          | `htmd` / `et htmd`                   |

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
- `etserver` INI configuration (`/etc/et/config`), daemon mode with pid file, log files honouring
  `--logdir`, `--logtostdout`, `--silent`, `--verbose`, and log rollover.
- Headless terminal multiplexer (`htm`/`htmd`) with upstream's base64 IPC framing, JSON state,
  tabs/splits/panes, and pane buffer replay.
- No telemetry: `--telemetry` is accepted for compatibility and ignored.
- `#![forbid(unsafe_code)]` across every crate.

## Tests

```sh
cargo test --workspace
```

## License

Apache-2.0
