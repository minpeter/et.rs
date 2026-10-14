---
packages:
  et:
    type: patch
---

## Reap disconnected forward-only sessions

A `--no-terminal` session that only serves port forwards, and a shell-less
`-N` or `-W` session, now advertises a 5-minute
`disconnect_timeout_seconds` when `--disconnect-timeout` is omitted. etserver
closes the detached terminal after that long with no client attached, instead
of leaving it reparented forever while the server default stays 0.

Interactive sessions, and `--no-terminal` with no forwards, still leave the
field unset so reconnect stays unlimited unless a timeout is configured.
`--disconnect-timeout 0` keeps a forward-only session too. Upstream
EternalTerminal applies one server default to every session and does not
special-case forward-only clients. Protocol v6 is unchanged.
