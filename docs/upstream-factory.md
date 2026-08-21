# Upstream factory

et.rs is a **Rust rewrite** of [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal).
It is **not** a git fork. Never add a C++ merge remote, subtree, or vendor
checkout that lands upstream trees into this repo.

Machine pin (last *reviewed* refs, not “already ported”):
[`.github/upstream-pin.yml`](../.github/upstream-pin.yml).
Human record and FACTORY BACKLOG: [`docs/upstream-pin.md`](upstream-pin.md).

## Shape

1. **Watch** — weekday 09:30 KST (`30 0 * * 1-5` UTC) via
   [`.github/workflows/upstream-watch.yml`](../.github/workflows/upstream-watch.yml).
   The job asks GitHub REST (`gh api`) for ET’s latest release tag/SHA and
   default-branch tip. If either moved past the pin, it writes a workflow
   summary and exits nonzero. It does not open issues.
2. **Review** — read the ET delta (protocol / wire / auth / security first).
   Update the pin only after that review. Updating the pin is not a port.
3. **Port** (later PRs) — reimplement in Rust. Gate is
   `cargo test --workspace`, especially `fixtures/wire.json`. There is no GUI
   gate. Do not bump `PROTOCOL_VERSION` unless the port is the coordinated
   wire change.

## Conflict policy

| Area | Winner |
| --- | --- |
| Protocol, wire bytes, auth, security | **Upstream** |
| Language / memory safety (`#![forbid(unsafe_code)]`) | **et.rs** |
| Native Windows server (ConPTY, no WSL) | **et.rs** |
| Telemetry | **et.rs** (`--telemetry` accepted, ignored) |
| Busybox role dispatch (`argv[0]` → `et` / `etserver` / `etterminal` / `htm` / `htmd`) | **et.rs** |
| Drop-in names (`et`, `etserver`) | **et.rs** |

When a port would break an et.rs-kept row, keep the et.rs behavior and adapt
the upstream idea around it (for example: same handshake bytes, ConPTY instead
of a POSIX pty on Windows).
