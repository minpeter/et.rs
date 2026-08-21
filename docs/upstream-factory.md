# Upstream factory

et.rs is a **Rust rewrite** of [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal).
It is **not** a git fork and **not** an OpenUsage-style git-merge factory.
Never add a C++ merge remote, subtree, or vendor checkout of
MisterTea/EternalTerminal.

This is a hybrid of three real rewrite factories — not a fourth invention:

| Pattern | What we take |
| --- | --- |
| **uutils/coreutils** | Pin the original and run its suite as the oracle. Here that is [`fixtures/wire.json`](../fixtures/wire.json) plus `cargo test --workspace`. |
| **rustls BoGo** | Fixtures and interop are the contract. We never merge the other language tree. |
| **Linux-stable** | Every upstream default-branch commit after a baseline is **classified** (`skip` / `backlog` / `porting` / `ported`). Unclassified = drift. |

## Machine files

| File | Role |
| --- | --- |
| [`.github/upstream-pin.yml`](../.github/upstream-pin.yml) | Last reviewed release tag/SHA, default-branch **name**, protocol versions, last classified tip. **Pin ≠ ported.** |
| [`.github/upstream-ledger.yml`](../.github/upstream-ledger.yml) | Every ET `master` commit after baseline `et-v7.0.0` / `7656a32a5bc15c6746726a27a5a4ba1e468fab6e`. |
| [`docs/upstream-pin.md`](upstream-pin.md) | Human record of the pin and the current ledger. `#784` / `69b3353` is `ported` (et.rs [#31](https://github.com/minpeter/et.rs/pull/31) / `906a7ca`). `#788` / `b74a12e` stays `skip`. |

## Shape

1. **Watch** — weekday 09:30 KST (`30 0 * * 1-5` UTC) via
   [`.github/workflows/upstream-watch.yml`](../.github/workflows/upstream-watch.yml)
   and [`scripts/check-upstream-ledger.py`](../scripts/check-upstream-ledger.py)
   (`gh` + `python3` stdlib). The job:
   1. Compares ET’s latest release tag/SHA and default-branch **name** to the pin.
   2. Calls `gh api repos/MisterTea/EternalTerminal/compare/{baseline}...{master}`
      (paginated). Every commit SHA in that compare **must** appear in the
      ledger. Missing SHA = fail; the SHAs are listed in the step summary.
   3. Classified-but-unported (`status: backlog` and kind `security` /
      `protocol`) is visibility only — listed in the summary, does **not**
      fail CI.
   4. On unclassified drift, opens or updates a single issue titled
      `upstream: unclassified ET master commits` (reuse if open). Needs
      `issues: write`. Actions never auto-push ledger edits; a factory agent
      classifies in a PR.
2. **Classify** — for each new `master` commit, add a ledger row in a PR.
   Bumping the pin tip to the last classified SHA is bookkeeping, not a port.
3. **Port** (later PRs) — reimplement in Rust. Gate is
   `cargo test --workspace`, especially `fixtures/wire.json`. There is no GUI
   gate. Do not bump `PROTOCOL_VERSION` unless the port is the coordinated
   wire change.

## Ledger schema

Each commit after baseline (boring YAML, parsed without PyYAML):

| Field | Values |
| --- | --- |
| `sha` | full 40-char hex |
| `date` | `YYYY-MM-DD` |
| `kind` | `security` \| `protocol` \| `product` \| `ci` \| `docs` \| `other` |
| `status` | `skip` \| `backlog` \| `porting` \| `ported` |
| `note` | short reason |
| `et_pr` | optional upstream PR number |

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
