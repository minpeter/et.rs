# Upstream pin

**This pin is the last *reviewed* EternalTerminal snapshot. It does not mean
et.rs has ported that snapshot.** Pin ≠ ported.

Canonical machine files:

- Pin (release tag/SHA, default-branch name, protocol versions, last classified tip):
  [`.github/upstream-pin.yml`](../.github/upstream-pin.yml)
- Ledger (every `master` commit after baseline):
  [`.github/upstream-ledger.yml`](../.github/upstream-ledger.yml)

Recorded 2026-08-21 from GitHub (`gh` / REST). Ledger classified 2026-09-04.
`#784` marked `ported` after et.rs [#31](https://github.com/minpeter/et.rs/pull/31) / `906a7ca86691f00a82f88b99b21d7afceb07bf97`.
`#798` marked `ported` after et.rs [#77](https://github.com/minpeter/et.rs/pull/77).

| Field | Value |
| --- | --- |
| Upstream | [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal) |
| Baseline / latest release tag | [`et-v7.0.0`](https://github.com/MisterTea/EternalTerminal/releases/tag/et-v7.0.0) |
| Baseline / release commit | [`7656a32a5bc15c6746726a27a5a4ba1e468fab6e`](https://github.com/MisterTea/EternalTerminal/commit/7656a32a5bc15c6746726a27a5a4ba1e468fab6e) |
| Default branch | `master` |
| Pin tip (last classified) | [`584a68b4b54c74de7035e6108f49151ebce6a191`](https://github.com/MisterTea/EternalTerminal/commit/584a68b4b54c74de7035e6108f49151ebce6a191) (`#792`, 2026-09-03; reviewed 2026-09-04) |
| et.rs wire version | **protocol v6** (`PROTOCOL_VERSION = 6` in `crates/et-core/src/lib.rs`, README) |
| ET wire version at this pin | still **protocol v6** (`PROTOCOL_VERSION = 6` in `src/base/Headers.hpp` on both `et-v7.0.0` and `master`) |

`7656a32...master` is `ahead_by` 16. All 16 are classified. Unclassified would be drift.

## Ledger (classified 2026-09-04)

| sha | date | kind | status | note |
| --- | --- | --- | --- | --- |
| [`f6cf437`](https://github.com/MisterTea/EternalTerminal/commit/f6cf43707bde07eb6d11495586a35b9f2d64b032) | 2026-07-08 | ci | skip | deployment fixes |
| [`dfc75d6`](https://github.com/MisterTea/EternalTerminal/commit/dfc75d6638c653249a2e4f6f1c27f665ca693420) | 2026-07-09 | ci | skip | #771 cowbuilder |
| [`27a7db6`](https://github.com/MisterTea/EternalTerminal/commit/27a7db658e21ee9f9c1bff68db1c2cb241481b5e) | 2026-07-10 | ci | skip | debian signing |
| [`3698116`](https://github.com/MisterTea/EternalTerminal/commit/3698116f764bc1868c179e4756eb0dabe7340827) | 2026-07-10 | ci | skip | debian fix |
| [`cd5b530`](https://github.com/MisterTea/EternalTerminal/commit/cd5b530d18affe7d77c290e3af8035700275cb51) | 2026-07-12 | ci | skip | debian |
| [`fb9ef1d`](https://github.com/MisterTea/EternalTerminal/commit/fb9ef1da67eb8e1cd1a30fdd9a4a5b6415e7a440) | 2026-07-13 | ci | skip | debian deploy SSH |
| [`3dd946d`](https://github.com/MisterTea/EternalTerminal/commit/3dd946d7128ea98653bbbab2f454706aa66d9893) | 2026-07-13 | ci | skip | #774 GCC 15 |
| [`12889c5`](https://github.com/MisterTea/EternalTerminal/commit/12889c5bfbf1ece81d45b4834f9b05254e723e1e) | 2026-07-21 | ci | skip | #776 GCC-16 CI |
| [`90711ad`](https://github.com/MisterTea/EternalTerminal/commit/90711ad421264db30dc5d05df4a37452b41a7667) | 2026-07-21 | ci | skip | #777 windows deploy |
| [`69b3353`](https://github.com/MisterTea/EternalTerminal/commit/69b33537ab12f324cf619aca04dc483728dc30c3) | 2026-07-30 | security | **ported** | #784 handshake 4KiB, recover, unix-socket LPE. Landed in et.rs via #31 / 906a7ca. |
| [`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) | 2026-08-07 | product | skip | #788 non-tty console keep-alive; not wire/security |
| [`fcce839`](https://github.com/MisterTea/EternalTerminal/commit/fcce83924326ab5743878f2d58a534bd8a6bc22c) | 2026-09-01 | other | skip | #801 HTM/Windows/coverage; not et.rs server accept/reconnect |
| [`50b961d`](https://github.com/MisterTea/EternalTerminal/commit/50b961d9e9eb6daf57d8a5ce9cae8f9209bffe44) | 2026-09-01 | security | **ported** | #798 accept starvation / stuck reconnect. Landed in et.rs via #77. PROTOCOL_VERSION stays 6. |
| [`3e8db00`](https://github.com/MisterTea/EternalTerminal/commit/3e8db00cdccba4906ca1b995d3fd7c0650a9fac9) | 2026-09-01 | product | skip | #803 TIOCGWINSZ; Unix terminal-size observation only |
| [`342c0df`](https://github.com/MisterTea/EternalTerminal/commit/342c0dfb32882c94df6aa18092fc897015222c0b) | 2026-09-02 | ci | skip | #802 Windows build/test parity; not a wire or server-lock change |
| [`584a68b`](https://github.com/MisterTea/EternalTerminal/commit/584a68b4b54c74de7035e6108f49151ebce6a191) | 2026-09-03 | security | skip | #792 disable SO_LINGER. et.rs never sets SO_LINGER and has no globalMutex-on-close; default linger-off already matches. |

## Ported and residual

[`69b3353`](https://github.com/MisterTea/EternalTerminal/commit/69b33537ab12f324cf619aca04dc483728dc30c3) (`#784`) is `status: ported`.
It landed in et.rs via [#31](https://github.com/minpeter/et.rs/pull/31) /
[`906a7ca86691f00a82f88b99b21d7afceb07bf97`](https://github.com/minpeter/et.rs/commit/906a7ca86691f00a82f88b99b21d7afceb07bf97)
(handshake 4 KiB cap + idle/absolute read deadlines; recover does not
displace on failure; unix-socket listen/connect as the session user).
Wire stays protocol v6.

[`50b961d`](https://github.com/MisterTea/EternalTerminal/commit/50b961d9e9eb6daf57d8a5ce9cae8f9209bffe44) (`#798`) is `status: ported`.
It landed in et.rs via [#77](https://github.com/minpeter/et.rs/pull/77).
It is a server lock/availability bug, not a protocol bump. Upstream held
`classMutex` across blocking recover I/O so one stuck reconnect stopped
every accept. et.rs already accepted on a dedicated thread and ran recover
off the session-table lock with a single-flight permit; this port adds the
remaining #798 semantics: refuse recover on a shutting-down session, and
raise the TCP listen backlog from 32 to 128 (INI `[Networking] backlog`,
non-positive falls back to 128). Wire stays protocol v6.

Upstream left reconnect passkey-before-recover for a future
`PROTOCOL_VERSION` bump; that residual is still unported. Do **not** treat
this pin as a green light to bump `PROTOCOL_VERSION` or land a v7 port.

[`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) (`#788`) stays `status: skip`
(product, not wire/security).
[`fcce839`](https://github.com/MisterTea/EternalTerminal/commit/fcce83924326ab5743878f2d58a534bd8a6bc22c) (`#801`),
[`3e8db00`](https://github.com/MisterTea/EternalTerminal/commit/3e8db00cdccba4906ca1b995d3fd7c0650a9fac9) (`#803`), and
[`342c0df`](https://github.com/MisterTea/EternalTerminal/commit/342c0dfb32882c94df6aa18092fc897015222c0b) (`#802`) stay `status: skip`
(HTM/Windows/coverage, TIOCGWINSZ, Windows build).
[`584a68b`](https://github.com/MisterTea/EternalTerminal/commit/584a68b4b54c74de7035e6108f49151ebce6a191) (`#792`) stays `status: skip`
(et.rs never sets `SO_LINGER` and has no process-wide mutex around close;
default linger-off already matches the C++ fix).

et.rs still claims **protocol v6**. EternalTerminal’s latest product release is
**v7.0.0**, and `master` is sixteen classified commits past that tag.

Review ports against the conflict policy in
[`docs/upstream-factory.md`](upstream-factory.md). Gate any later port with
`cargo test --workspace` (especially `fixtures/wire.json`), not a GUI.
