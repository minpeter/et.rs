# Upstream pin

**This pin is the last *reviewed* EternalTerminal snapshot. It does not mean
et.rs has ported that snapshot.** Pin ≠ ported.

Canonical machine files:

- Pin (release tag/SHA, default-branch name, protocol versions, last classified tip):
  [`.github/upstream-pin.yml`](../.github/upstream-pin.yml)
- Ledger (every `master` commit after baseline):
  [`.github/upstream-ledger.yml`](../.github/upstream-ledger.yml)

Recorded 2026-08-21 from GitHub (`gh` / REST). Ledger classified 2026-08-22.
`#784` marked `ported` after et.rs [#31](https://github.com/minpeter/et.rs/pull/31) / `906a7ca86691f00a82f88b99b21d7afceb07bf97`.

| Field | Value |
| --- | --- |
| Upstream | [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal) |
| Baseline / latest release tag | [`et-v7.0.0`](https://github.com/MisterTea/EternalTerminal/releases/tag/et-v7.0.0) |
| Baseline / release commit | [`7656a32a5bc15c6746726a27a5a4ba1e468fab6e`](https://github.com/MisterTea/EternalTerminal/commit/7656a32a5bc15c6746726a27a5a4ba1e468fab6e) |
| Default branch | `master` |
| Pin tip (last classified) | [`b74a12efc567dbc1360ac0846f889c945a2eba60`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) (`#788`, 2026-08-07) |
| et.rs wire version | **protocol v6** (`PROTOCOL_VERSION = 6` in `crates/et-core/src/lib.rs`, README) |
| ET wire version at this pin | still **protocol v6** (`PROTOCOL_VERSION = 6` in `src/base/Headers.hpp` on both `et-v7.0.0` and `master`) |

`7656a32...master` is `ahead_by` 11. All 11 are classified. Unclassified would be drift.

## Ledger (classified 2026-08-22)

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

## Ported and residual

[`69b3353`](https://github.com/MisterTea/EternalTerminal/commit/69b33537ab12f324cf619aca04dc483728dc30c3) (`#784`) is `status: ported`.
It landed in et.rs via [#31](https://github.com/minpeter/et.rs/pull/31) /
[`906a7ca86691f00a82f88b99b21d7afceb07bf97`](https://github.com/minpeter/et.rs/commit/906a7ca86691f00a82f88b99b21d7afceb07bf97)
(handshake 4 KiB cap + idle/absolute read deadlines; recover does not
displace on failure; unix-socket listen/connect as the session user).
Wire stays protocol v6.

Upstream left reconnect passkey-before-recover for a future
`PROTOCOL_VERSION` bump; that residual is still unported. Do **not** treat
this pin as a green light to bump `PROTOCOL_VERSION` or land a v7 port.

[`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) (`#788`) stays `status: skip`
(product, not wire/security).

et.rs still claims **protocol v6**. EternalTerminal’s latest product release is
**v7.0.0**, and `master` is eleven classified commits past that tag.

Review ports against the conflict policy in
[`docs/upstream-factory.md`](upstream-factory.md). Gate any later port with
`cargo test --workspace` (especially `fixtures/wire.json`), not a GUI.
