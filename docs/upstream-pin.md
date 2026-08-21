# Upstream pin

**This pin is the last *reviewed* EternalTerminal snapshot. It does not mean
et.rs has ported that snapshot.**

Canonical machine file (the watch workflow reads this):
[`.github/upstream-pin.yml`](../.github/upstream-pin.yml).

Recorded 2026-08-21 from GitHub (`gh` / REST), not a scrape of private APIs.

| Field | Value |
| --- | --- |
| Upstream | [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal) |
| Latest release tag | [`et-v7.0.0`](https://github.com/MisterTea/EternalTerminal/releases/tag/et-v7.0.0) |
| Release commit | [`7656a32a5bc15c6746726a27a5a4ba1e468fab6e`](https://github.com/MisterTea/EternalTerminal/commit/7656a32a5bc15c6746726a27a5a4ba1e468fab6e) |
| Default branch | `master` |
| Default-branch tip | [`b74a12efc567dbc1360ac0846f889c945a2eba60`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) (`#788`, 2026-08-07) |
| et.rs wire version | **protocol v6** (`PROTOCOL_VERSION = 6` in `crates/et-core/src/lib.rs`, README) |
| ET wire version at this pin | still **protocol v6** (`PROTOCOL_VERSION = 6` in `src/base/Headers.hpp` on both `et-v7.0.0` and `master`) |

## FACTORY BACKLOG (not in this PR)

et.rs still claims **protocol v6**. EternalTerminal’s latest product release is
**v7.0.0**, and `master` is several commits past that tag — including
post-v7 security work. That gap is backlog. Do **not** treat this pin as a
green light to bump `PROTOCOL_VERSION` or land a v7 port.

Notable unported `master` work after `et-v7.0.0`:

- [`69b3353`](https://github.com/MisterTea/EternalTerminal/commit/69b33537ab12f324cf619aca04dc483728dc30c3) (`#784`) — four pre-auth / privilege-escalation fixes (handshake size + absolute read deadlines; reconnect recover crash; unix-socket LPE). Upstream left reconnect passkey-before-recover for a future `PROTOCOL_VERSION` bump.
- [`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) (`#788`) — keep the client alive when the console fd is not a tty.

Review those against the conflict policy in
[`docs/upstream-factory.md`](upstream-factory.md). Gate any later port with
`cargo test --workspace` (especially `fixtures/wire.json`), not a GUI.
