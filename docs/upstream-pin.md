# Upstream pin

**This pin is the last *reviewed* EternalTerminal snapshot. It does not mean
et.rs has ported that snapshot.** Pin ≠ ported.

Canonical machine files:

- Pin (release tag/SHA, default-branch name, protocol versions, last classified tip):
  [`.github/upstream-pin.yml`](../.github/upstream-pin.yml)
- Ledger (every `master` commit after baseline):
  [`.github/upstream-ledger.yml`](../.github/upstream-ledger.yml)

Recorded 2026-08-21 from GitHub (`gh` / REST). Ledger classified 2026-09-22.
`#784` marked `ported` after et.rs [#31](https://github.com/minpeter/et.rs/pull/31) / `906a7ca86691f00a82f88b99b21d7afceb07bf97`.
`#798` marked `ported` after et.rs [#77](https://github.com/minpeter/et.rs/pull/77).

| Field | Value |
| --- | --- |
| Upstream | [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal) |
| Baseline / latest release tag | [`et-v7.0.0`](https://github.com/MisterTea/EternalTerminal/releases/tag/et-v7.0.0) |
| Baseline / release commit | [`7656a32a5bc15c6746726a27a5a4ba1e468fab6e`](https://github.com/MisterTea/EternalTerminal/commit/7656a32a5bc15c6746726a27a5a4ba1e468fab6e) |
| Default branch | `master` |
| Pin tip (last classified) | [`a836741`](https://github.com/MisterTea/EternalTerminal/commit/a8367415783a64405c62c70b755b4c09b410532b) (#830 ProxyJump none, reviewed 2026-09-22) |
| et.rs wire version | **protocol v6** (`PROTOCOL_VERSION = 6` in `crates/et-core/src/lib.rs`, README) |
| ET wire version at this pin | still **protocol v6** (`PROTOCOL_VERSION = 6` in `src/base/Headers.hpp` on both `et-v7.0.0` and `master`) |

The reviewed baseline-to-#830 range contains 44 classified commits (31 prior + 13 on 2026-09-22). Unclassified commits would be drift. `#837` (`TERMINAL_CLOSE` / `--close-on-hangup`) is `ported`.

## Ledger (classified 2026-09-22)

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
| [`cd731902`](https://github.com/MisterTea/EternalTerminal/commit/cd7319020edce131fbd6f21b1a87e07f4ac41cdb) | 2026-09-05 | product | **ported** | #804 interruptible unsent output and tmux control preservation; et.rs #100. |
| [`be28bd6`](https://github.com/MisterTea/EternalTerminal/commit/be28bd6de304093edee6efad55a93086fe9befd0) | 2026-09-08 | product | **ported** | #805/#806 synchronized to #813; [command/state/screen/lifecycle matrix](htm-parity-matrix.md). PROTOCOL_VERSION stays 6. |
| [`15256c5`](https://github.com/MisterTea/EternalTerminal/commit/15256c50903f936bfbd3e90de2b03ffa0184f82d) | 2026-09-10 | security | skip | #809 replace select() with epoll/kqueue/poll to avoid FD_SETSIZE fd_set stack corruption. et.rs has no C select()/fd_set path (socket2/nix, forbid unsafe). Same skip as #792. PROTOCOL_VERSION stays 6. |
| [`59cee86`](https://github.com/MisterTea/EternalTerminal/commit/59cee86068bea79090b57a96c366243fc73d6130) | 2026-09-11 | docs | skip | C++ comment-only; Rust has its own screen model and ESC-k filter. |
| [`ea2c2ed`](https://github.com/MisterTea/EternalTerminal/commit/ea2c2ed170b6f0a106a7eee324b14395345a6671) | 2026-09-14 | product | skip | #812 optional RAW_STACKTRACE for C++ logger; et.rs has no easylogging/ust path. PROTOCOL_VERSION stays 6. |
| [`8a306f6`](https://github.com/MisterTea/EternalTerminal/commit/8a306f6d3580886f77357864fc010a4e8b78c3a6) | 2026-09-17 | product | **ported** | Canonical command/state parity, sandboxed libvterm, authenticated diagnostics, bounded bridges and lifecycle. [Native-platform/GUI verification limits](htm-control-mode.md) remain explicit. |
| [`02b2142`](https://github.com/MisterTea/EternalTerminal/commit/02b21424b4c85ababe9fd0e446d2e484f16b0c6b) | 2026-09-17 | security | skip | #810 session/forwarding FD and generated socket-dir cleanup. et.rs RAII Drop already closes sessions, forwards, and temp unix-socket dirs. |
| [`0e38189`](https://github.com/MisterTea/EternalTerminal/commit/0e38189fcd57269244f7bdf1bd9dfd0ee97df8f8) | 2026-09-17 | product | skip | #811 honor explicit TCP forwarding destinations. et.rs `Endpoint::parse_destination` already preserves names. |
| [`2d3e2fc`](https://github.com/MisterTea/EternalTerminal/commit/2d3e2fc0f57e7adb1cfffe58c7e1d67906292322) | 2026-09-17 | product | **ported** | #814 isolate destination `--ssh-option` off the jumphost SSH argv; add `--ssh-config` / `--no-ssh-config`. |
| [`5673969`](https://github.com/MisterTea/EternalTerminal/commit/5673969b7c04d15111dcd330710ae31ba0c33499) | 2026-09-18 | security | skip | #815 preserve partial socket write progress. et.rs `write_all_until` / `write_live_frame_until` / `write_local_packet` already avoid the C++ retry-from-0 framing bug. |
| [`a8d84af`](https://github.com/MisterTea/EternalTerminal/commit/a8d84af99ba377b75dfa230e55774c8d9a540681) | 2026-09-18 | product | skip | C++ UniversalStacktrace / easylogging only; et.rs has no ust path (same family as #812). |
| [`71bfe95`](https://github.com/MisterTea/EternalTerminal/commit/71bfe95216333628a0b4cb26d8a5b12a247d61e1) | 2026-09-18 | product | skip | external/UniversalStacktrace MinGW only; N/A to Rust. |
| [`0e3e3e0`](https://github.com/MisterTea/EternalTerminal/commit/0e3e3e0cbf3fe5bf329cfb2feff08995140d5470) | 2026-09-18 | ci | skip | #817 C++ Windows test/WSAPoll port; et.rs already has Windows-native ConPTY server and its own tests. |
| [`17ec755`](https://github.com/MisterTea/EternalTerminal/commit/17ec75556521df092024ceb6b95636cef367a0aa) | 2026-09-19 | ci | skip | #818 OpenWrt packaging/workflows only. |
| [`db4f6f6`](https://github.com/MisterTea/EternalTerminal/commit/db4f6f63183b403c5a530249fe5e126c59adf660) | 2026-09-19 | product | skip | #816 Rocky/Gentoo CI plus optional C++ SSH login/MOTD display; et.rs already has `terminal_motd` / `ssh_process` paths. |
| [`e34389e`](https://github.com/MisterTea/EternalTerminal/commit/e34389ea302b949c8c3342c0bce1ef11472abef8) | 2026-09-19 | security | skip | #778 CVE-2023-23558 telemetry/temp audit; et.rs has no telemetry |
| [`91cb503`](https://github.com/MisterTea/EternalTerminal/commit/91cb5031cd30bf127455615462dc30f47a51e913) | 2026-09-21 | ci | skip | clang-format PRCI (reverted) |
| [`5b2cd10`](https://github.com/MisterTea/EternalTerminal/commit/5b2cd10256433926bbcff3ca57b4620234430258) | 2026-09-21 | ci | skip | revert clang-format |
| [`09551a9`](https://github.com/MisterTea/EternalTerminal/commit/09551a96c123879d785c230c9ece2d418cf38222) | 2026-09-21 | product | **ported** | #789/#847 comma-separated SSH-style tunnels |
| [`8f3b44c`](https://github.com/MisterTea/EternalTerminal/commit/8f3b44c18329374d8752486aa0329fbd9ca90299) | 2026-09-21 | ci | skip | #677/#834 C++ noexecstack |
| [`c097839`](https://github.com/MisterTea/EternalTerminal/commit/c097839f059a7ef431939fe6574b80968051f73c) | 2026-09-21 | product | skip | #669/#833 partial listen; et.rs already probes IPv6 |
| [`62a9dd5`](https://github.com/MisterTea/EternalTerminal/commit/62a9dd54d8d2fb6c70b9548d347a029620f7c29d) | 2026-09-21 | product | skip | #655/#831 subprocess drain; et.rs ssh_process already drains |
| [`3abb882`](https://github.com/MisterTea/EternalTerminal/commit/3abb882f5675550d876bb0efbc119dd9fee17fd3) | 2026-09-21 | docs | skip | #219/#821 README binaries |
| [`651fe3e`](https://github.com/MisterTea/EternalTerminal/commit/651fe3e717305240643a6201422dd9baeaacb867) | 2026-09-21 | security | skip | #799/#848 unknown packet session-local; et.rs already SessionError |
| [`5661a4b`](https://github.com/MisterTea/EternalTerminal/commit/5661a4b6e4f367b493ee557496919b619a65747e) | 2026-09-21 | product | skip | #683/#835 FreeBSD login argv0; et.rs uses `-l` |
| [`f49e556`](https://github.com/MisterTea/EternalTerminal/commit/f49e55681049c7784d4f4012d9eacbbcedf48e6f) | 2026-09-21 | docs | skip | #752/#841 README roles |
| [`d70e00a`](https://github.com/MisterTea/EternalTerminal/commit/d70e00ac44758b8037847ce128e647204f2e0603) | 2026-09-21 | protocol | **ported** | #707/#837 `TERMINAL_CLOSE=11` / `--close-on-hangup`. PROTOCOL_VERSION stays 6. |
| [`a836741`](https://github.com/MisterTea/EternalTerminal/commit/a8367415783a64405c62c70b755b4c09b410532b) | 2026-09-21 | product | skip | #653/#830 ProxyJump none; et.rs already handles |


## Ported and residual

[`09551a9`](https://github.com/MisterTea/EternalTerminal/commit/09551a96c123879d785c230c9ece2d418cf38222)
(`#789` / `#847`) is `status: ported`. Comma-separated SSH-style tunnels are
parsed independently in `crates/et-cli/src/tunnel.rs` (et-style when ≤2 colon
parts, otherwise ssh-style). Protocol v6 is unchanged.

[`d70e00a`](https://github.com/MisterTea/EternalTerminal/commit/d70e00ac44758b8037847ce128e647204f2e0603)
(`#707` / `#837`) is `status: ported`. Upstream added `TERMINAL_CLOSE = 11`
and optional `--close-on-hangup` without bumping `PROTOCOL_VERSION` (still 6).
With the flag, the et client sends that packet on Unix `SIGHUP` and on
Windows console close, logoff, shutdown, or break, then leaves the client
loop. etserver writes a framed local `TERMINAL_CLOSE` and ends that session's
terminal bridge; etterminal treats the framed packet as a clean PTY shutdown.
Unknown client packet types stay `SessionError` (session-local, same as the
`#848` skip). The default remains no remote close.


[`cd731902`](https://github.com/MisterTea/EternalTerminal/commit/cd7319020edce131fbd6f21b1a87e07f4ac41cdb)
(`#804`) is `status: ported` after independent review of
[et.rs #100](https://github.com/minpeter/et.rs/pull/100). Rust stages terminal output
before assigning replay sequences, flushes unsent floods at the 64 KiB threshold,
preserves small output and tmux response/control lines, and prioritizes tmux
responses ahead of queued pane output. Native socket buffers remain small.
The implementation reuses Rust's existing bounded queues and cancellation rather
than copying the C++ event loop. Protocol v6 and generated wire fixtures are unchanged.

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
[`be28bd6`](https://github.com/MisterTea/EternalTerminal/commit/be28bd6de304093edee6efad55a93086fe9befd0)
(`#805` / `#806`) and [#813](https://github.com/MisterTea/EternalTerminal/pull/813)
are `status: ported`. et.rs already had an HTM multiplexer; the old claim that
HTM was absent was incorrect. Its UUID/JSON/base64 protocol has been replaced by
a bounded tmux control-mode implementation synchronized to #813, not the
intermediate #805 state. The [compatibility record](htm-control-mode.md) and
[production matrix](htm-parity-matrix.md) document source-backed quirks,
preserved security policies, native C++ differential tests, and platform-only
verification limitations. No canonical command family is intentionally deferred.
[`15256c5`](https://github.com/MisterTea/EternalTerminal/commit/15256c50903f936bfbd3e90de2b03ffa0184f82d)
(`#809`) stays `status: skip`. Upstream replaced `select()` with epoll/kqueue/poll
to avoid `FD_SETSIZE` `fd_set` stack corruption on high fds / many port forwards.
et.rs is Rust (`forbid(unsafe)`), uses socket2/nix and its own nonblocking
connection workers, and has no C `select()`/`fd_set`/`FD_SETSIZE` path, so the
overflow bug does not apply (same skip pattern as `#792` `SO_LINGER`).
[`59cee86`](https://github.com/MisterTea/EternalTerminal/commit/59cee86068bea79090b57a96c366243fc73d6130)
stays `status: skip`: this is a C++ comment-only change. The Rust screen model
has its own legacy ESC-k filter; live output remains byte-exact.
[`ea2c2ed`](https://github.com/MisterTea/EternalTerminal/commit/ea2c2ed170b6f0a106a7eee324b14395345a6671)
(`#812`) stays `status: skip`. Optional `RAW_STACKTRACE` (default OFF) so C++
crash logs can emit PCs without synchronous symbolization that held the logger
mutex. et.rs has no easylogging/ust/`ET_RAW_STACKTRACE` path (`forbid(unsafe)`),
so the C++ stacktrace helpers are not ported. `PROTOCOL_VERSION` stays 6.

[`02b2142`](https://github.com/MisterTea/EternalTerminal/commit/02b21424b4c85ababe9fd0e446d2e484f16b0c6b)
(`#810`) stays `status: skip`. Upstream now closes completed sessions' router
connections and leftover forwarding sockets and removes generated socket
directories. et.rs already does this through RAII: `Runtime`/`Router`/
`ActiveSession`/`Forwarder` `Drop` shut down connections, `forward_worker_state::remove`
calls `stop_io`, and `ForwardListener`/`ForwardPipe`/`PendingPath`/
`PendingDirectories`/`UserSocketCleanup` remove unix sockets and created temp
dirs. Reconnect and timeout paths are unchanged. `PROTOCOL_VERSION` stays 6.

[`0e38189`](https://github.com/MisterTea/EternalTerminal/commit/0e38189fcd57269244f7bdf1bd9dfd0ee97df8f8)
(`#811`) stays `status: skip`. Upstream stopped ignoring explicit TCP
destination hostnames (empty names still try IPv6 loopback then IPv4). et.rs
already preserves non-empty names in `Endpoint::parse_destination` and connects
via `connect_tcp(host, port)`. `PROTOCOL_VERSION` stays 6.

[`2d3e2fc`](https://github.com/MisterTea/EternalTerminal/commit/2d3e2fc0f57e7adb1cfffe58c7e1d67906292322)
(`#814`) is `status: ported`. Destination `--ssh-option` values stay on the
target bootstrap/probe/`ssh -G` path and are no longer replayed onto the
direct jumphost SSH argv (operational guards such as `ClearAllForwardings`
remain). `--ssh-config <absolute-path|none>` and `--no-ssh-config` select the
sole OpenSSH `-F` policy for destination and jumphost resolution. Validation
fails closed on relative, symlink, non-regular, missing, or shell-unsafe
paths; Windows drive and UNC paths are accepted as absolute.

[`5673969`](https://github.com/MisterTea/EternalTerminal/commit/5673969b7c04d15111dcd330710ae31ba0c33499)
(`#815`) stays `status: skip`. Upstream `UnixSocketHandler::write` returned
`-1` after a successful prefix, so `writeAllOrThrow` retried from offset 0
and corrupted CatchupBuffer framing. et.rs has no that C++ path:
`write_all_until` advances on `Ok(count)`; on mid-frame error
`write_live_frame_until` soft-disconnects/shuts down so a partial frame
cannot desync recovery; local `write_local_packet` resumes `WouldBlock`
from the partial. `PROTOCOL_VERSION` stays 6.

[`a8d84af`](https://github.com/MisterTea/EternalTerminal/commit/a8d84af99ba377b75dfa230e55774c8d9a540681)
stays `status: skip`. C++ UniversalStacktrace / easylogging only; et.rs
has no ust path (same family as `#812`). `PROTOCOL_VERSION` stays 6.

[`71bfe95`](https://github.com/MisterTea/EternalTerminal/commit/71bfe95216333628a0b4cb26d8a5b12a247d61e1)
stays `status: skip`. `external/UniversalStacktrace` MinGW only; N/A to
Rust. `PROTOCOL_VERSION` stays 6.

[`0e3e3e0`](https://github.com/MisterTea/EternalTerminal/commit/0e3e3e0cbf3fe5bf329cfb2feff08995140d5470)
(`#817`) stays `status: skip`. C++ Windows test/WSAPoll port; et.rs already
has a Windows-native ConPTY server and its own tests. Not wire/auth.
`PROTOCOL_VERSION` stays 6.

[`17ec755`](https://github.com/MisterTea/EternalTerminal/commit/17ec75556521df092024ceb6b95636cef367a0aa)
(`#818`) stays `status: skip`. OpenWrt packaging/workflows only.
`PROTOCOL_VERSION` stays 6.

[`db4f6f6`](https://github.com/MisterTea/EternalTerminal/commit/db4f6f63183b403c5a530249fe5e126c59adf660)
(`#816`) stays `status: skip`. Portability CI plus optional C++
`SshSetupHandler` `displayLoginOutput` (strip `IDPASSKEY` from MOTD/login
banner). et.rs already has `terminal_motd` / `ssh_process` paths; not a
protocol/wire/auth change. `PROTOCOL_VERSION` stays 6.

et.rs still claims **protocol v6**. EternalTerminal’s latest product release is
**v7.0.0**, and the reviewed tip is thirty-one classified commits past that tag.

Review ports against the conflict policy in
[`docs/upstream-factory.md`](upstream-factory.md). Gate any later port with
`cargo test --workspace` (especially `fixtures/wire.json`), not a GUI.
