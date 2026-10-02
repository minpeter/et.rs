# Upstream pin

**This pin is the last *reviewed* EternalTerminal snapshot. It does not mean
et.rs has ported that snapshot.** Pin ≠ ported.

Canonical machine files:

- Pin (release tag/SHA, default-branch name, protocol versions, last classified tip):
  [`.github/upstream-pin.yml`](../.github/upstream-pin.yml)
- Ledger (every `master` commit after baseline):
  [`.github/upstream-ledger.yml`](../.github/upstream-ledger.yml)

Recorded 2026-08-21 from GitHub (`gh` / REST). Ledger classified 2026-10-02.
`#784` marked `ported` after et.rs [#31](https://github.com/minpeter/et.rs/pull/31) / `906a7ca86691f00a82f88b99b21d7afceb07bf97`.
`#798` marked `ported` after et.rs [#77](https://github.com/minpeter/et.rs/pull/77).

| Field | Value |
| --- | --- |
| Upstream | [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal) |
| Baseline / latest release tag | [`et-v7.0.0`](https://github.com/MisterTea/EternalTerminal/releases/tag/et-v7.0.0) |
| Baseline / release commit | [`7656a32a5bc15c6746726a27a5a4ba1e468fab6e`](https://github.com/MisterTea/EternalTerminal/commit/7656a32a5bc15c6746726a27a5a4ba1e468fab6e) |
| Default branch | `master` |
| Pin tip (last classified) | [`5129342`](https://github.com/MisterTea/EternalTerminal/commit/5129342ef5ce3185125d907b95ad6d15a36b1cb6) (#876 tip, editor setup docs skip, reviewed 2026-10-02) |
| et.rs wire version | **protocol v6** (`PROTOCOL_VERSION = 6` in `crates/et-core/src/lib.rs`, README) |
| ET wire version at this pin | still **protocol v6** (`PROTOCOL_VERSION = 6` in `src/base/Headers.hpp` on both `et-v7.0.0` and `master`) |

The reviewed baseline-to-tip range contains 77 classified commits. Unclassified commits would be drift. The product-parity ports below passed combined Linux verification: 824 tests passed, none failed, and two existing tests were ignored. Formatting, workspace clippy, Windows GNU/macOS ARM binary cross-checks, and release/AUR packaging checks passed. Real OpenSSH mux clients exercised the Rust master; no live C++ peer, native Windows/macOS runtime, or actual VS Code sleep cycle was tested in this port. `ported` covers the behavior described in each row, including its explicit limitations, not unrestricted product parity. Protocol remains v6.

## Ledger (classified 2026-10-02)

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
| [`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) | 2026-08-07 | product | **ported** | #788 non-TTY EOF survival and SSH diagnostics; Linux tests, Windows cross-check |
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
| [`d70e00a`](https://github.com/MisterTea/EternalTerminal/commit/d70e00ac44758b8037847ce128e647204f2e0603) | 2026-09-21 | protocol | **ported** | #707/#837 `TERMINAL_CLOSE=11` / `--close-on-hangup`. Landed via #116. PROTOCOL_VERSION stays 6. |
| [`a836741`](https://github.com/MisterTea/EternalTerminal/commit/a8367415783a64405c62c70b755b4c09b410532b) | 2026-09-21 | product | skip | #653/#830 ProxyJump none; et.rs already handles |
| [`fcd4d95`](https://github.com/MisterTea/EternalTerminal/commit/fcd4d959c48082d465556a26400ab734bffdccc0) | 2026-09-22 | product | skip | #747/#840 nested SSH Include paths. C++ `ParseConfigFile.hpp` only; et.rs uses OpenSSH `ssh -G`, which already resolves relative Includes. Not wire/auth. |
| [`9718366`](https://github.com/MisterTea/EternalTerminal/commit/9718366cc5059912791c2590972ec451a05eeb9a) | 2026-09-22 | product | skip | #570/#829 telemetry crash-signal handler (`signal`+`raise`). et.rs has no telemetry. Not wire/auth. |
| [`34b1948`](https://github.com/MisterTea/EternalTerminal/commit/34b194813dc4a660370755c4306a19a489edf5d2) | 2026-09-23 | protocol | **ported** | #854 raw pipe command channel: `TerminalBuffer.is_stderr`, `InitialPayload`/`TermInit` `no_pty`+`command`, `et -T`. et.rs flow-control tags moved to fields 6 and 5 so they do not collide with `no_pty`. PROTOCOL_VERSION stays 6. |
| [`7a0fe09`](https://github.com/MisterTea/EternalTerminal/commit/7a0fe09bc92eb80e7441c9d974daa9665c596113) | 2026-09-23 | product | **ported** | #850 strict host boundary and positional command |
| [`bb4701d`](https://github.com/MisterTea/EternalTerminal/commit/bb4701d8a67be77496bd5926ca6a4fa2cc07e991) | 2026-09-23 | product | **ported** | #855 global server timeout, restart defaults and unclaimed expiry |
| [`2088bc4`](https://github.com/MisterTea/EternalTerminal/commit/2088bc4607e5239fe782b51a3b1f6f4bc375d9d6) | 2026-09-24 | product | **ported** | #852 local `-V`/`-G`; `-G` uses the full system OpenSSH dump |
| [`ce4963e`](https://github.com/MisterTea/EternalTerminal/commit/ce4963edfccf3ea38dbd320cc7751a2c8af4d882) | 2026-09-24 | protocol | **ported** | #851 `TERMINAL_EXIT_STATUS=12` and `supports_exit_status`. Forwarded only when the client opts in. PROTOCOL_VERSION stays 6. |
| [`6f53869`](https://github.com/MisterTea/EternalTerminal/commit/6f53869473a16407b59f1f3382d291ab97b4f64f) | 2026-09-24 | protocol | **ported** | #849 `et -D` / `et -W`: `half_close`, `no_shell`. PROTOCOL_VERSION stays 6. |
| [`f90c6f4`](https://github.com/MisterTea/EternalTerminal/commit/f90c6f4715f8f7e72afaf8085248ed7305c8aa6a) | 2026-09-24 | product | **ported** | #857 bounded PTY-only tmux-CC wall filter |
| [`b834d6e`](https://github.com/MisterTea/EternalTerminal/commit/b834d6ebbd0ba4742f5278cc562bba551800c0c0) | 2026-09-25 | ci | skip | #859 CI cache. Not protocol/wire/auth. |
| [`9a2d230`](https://github.com/MisterTea/EternalTerminal/commit/9a2d23092584606f8d0c55b111ed7416ca71d5ea) | 2026-09-25 | product | **ported** | #853 Unix mux v4 and local TCP/Unix mutation; unsupported requests rejected (see below) |
| [`c5ddae7`](https://github.com/MisterTea/EternalTerminal/commit/c5ddae79be824944df0e423cb49c032c60cf3394) | 2026-09-25 | ci | skip | #865 HTM e2e harness. CI/product only. |
| [`64fa900`](https://github.com/MisterTea/EternalTerminal/commit/64fa9006142cc63e936445fb908d07338ae9009e) | 2026-09-25 | product | **ported** | #863 split `id/passkey_TERM` at the first underscore. |
| [`99ac197`](https://github.com/MisterTea/EternalTerminal/commit/99ac1972c21f68c141d66f967ded231fc2903c7b) | 2026-09-25 | product | skip | #843/#769 SSH banner stderr UX. Product only. |
| [`fe0795c`](https://github.com/MisterTea/EternalTerminal/commit/fe0795c1dc6c42d13b50445681bf6a5b341ca64e) | 2026-09-25 | protocol | **ported** | #858 `disconnect_timeout_seconds` field 8. et.rs `flowcontrol` moved to field 9. |
| [`a4bed0c`](https://github.com/MisterTea/EternalTerminal/commit/a4bed0cfabe64cc307bc0afb63c6512e4e85d4e8) | 2026-09-25 | protocol | **ported** | #864 client reads peer catchup before writing its own. |
| [`f3137ce`](https://github.com/MisterTea/EternalTerminal/commit/f3137cee7b805284d7c76a7a5538884946576fd1) | 2026-09-26 | product | **ported** | #867 OpenSSH short-flag remap; README migration required |
| [`540367a`](https://github.com/MisterTea/EternalTerminal/commit/540367ac4509be41714769cf511d8c0aa90cde7a) | 2026-09-26 | security | **ported** | #793 named sessions, challenge handshake, restart survival. |
| [`da977ba`](https://github.com/MisterTea/EternalTerminal/commit/da977ba0fa212b775774c7e58a0f6d8f4c6ea175) | 2026-09-27 | product | **ported** | #870 forwards, SendEnv and RemoteCommand; unsupported forward forms remain explicit |
| [`ca91fb5`](https://github.com/MisterTea/EternalTerminal/commit/ca91fb5d5eaccaa464f1106cb946586ebc7789f9) | 2026-09-27 | protocol | **ported** | #868 failed connect exits, second connect recovers, catchup read-first. |
| [`044bcb5`](https://github.com/MisterTea/EternalTerminal/commit/044bcb5ae7960445a8bffb6fed4d3589f1aa8fc4) | 2026-09-27 | product | skip | #827 PTY teardown when a background process holds the slave. |
| [`16aec0c`](https://github.com/MisterTea/EternalTerminal/commit/16aec0c1d49b24027057541c7bb0f967b077bc2f) | 2026-09-28 | product | **ported** | #828 secure agent symlink retarget; absent agent clears stale link |
| [`568b7cc`](https://github.com/MisterTea/EternalTerminal/commit/568b7ccc043eb632462d6f51f8219f188c5a25a3) | 2026-09-28 | product | skip | #832/#660 empty no-op close after #833 already fixed partial listen. Same skip as #669/#833 (et.rs already probes IPv6). PROTOCOL_VERSION stays 6. |
| [`662c332`](https://github.com/MisterTea/EternalTerminal/commit/662c332ba572364265ea84d350c4065b3dc3d52e) | 2026-09-28 | product | **ported** | #825 actual Unix PTY path in SSH_TTY |
| [`f50f878`](https://github.com/MisterTea/EternalTerminal/commit/f50f878d21355e986a07582b4183f47a2ca309b7) | 2026-09-28 | product | skip | #823/#298 C++ per-connection port-forward 64KiB event-loop budget. Product/fairness; no wire change. PROTOCOL_VERSION stays 6. |
| [`5b0f17a`](https://github.com/MisterTea/EternalTerminal/commit/5b0f17a56e2a664ce506f3266d7cf770561e55b6) | 2026-09-28 | product | **ported** | #819 Unix ctl, cursors, transcript and lifecycle; raw -T/-W and Windows unsupported |
| [`eb518af`](https://github.com/MisterTea/EternalTerminal/commit/eb518af9f06dc338660c020cdc11fc7bede7c35e) | 2026-09-29 | product | skip | #872 C++ platform split N/A; equivalent `CLIENT_READ_BATCH=64`, bounded per-stream queues, and async pending writes |
| [`b5b009b`](https://github.com/MisterTea/EternalTerminal/commit/b5b009bf9ad91fda30eb2b394c6936c69e2b9806) | 2026-09-30 | product | **ported** | #874 EOF survival and SSH diagnostics; no actual VS Code sleep-cycle test. |
| [`ea2542f`](https://github.com/MisterTea/EternalTerminal/commit/ea2542fade29191703356e0abf00b78e72bb58e2) | 2026-09-30 | ci | skip | #875 C++ mains testable (MainEntry split) + setup-failure CI coverage. C++ harness only; not et.rs wire. PROTOCOL_VERSION stays 6. |
| [`a5e29af`](https://github.com/MisterTea/EternalTerminal/commit/a5e29afdf97b163cdc74331a58fbdb0514a466c5) | 2026-09-30 | product | skip | #873 client setup failures throw instead of exit(1); Connection drops writes when no handshake writer (hang fix). Product/reliability; et.rs already uses Result paths. No wire/auth change. PROTOCOL_VERSION stays 6. |
| [`dc1dc63`](https://github.com/MisterTea/EternalTerminal/commit/dc1dc63dc6b6175168d4dbc52227608ed3cbc6d0) | 2026-09-30 | ci | skip | #877 OpenWrt package installs et1. Packaging/CI only. PROTOCOL_VERSION stays 6. |
| [`bcc28abc`](https://github.com/MisterTea/EternalTerminal/commit/bcc28abc39d5445bd6f80efe518c8e5fdae125c4) | 2026-10-01 | product | skip | #878/#769 SSH auth banners on terminal after stderr→log redirect (preserve original stderr). Same product/UX family as #843/#769 skip; not wire/auth. PROTOCOL_VERSION stays 6. |
| [`5129342`](https://github.com/MisterTea/EternalTerminal/commit/5129342ef5ce3185125d907b95ad6d15a36b1cb6) | 2026-10-02 | docs | skip | #876 README-only editor setup for upstream et1; et.rs does not package that wrapper or claim editor sleep-cycle verification. Pin tip. |


## Ported and residual

[`09551a9`](https://github.com/MisterTea/EternalTerminal/commit/09551a96c123879d785c230c9ece2d418cf38222)
(`#789` / `#847`) is `status: ported`. Comma-separated SSH-style tunnels are
parsed independently in `crates/et-cli/src/tunnel.rs` (et-style when ≤2 colon
parts, otherwise ssh-style). Protocol v6 is unchanged.

[`d70e00a`](https://github.com/MisterTea/EternalTerminal/commit/d70e00ac44758b8037847ce128e647204f2e0603)
(`#707` / `#837`) is `status: ported`. It landed in et.rs via
[#116](https://github.com/minpeter/et.rs/pull/116). Upstream added `TERMINAL_CLOSE = 11`
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

[`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) (`#788`) is `status: ported` with `#874`:
non-TTY EOF no longer ends the session, and SSH diagnostics survive as recognizable
phrases, including redirected raw bytes on Windows. Linux heredoc and input tests
pass; the Windows path is cross-compiled, not natively exercised in this port.
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

[`fcd4d95`](https://github.com/MisterTea/EternalTerminal/commit/fcd4d959c48082d465556a26400ab734bffdccc0)
(`#747` / `#840`) stays `status: skip`. Upstream resolves nested SSH `Include`
paths relative to the file that contains them (`ParseConfigFile.hpp`). et.rs
resolves SSH config through real OpenSSH `ssh -G`
(`crates/et-bin/src/ssh_config.rs`); OpenSSH already resolves relative
`Include` paths against the containing file. Not protocol, wire, auth, or
security. No Rust port. `PROTOCOL_VERSION` stays 6.

[`9718366`](https://github.com/MisterTea/EternalTerminal/commit/9718366cc5059912791c2590972ec451a05eeb9a)
(`#570` / `#829`) stays `status: skip`. Upstream replaces
the C++ `TelemetryService.cpp` crash-signal handler with `signal(sig, SIG_DFL)`
plus `raise(sig)` so a fault terminates instead of looping. et.rs has no
telemetry. Not wire or auth. No Rust port. `PROTOCOL_VERSION` stays 6.

[`34b1948`](https://github.com/MisterTea/EternalTerminal/commit/34b194813dc4a660370755c4306a19a489edf5d2)
(`#854`) is `status: ported`. `et -T` / `--no-pty` runs `-c` on pipes
(binary stdio, separate stderr) instead of a login pty. The wire adds
`TerminalBuffer.is_stderr`, `InitialPayload.no_pty` + `command`, and the same
fields on `TermInit`. et.rs previously used those field numbers for
`flowcontrol`; those tags first moved off `no_pty`. `#851`/`#849` then took
`InitialPayload` field 6 (`supports_exit_status`) and `TermInit` field 5
(`no_shell`). `#858` then took `InitialPayload` field 8
(`disconnect_timeout_seconds`) and `#793` took `TermInit` fields 6–7, so et.rs
`flowcontrol` now lives at `InitialPayload` field 9 and `TermInit` field 8.
`PortForwardData.window` moved from field 6 to 7 so it is
not `half_close`. `PROTOCOL_VERSION` stays 6.

[`7a0fe09`](https://github.com/MisterTea/EternalTerminal/commit/7a0fe09bc92eb80e7441c9d974daa9665c596113)
(`#850`) is `status: ported`. SSH-style positional commands use a strict host
boundary, together with the #867 short-flag remap. CLI and integration tests pass.
`PROTOCOL_VERSION` stays 6.

[`bb4701d`](https://github.com/MisterTea/EternalTerminal/commit/bb4701d8a67be77496bd5926ca6a4fa2cc07e991)
(`#855`) is `status: ported`. The global server timeout is minutes in CLI and
INI `[Networking] disconnect_timeout`; explicit 0 disables it. Restart resolves
the current default, while unclaimed resumes receive `max(timeout, 60s grace)`.
Restart, claim-race and real-time expiry tests pass; `PROTOCOL_VERSION` stays 6.

[`2088bc4`](https://github.com/MisterTea/EternalTerminal/commit/2088bc4607e5239fe782b51a3b1f6f4bc375d9d6)
(`#852`) is `status: ported`: local `-V` and `-G` bypass daemon/mux dispatch.
`-G` prints the full resolved system OpenSSH dump, not upstream's smaller subset.
Bootstrap and CLI tests pass.

[`ce4963e`](https://github.com/MisterTea/EternalTerminal/commit/ce4963edfccf3ea38dbd320cc7751a2c8af4d882)
(`#851`) is `status: ported` for wire parity. `TERMINAL_EXIT_STATUS = 12` and
`TerminalExitStatus.exitcode` report `WEXITSTATUS` or `128+signal`.
`InitialPayload.supports_exit_status` is field 6 (default unset). etserver
forwards packet 12 only when the client set it, because et-v7.0.0 aborts on
unknown type 12. `et --command` / command sessions exit with that status; interactive
sessions and `et -W` stay 0. et.rs `flowcontrol` left field 6 and now lives at field 9.
`PROTOCOL_VERSION` stays 6. This pin does not claim every product follow-up
beyond that wire behavior is finished.

[`6f53869`](https://github.com/MisterTea/EternalTerminal/commit/6f53869473a16407b59f1f3382d291ab97b4f64f)
(`#849`) is `status: ported` for wire parity. `et -D` is SOCKS after connect
(SOCKS4/4a and SOCKS5 no-auth, including post-CONNECT early data). `et -W host:port`
ties stdio to the remote destination with `no_shell` and no pty. `half_close`
keeps the destination open for the reply after the source finishes writing.
`TermInit.no_shell` is field 5. et.rs `flowcontrol` left that tag and now lives at field 8.
`PortForwardData.half_close` is field 6, so et.rs `window` moved to field 7.
Windows rejects `-W`. `PROTOCOL_VERSION` stays 6.

[`f90c6f4`](https://github.com/MisterTea/EternalTerminal/commit/f90c6f4715f8f7e72afaf8085248ed7305c8aa6a)
(`#857`) is `status: ported`. A PTY-only tmux-CC filter removes journald wall
text while retaining response bodies and binary bytes. It buffers at most seven
undecided prefix bytes; megabyte streams, one-byte chunks, keyword lookalikes and
split terminators are tested. `PROTOCOL_VERSION` stays 6.

[`b834d6e`](https://github.com/MisterTea/EternalTerminal/commit/b834d6ebbd0ba4742f5278cc562bba551800c0c0)
(`#859`) stays `status: skip`. CI cache only.

[`9a2d230`](https://github.com/MisterTea/EternalTerminal/commit/9a2d23092584606f8d0c55b111ed7416ca71d5ea)
(`#853`) is `status: ported`. Unix mux v4 supports command/interactive passengers,
background/persistence, and local TCP/Unix forward open/cancel. Cancellation
leaves accepted streams alive. Real system OpenSSH clients test framing,
descriptor passing and command status. Remote, dynamic, stdio, X11, subsystem
and agent mux requests, raw `-T` masters (except `-NT`), and Windows local mux
are explicitly unsupported. ControlPath tokens are literal, not expanded.

[`c5ddae7`](https://github.com/MisterTea/EternalTerminal/commit/c5ddae79be824944df0e423cb49c032c60cf3394)
(`#865`) stays `status: skip`. HTM end-to-end harness. CI/product only.

[`64fa900`](https://github.com/MisterTea/EternalTerminal/commit/64fa9006142cc63e936445fb908d07338ae9009e)
(`#863`) is `status: ported`. etterminal splits `id/passkey_TERM` at the first
underscore, so a TERM such as `xterm_256color` does not abort session start.

[`99ac197`](https://github.com/MisterTea/EternalTerminal/commit/99ac1972c21f68c141d66f967ded231fc2903c7b)
(`#843` / `#769`) stays `status: skip`. SSH banner stderr UX. Product only.

[`fe0795c`](https://github.com/MisterTea/EternalTerminal/commit/fe0795c1dc6c42d13b50445681bf6a5b341ca64e)
(`#858`) is `status: ported` for the wire field and the etserver/etterminal
honor path. `InitialPayload.disconnect_timeout_seconds` is field 8 (seconds;
0 means no timeout). The client `--disconnect-timeout` flag is minutes.
et.rs `flowcontrol` moved to `InitialPayload` field 9. The `et1` wrapper
script is not packaged. `PROTOCOL_VERSION` stays 6.

[`a4bed0c`](https://github.com/MisterTea/EternalTerminal/commit/a4bed0cfabe64cc307bc0afb63c6512e4e85d4e8)
(`#864`) is `status: ported`. The client reads the peer `CatchupBuffer` before
writing its own. The server still writes first, so a patched client recovers
against an old or new server.

[`f3137ce`](https://github.com/MisterTea/EternalTerminal/commit/f3137cee7b805284d7c76a7a5538884946576fd1)
(`#867`) is `status: ported` with the OpenSSH short-flag remap and strict host
boundary. Existing scripts must follow the README migration table. The migrated
integration suite and CLI boundary tests pass.

[`540367a`](https://github.com/MisterTea/EternalTerminal/commit/540367ac4509be41714769cf511d8c0aa90cde7a)
(`#793`) is `status: ported` for the wire, auth, and named-session behavior.
`ConnectRequest` gains `resetIntent` and `supportsChallenge`. Peers that omit
`supportsChallenge` keep the one-round protocol-6 handshake. Challenge-capable
clients prove possession of the passkey with `ConnectAuth` and verify the
server's reset decision. `RETRY_LATER` covers the post-restart grace window.
Named sessions live in owner-only `~/.et/sessions` (`--name`, `--attach`,
`--list`, `--kill`). `TermInit` fields 6–7 and `TerminalUserInfo` fields 6–8
are the upstream resume tags, so et.rs `flowcontrol` on `TermInit` lives at
field 8. `PROTOCOL_VERSION` stays 6.

[`da977ba`](https://github.com/MisterTea/EternalTerminal/commit/da977ba0fa212b775774c7e58a0f6d8f4c6ea175)
(`#870`) is `status: ported`: ordinary `RemoteForward`, `DynamicForward`,
`SendEnv`, `RemoteCommand`, and related ssh_config behavior pass configuration
and real forwarding tests. Remote bind errors remain fatal; reverse SOCKS,
allocated remote port 0 and unsupported streamlocal bind policies are skipped
with warnings. See the README for environment and bootstrap isolation rules.

[`ca91fb5`](https://github.com/MisterTea/EternalTerminal/commit/ca91fb5d5eaccaa464f1106cb946586ebc7789f9)
(`#868`, including `#866` / `#862` / `#861`) is `status: ported`. A failed
initial connect exits after three attempts. A second `connect()` on the same
connection runs recover instead of installing sequence 0. The client still
reads catchup first.

[`044bcb5`](https://github.com/MisterTea/EternalTerminal/commit/044bcb5ae7960445a8bffb6fed4d3589f1aa8fc4)
(`#827` / `#448`) stays `status: skip` because et.rs already has equivalent
behavior: `terminal_pty` waits for the foreground child independently of PTY
EOF, bounds output draining, reports type 12 exit status, and kills the remaining
process group. A background descendant retaining the slave therefore does not
keep the session alive indefinitely. `PROTOCOL_VERSION` stays 6.

[`16aec0c`](https://github.com/MisterTea/EternalTerminal/commit/16aec0c1d49b24027057541c7bb0f967b077bc2f)
(`#828` / `#506`) is `status: ported`. The stable, secure agent proxy symlink
retargets on reconnect/reattach. Tests exercise different agents through the
same remote socket, rejected authentication and missing-directory recovery.
Saved attach uses current `SSH_AUTH_SOCK` and consistent `TMPDIR`; an absent
agent clears the stale link rather than upstream's old-link fallback.

[`568b7cc`](https://github.com/MisterTea/EternalTerminal/commit/568b7ccc043eb632462d6f51f8219f188c5a25a3)
(`#832` / `#660`) stays `status: skip`. Empty no-op close after `#833` already
fixed partial listen. Same skip as `#669`/`#833` (et.rs already probes IPv6).
`PROTOCOL_VERSION` stays 6.

[`662c332`](https://github.com/MisterTea/EternalTerminal/commit/662c332ba572364265ea84d350c4065b3dc3d52e)
(`#825` / `#425`) is `status: ported`. Remote Unix PTY sessions export their
actual PTY path as `SSH_TTY`; PTY and no-PTY tests pass.

[`f50f878`](https://github.com/MisterTea/EternalTerminal/commit/f50f878d21355e986a07582b4183f47a2ca309b7)
(`#823` / `#298`) stays `status: skip` with equivalent Rust evidence: per-stream
readers feed bounded queues and pending connection writes are asynchronous.
`PROTOCOL_VERSION` stays 6.

[`5b0f17a`](https://github.com/MisterTea/EternalTerminal/commit/5b0f17a56e2a664ce506f3266d7cf770561e55b6)
(`#819`) is `status: ported`. Unix `et --ctl` supports input, resize, output
cursors, status, redacted transcripts, tombstones and saved-session adoption.
Local kill retains an attachable remote shell; definite remote end removes
matching saved credentials, so the same name can bootstrap afresh. Tests cover
both paths, startup-command non-replay and replacement-ID preservation.
Raw `-T`/`-W` control and Windows local control are unsupported.

[`eb518af`](https://github.com/MisterTea/EternalTerminal/commit/eb518af9f06dc338660c020cdc11fc7bede7c35e)
(`#872`) stays `status: skip` with equivalent evidence where applicable:
`CLIENT_READ_BATCH=64` bounds server client reads, and forwarding uses bounded
per-stream reader queues plus asynchronous pending connection writes. The C++
platform split and `FdPoller` lifetime do not map to Rust. This does not claim
native macOS/Windows runtime or C++ live-peer testing. `PROTOCOL_VERSION` stays 6.

[`b5b009b`](https://github.com/MisterTea/EternalTerminal/commit/b5b009bf9ad91fda30eb2b394c6936c69e2b9806)
(`#874`, “keep VS Code Remote-SSH sessions alive over et across sleep”) is
`status: ported`. It shares #788's non-TTY EOF survival and SSH
diagnostic handling, including redirected Windows raw bytes. Linux heredoc and
reconnect tests pass; no actual VS Code sleep cycle, native Windows/macOS runtime
or live C++ peer was exercised in this port. `PROTOCOL_VERSION` stays 6.

[`ea2542f`](https://github.com/MisterTea/EternalTerminal/commit/ea2542fade29191703356e0abf00b78e72bb58e2)
(`#875`) stays `status: skip`. C++ mains testable (`MainEntry` split) plus
setup-failure CI coverage. C++ harness only; not et.rs wire.
`PROTOCOL_VERSION` stays 6.

[`a5e29af`](https://github.com/MisterTea/EternalTerminal/commit/a5e29afdf97b163cdc74331a58fbdb0514a466c5)
(`#873`) stays `status: skip`. Client setup failures throw instead of
`exit(1)`; `Connection` drops writes when no handshake writer (hang fix).
Product/reliability; et.rs already uses `Result` paths. No wire/auth change.
`PROTOCOL_VERSION` stays 6.

[`dc1dc63`](https://github.com/MisterTea/EternalTerminal/commit/dc1dc63dc6b6175168d4dbc52227608ed3cbc6d0)
(`#877`) stays `status: skip`. OpenWrt package installs
`et1`. Packaging/CI only. `PROTOCOL_VERSION` stays 6.

[`bcc28abc`](https://github.com/MisterTea/EternalTerminal/commit/bcc28abc39d5445bd6f80efe518c8e5fdae125c4)
(`#878` / `#769`) stays `status: skip`. SSH auth banners
show on the terminal after the stderr→log redirect (preserve original stderr).
Same product/UX family as `#843`/`#769`. Not wire/auth. Pin ≠ a claim that
every product backlog item is finished. `PROTOCOL_VERSION` stays 6.

[`5129342`](https://github.com/MisterTea/EternalTerminal/commit/5129342ef5ce3185125d907b95ad6d15a36b1cb6)
(`#876`) is the pin tip and `status: skip`. This README-only change documents
VS Code/Cursor Remote-SSH settings using upstream's installed `et1` wrapper.
et.rs does not package `et1`; copying that installation claim would be incorrect.
No runtime or wire change is required, and actual editor sleep-cycle verification
remains unclaimed.

et.rs still claims **protocol v6**. EternalTerminal’s latest product release is
**v7.0.0**, and the reviewed tip is seventy-seven classified commits past that tag.

Review ports against the conflict policy in
[`docs/upstream-factory.md`](upstream-factory.md). Gate any later port with
`cargo test --workspace` (especially `fixtures/wire.json`), not a GUI.
