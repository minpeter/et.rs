# Upstream pin

**This pin is the last *reviewed* EternalTerminal snapshot. It does not mean
et.rs has ported that snapshot.** Pin ≠ ported.

Canonical machine files:

- Pin (release tag/SHA, default-branch name, protocol versions, last classified tip):
  [`.github/upstream-pin.yml`](../.github/upstream-pin.yml)
- Ledger (every `master` commit after baseline):
  [`.github/upstream-ledger.yml`](../.github/upstream-ledger.yml)

Recorded 2026-08-21 from GitHub (`gh` / REST). Ledger classified 2026-10-14.
`#784` marked `ported` after et.rs [#31](https://github.com/minpeter/et.rs/pull/31) / `906a7ca86691f00a82f88b99b21d7afceb07bf97`.
`#798` marked `ported` after et.rs [#77](https://github.com/minpeter/et.rs/pull/77).

| Field | Value |
| --- | --- |
| Upstream | [MisterTea/EternalTerminal](https://github.com/MisterTea/EternalTerminal) |
| Baseline / latest release tag | [`et-v7.1.0`](https://github.com/MisterTea/EternalTerminal/releases/tag/et-v7.1.0) (moved from `et-v7.0.0` on 2026-10-28) |
| Baseline / release commit | [`0ea859f331db8b0d7d46e062f3ac99ff96476f78`](https://github.com/MisterTea/EternalTerminal/commit/0ea859f331db8b0d7d46e062f3ac99ff96476f78) |
| Default branch | `master` |
| Pin tip (last classified) | [`59dc173`](https://github.com/MisterTea/EternalTerminal/commit/59dc173f6369411827b748fd3b8baad989b031fe) (merge of #901, the 7.1.0 version bump, reviewed 2026-10-28) |
| et.rs wire version | **protocol v6** (`PROTOCOL_VERSION = 6` in `crates/et-core/src/lib.rs`, README) |
| ET wire version at this pin | still **protocol v6** (`PROTOCOL_VERSION = 6` in `src/base/Headers.hpp` on both `et-v7.1.0` and `master`) |

No `master` commits fall between the `et-v7.1.0` baseline and the reviewed tip. The ledger keeps all 133 commits classified between `et-v7.0.0` and `59dc173` as history; unclassified commits after the baseline would be drift. The product-parity ports below passed combined Linux verification: 824 tests passed, none failed, and two existing tests were ignored. Formatting, workspace clippy, Windows GNU/macOS ARM binary cross-checks, and release/AUR packaging checks passed. Real OpenSSH mux clients exercised the Rust master; no live C++ peer, native Windows/macOS runtime, or actual VS Code sleep cycle was tested in this port. `ported` covers the behavior described in each row, including its explicit limitations, not unrestricted product parity. Protocol remains v6.

## Ledger (classified 2026-10-12)

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
| [`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) | 2026-08-07 | product | **ported** | #788 non-TTY input EOF survival; diagnostics and Windows raw input tracked under #874 |
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
| [`99ac197`](https://github.com/MisterTea/EternalTerminal/commit/99ac1972c21f68c141d66f967ded231fc2903c7b) | 2026-09-25 | product | skip | #843/#769 equivalent foreground behavior: SSH inherits stderr; file logging does not redirect it |
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
| [`bcc28abc`](https://github.com/MisterTea/EternalTerminal/commit/bcc28abc39d5445bd6f80efe518c8e5fdae125c4) | 2026-10-01 | product | skip | #878/#769 logging never redirects process stderr; foreground SSH already inherits it; background -f intentionally detaches stdio |
| [`5129342`](https://github.com/MisterTea/EternalTerminal/commit/5129342ef5ce3185125d907b95ad6d15a36b1cb6) | 2026-10-02 | docs | skip | #876 README-only editor setup for upstream et1; et.rs does not package that wrapper or claim editor sleep-cycle verification. |
| [`b2adbfd`](https://github.com/MisterTea/EternalTerminal/commit/b2adbfd1846ddf0448a73a37f14d65b3a1a8ec3e) | 2026-10-05 | product | skip | #820 etctl client CLI drives local `et --ctl` Unix sockets (ControlProtocol IPC, same class as #819). et.rs already has that control surface. Help-text-only `--ctl-socket` path. Not wire/auth/server. |
| [`8f66739`](https://github.com/MisterTea/EternalTerminal/commit/8f667391875832fb5f7035936eb51e08da679bc0) | 2026-10-07 | ci | skip | #884 C++ build hygiene / `-Werror`. et.rs uses Rust Result paths and its own daemonize; nothing to port. PROTOCOL_VERSION stays 6. |
| [`8a92ea7`](https://github.com/MisterTea/EternalTerminal/commit/8a92ea76fc7b29c8316b924398b2c505d77177b1) | 2026-10-12 | product | **ported** | #880 replay recorded `session-bind@openssh.com` requests on forwarded agent connections and strip the agent's replies. Refusals are logged and tolerated. The recorder landed with #881; #879 still does not wire it into bootstrap ssh. PROTOCOL_VERSION stays 6. |
| [`f830e25`](https://github.com/MisterTea/EternalTerminal/commit/f830e25fc20b6d66de6fcb91e08dd6743808a29c) | 2026-10-09 | product | skip | #886 Windows console NUL modifier keys. No raw KEY_EVENT_RECORD path. |
| [`628ca71`](https://github.com/MisterTea/EternalTerminal/commit/628ca7111d6c2eb4a5c55daae269b4e383d84f36) | 2026-10-09 | product | skip | #886 layout follow-up for the same console records. |
| [`f6ed9fe`](https://github.com/MisterTea/EternalTerminal/commit/f6ed9fedef7d54242c18587649075e331d67e5b5) | 2026-10-09 | product | skip | #888 sorted Include globs. et.rs uses OpenSSH `ssh -G`. |
| [`e49d71f`](https://github.com/MisterTea/EternalTerminal/commit/e49d71f1089cec5c10f36b2bb96ac0a990798347) | 2026-10-10 | product | **ported** | #892 bound parked forwarding sockets and reject stale destination replies. |
| [`e6c3558`](https://github.com/MisterTea/EternalTerminal/commit/e6c355897b618a8c295b401e7e21c5c31b8799a4) | 2026-10-11 | docs | skip | #896 telemetry README. et.rs never collects telemetry. |
| [`f49c1bb`](https://github.com/MisterTea/EternalTerminal/commit/f49c1bb8f4b73b9534bdc90e7b51d9539aae54ef) | 2026-10-10 | product | **ported** | #892 bound incomplete SOCKS handshakes on dynamic forwards. |
| [`c758c95`](https://github.com/MisterTea/EternalTerminal/commit/c758c953e66a5e182d1ccb2f9982e81392a12918) | 2026-10-10 | product | **ported** | #893 preserve log-file identity during rotation. |
| [`1928401`](https://github.com/MisterTea/EternalTerminal/commit/19284011f415c67e15cbb5c590d33f4cd3075f66) | 2026-10-11 | product | skip | #893 telemetry storage out of shared tmp. No telemetry store. |
| [`fe377a4`](https://github.com/MisterTea/EternalTerminal/commit/fe377a419acead6d41759086677f92420bfef893) | 2026-10-11 | product | **ported** | #893 refuse unsafe daemon pid files and truncate stale contents. |
| [`c98e3f5`](https://github.com/MisterTea/EternalTerminal/commit/c98e3f5660680bed8f7eacc4b7b518d67add4ff3) | 2026-10-11 | product | **ported** | #893 check every ancestor of the etserver fifo directory. |
| [`63e7be9`](https://github.com/MisterTea/EternalTerminal/commit/63e7be9e50630a034cf20ca948f75e27dda13fa6) | 2026-10-01 | product | **ported** | #881 record the bootstrap ssh session-bind. #879 wiring is still open. |
| [`56d2e98`](https://github.com/MisterTea/EternalTerminal/commit/56d2e9804106e96e0543838e92eebab7e2c37adb) | 2026-10-12 | product | **ported** | #881 Windows named-pipe recorder. Not executed on Windows in this port. |
| [`e22996b`](https://github.com/MisterTea/EternalTerminal/commit/e22996bbc194e0c2a987d48cf41300c2c7fcacbc) | 2026-10-12 | product | skip | Disabled-telemetry identifier init. et.rs has no telemetry. |
| [`b0c72ed`](https://github.com/MisterTea/EternalTerminal/commit/b0c72ed5b418de14f0df2181e78232a30ce41d6b) | 2026-10-12 | ci | skip | #897 MSan coverage. |
| [`3130b52`](https://github.com/MisterTea/EternalTerminal/commit/3130b5256530c5c864585d2e64fb69289707072c) | 2026-10-12 | ci | skip | #897 git bootstrap in distro containers. |
| [`ad065d2`](https://github.com/MisterTea/EternalTerminal/commit/ad065d2d1d6383d225e0038dc153319ab38faeac) | 2026-10-12 | ci | skip | Merge #897. |
| [`4583d9d`](https://github.com/MisterTea/EternalTerminal/commit/4583d9d05881dc9a7089825e54cf80725c5fa5a0) | 2026-10-12 | docs | skip | Merge #896 telemetry docs. |
| [`0368025`](https://github.com/MisterTea/EternalTerminal/commit/03680253921a9c9444ebb5d6ce4542e0cfa2354a) | 2026-10-12 | product | **ported** | Merge #893. Telemetry storage skipped. |
| [`4c5508b`](https://github.com/MisterTea/EternalTerminal/commit/4c5508b6136d2037541624ffb28b2f2d7f74b854) | 2026-10-12 | product | skip | Merge #888. |
| [`3142f87`](https://github.com/MisterTea/EternalTerminal/commit/3142f879eb4b06bb1d30ed407e25bff4f5402a7c) | 2026-10-12 | product | skip | Merge #886. |
| [`c8116ac`](https://github.com/MisterTea/EternalTerminal/commit/c8116ac75aedebf9f6d4eac69248b24fab0301db) | 2026-10-12 | product | **ported** | Merge #892. |
| [`026b451`](https://github.com/MisterTea/EternalTerminal/commit/026b45162fe60a6c704528b32360d18dea332333) | 2026-10-10 | ci | skip | #894 QEMU interpreter registration. |
| [`64173c4`](https://github.com/MisterTea/EternalTerminal/commit/64173c449c728e03366b27172f2f9b0be1934107) | 2026-10-10 | ci | skip | #894 pin third-party actions. |
| [`9a82ff4`](https://github.com/MisterTea/EternalTerminal/commit/9a82ff470a9af83e8db5a12318df8ba286a347b5) | 2026-10-12 | ci | skip | #894 FreeBSD ccache 4. |
| [`ade24de`](https://github.com/MisterTea/EternalTerminal/commit/ade24de1df69b9bd1cad8bafe51f928556f40bfa) | 2026-10-10 | product | **ported** | #895 iterative tmux control prelude. |
| [`ed6067e`](https://github.com/MisterTea/EternalTerminal/commit/ed6067e5a39c66fdce61f302ba15bf429957581d) | 2026-10-10 | product | skip | #895 linear OSC 133 scan. No OSC parser in et.rs. |
| [`d5025c2`](https://github.com/MisterTea/EternalTerminal/commit/d5025c2df0176981e5eb6a69603378970a218a9e) | 2026-10-12 | ci | skip | Merge #894. |
| [`dd15b2b`](https://github.com/MisterTea/EternalTerminal/commit/dd15b2b119a2e29f070c73491e9afd7ce19a2359) | 2026-10-12 | product | **ported** | Merge #895. OSC scan skipped. |
| [`e02aefa`](https://github.com/MisterTea/EternalTerminal/commit/e02aefa2301a9544fe7a40564e612dcf122291e1) | 2026-10-12 | product | **ported** | Merge #881 recorder. #879 wiring not ported. |


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
responses ahead of queued pane output. The interrupt drain-discard
(`drainDiscardReadableBytes`, `drainDiscardJumphostTerminalBuffers`) was missing
until et.rs 0.0.47; see "Benchmark round 2" below. Live output sockets set
upstream's 32 KiB `TCP_NOTSENT_LOWAT` on Linux and keep a bounded send buffer
(1 MiB requested on Linux, 256 KiB elsewhere).
The connected staging queue is capped at 2 MiB (1 MiB per lane), and the bridge
stops reading terminal output at 256 KiB staged, rather than upstream's 16 MB `WriteBuffer`:
it only has to keep the bounded transport send buffer fed, and a larger cap just
keeps more stale, interruptible output resident in etserver.
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

[`b74a12e`](https://github.com/MisterTea/EternalTerminal/commit/b74a12efc567dbc1360ac0846f889c945a2eba60) (`#788`) is `status: ported`:
non-TTY input EOF no longer ends the session. SSH diagnostic phrasing and the
Windows redirected-byte input path are tracked under `#874`. Linux heredoc and
input tests pass; redirected Windows input lacks native runtime coverage.
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
(`#843` / `#769`) stays `status: skip`: foreground `SystemSsh` already inherits
stderr, and file logging never redirects that descriptor. Background `-f`
intentionally detaches stdio rather than displaying interactive auth banners.

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

The local-control regression test follows upstream's
[`AppendAfterRead`](https://github.com/MisterTea/EternalTerminal/blob/eac0d1d892bd09ec9f6dffe8ab9f8b7195315f6f/test/unit_tests/SessionScrollbackTest.cpp#L68-L81)
contract: reads do not consume history, and appended output follows previously
read bytes. It now forces output between two full snapshots and checks prefix
preservation, replacing a suffix assertion that raced normal PTY output.
This is a test correction; Rust history and cursor behavior are unchanged.

Upstream's [`MuxProtocol`](https://github.com/MisterTea/EternalTerminal/blob/eac0d1d892bd09ec9f6dffe8ab9f8b7195315f6f/src/terminal/MuxProtocol.cpp#L126-L155)
bounds individual waits rather than total transfer throughput. The Rust-only
6 MB slow-passenger test now uses a 15-second no-progress watchdog plus a
60-second total cap, retaining exact byte-count and exit-status checks; its
former 15-second total cap expired on hosted macOS after 5–5.77 MB of output.

[`eb518af`](https://github.com/MisterTea/EternalTerminal/commit/eb518af9f06dc338660c020cdc11fc7bede7c35e)
(`#872`) stays `status: skip` with equivalent evidence where applicable:
`CLIENT_READ_BATCH=64` bounds server client reads, and forwarding uses bounded
per-stream reader queues plus asynchronous pending connection writes. The C++
platform split and `FdPoller` lifetime do not map to Rust. This does not claim
native macOS/Windows runtime or C++ live-peer testing. `PROTOCOL_VERSION` stays 6.

### Windows transport follow-up (et.rs #134)

The original #823/#872 equivalence claim omitted Windows live writes. Reviewed
[#823](https://github.com/MisterTea/EternalTerminal/pull/823) and
[#872](https://github.com/MisterTea/EternalTerminal/pull/872) before this fix:
#823 bounds each forwarding update to four 16 KiB reads; #872 supplies the
Windows nonblocking socket and `WSAPoll` implementation. Upstream's
[`BackedWriter`](https://github.com/MisterTea/EternalTerminal/blob/eb518af9f06dc338660c020cdc11fc7bede7c35e/src/base/BackedWriter.cpp)
and [`Connection`](https://github.com/MisterTea/EternalTerminal/blob/eb518af9f06dc338660c020cdc11fc7bede7c35e/src/base/Connection.cpp)
still finish the entire write while holding the connection mutex. That part
does not solve the reported head-of-line blocking.

Rust now shares its existing pending-frame contract between Unix and Windows:
one send of at most 64 KiB per advancement, permanent nonblocking Winsock mode,
and bounded client producer/read batches. The server prepares under the
connection mutex, sends outside it, and retains `write_serial` through completion
so recovery installation cannot race the old writer. A safe `winapi-wsapoll`
wrapper preserves `unsafe_code = "forbid"`; bootstrap/recovery synchronous I/O
waits for readiness without toggling another socket clone back to blocking.
These are deliberate Rust adaptations, not a copy of the C++ locking loop.

The Windows pump retains the next producer's preference across pending writes:
a local-input batch yields to forwarding, and a forwarding batch yields to
local input. This adapts #823's bounded-yield intent to retained frames. A
native Windows regression fails with the old preference reset and passes with
alternation, verifying forwarding runs before the next queued input frame.

Review follow-up: capped `WSAPoll` intervals retain the caller's absolute
deadline. The PID-path test now checks each platform's existing default;
upstream Windows uses its temporary directory while Rust keeps the existing
relative `etserver.pid`. This follow-up changes no PID-path runtime behavior.

Replay accepts each frame once before live transmission, with unchanged nonce
and sequence ordering. A failed partial frame shuts down its old transport;
recovery sends the complete replay record before later live traffic. Deadlines
remain absolute: two seconds normally, five with flow control. Final close
follows retained data, and redirected stdin EOF does not end the remote session.

Native Windows loopback tests cover stalled forwarding with inbound dispatch,
server output with independent reverse-direction reads, concurrent
2 MiB/3 MiB transfers, EOF, final-close ordering, replay after partial writes,
and deadline expiry. The Windows runtime harness also starts the shipped server
and terminal, transfers 16 MiB in each direction through a real TCP forward,
checks every echoed byte, and verifies source and destination EOF. Its client
is a protocol test pump; the actual Windows client pump has separate stalled
forwarding coverage. The executables are cross-built for Windows GNU on Linux
and **executed on Windows**, separately from cross-checking. No C++ live peer,
editor sleep cycle, or native macOS execution is claimed. Windows CI now runs
these transport/session/client tests in addition to ConPTY and HTM coverage.

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
(`#878` / `#769`) stays `status: skip`: et.rs logging never redirects process
stderr, so preserving a pre-redirect descriptor is unnecessary. Foreground SSH
inherits stderr; background `-f` intentionally detaches it. `PROTOCOL_VERSION`
stays 6.

[`5129342`](https://github.com/MisterTea/EternalTerminal/commit/5129342ef5ce3185125d907b95ad6d15a36b1cb6)
(`#876`) stays `status: skip`. This README-only change documents
VS Code/Cursor Remote-SSH settings using upstream's installed `et1` wrapper.
et.rs does not package `et1`; copying that installation claim would be incorrect.
No runtime or wire change is required, and actual editor sleep-cycle verification
remains unclaimed.

[`b2adbfd`](https://github.com/MisterTea/EternalTerminal/commit/b2adbfd1846ddf0448a73a37f14d65b3a1a8ec3e)
(`#820`) stays `status: skip`. It adds a client-side `etctl`
CLI that drives local `et --ctl` sessions over the Unix control socket
(`ControlProtocol` IPC, same class as `#819`). et.rs already has that local
control surface. The only `et` change is help text for the default
`--ctl-socket` path (`~/.et/control/<name>.sock`). No wire, handshake, auth,
crypto, server, or `PROTOCOL_VERSION` change.

[`8f66739`](https://github.com/MisterTea/EternalTerminal/commit/8f667391875832fb5f7035936eb51e08da679bc0)
(`#884`) is `status: skip`. It fails the C++ build on
compiler warnings (`-Werror`), reads the package version from `vcpkg.json`,
replaces the deprecated `daemon()` call, and checks ignored `chdir` /
`read` / `write` / `system()` results plus nodiscard protobuf
`SerializeToString`. Vendored headers stay out of `-Werror`. et.rs uses
Rust `Result` paths and its own daemonize; nothing to port. No `.proto`,
`Headers.hpp`, wire, handshake, auth, or crypto change. `PROTOCOL_VERSION`
stays 6.

[`8a92ea7`](https://github.com/MisterTea/EternalTerminal/commit/8a92ea76fc7b29c8316b924398b2c505d77177b1)
(`#880`, part 1/3 of OpenSSH agent session binding) is `status: ported`. The
client replays recorded `session-bind@openssh.com` requests on each new
connection to the stable `et-agent-<id>` proxy and strips exactly one agent
reply per bind. `SSH_AGENT_FAILURE` and `SSH_AGENT_EXTENSION_FAILURE` are
logged and tolerated.

[`e02aefa`](https://github.com/MisterTea/EternalTerminal/commit/e02aefa2301a9544fe7a40564e612dcf122291e1)
is the pin tip, reviewed 2026-10-13. Twenty-nine commits after `#880` are
classified. Ported behavior:

- `#892` parks at most 128 forwarding sockets for 30 seconds and closes a
  destination whose reply names a token that is no longer parked. Incomplete
  dynamic-forward SOCKS handshakes are capped at 64 and closed after 30
  seconds.
- `#893` truncates the open log inode on rotation, refuses unsafe daemon pid
  files, and checks every ancestor of the etserver directory. Telemetry
  storage is skipped because et.rs has no telemetry.
- `#895` keeps a mid-line tmux control prelude in one loop, including a large
  backlog. The OSC 133 scanner is skipped because et.rs has no OSC parser.
- `#881` records the last non-forwarded bootstrap session-bind on a private
  proxy, including a Windows named pipe. At this earlier pin, `#879` had not
  yet handed that proxy to bootstrap ssh. The 2026-10-14 classification below
  ports that wiring.

`#886`, `#888`, `#894`, `#896`, `#897`, and `e22996b` are ledger skips.
`PROTOCOL_VERSION` stays 6. No live C++ peer was tested.

et.rs still claims **protocol v6**. EternalTerminal’s latest product release is
**v7.0.0**, and the reviewed tip is one hundred nine classified commits past that tag.

### Single-loop runtimes (et.rs performance work, 2026-10-19)

Reviewed against upstream master
[`7eb237e`](https://github.com/MisterTea/EternalTerminal/commit/7eb237e6d9822b674f4a527924b5f09117659321).
Upstream `UserTerminalHandlerUnix.cpp` drives the PTY master, the command's
stderr and the router from one `select()` loop with a 10 ms timeout and one
16 KiB `read` per wakeup; `TerminalServer::run` polls every listener and the
router from one loop (100 ms) and expires unclaimed resumes there;
`PortForwardHandler::update` runs from the terminal loop's `select()`.

et.rs now follows that single-loop shape with these deliberate differences:

- Linux `etterminal` (PTY and `-T` pipes) learns about the shell's exit from a
  pidfd in the same `poll(2)` set, so there is no 10 ms tick or `waitpid`
  probing; kernels without `pidfd_open` keep the threaded runtime, as do
  macOS (whose `poll` is unreliable on PTYs) and Windows.
- PTY reads continue while the master returns full `N_TTY_BUF_SIZE - 1`
  reads and are sent as one local `TERMINAL_BUFFER` of up to 32 KiB; upstream
  sends one frame per read.
- Forwarding moves onto the session thread only after the session loop first
  polls it; before that (and on Windows) the forwarding worker thread runs the
  same engine.
- `etserver` runs one `et-runtime` control thread: on Linux and macOS it accepts
  on all TCP listeners, serves the terminal router (registrations, startup
  status, terminal hang-ups) and applies terminal lifecycle events in one
  `poll(2)`, and sweeps resume expiry once a second only while a resumed
  terminal is registered. Windows keeps a separate router thread.

No wire, handshake, crypto or `PROTOCOL_VERSION` change.

### Local router stream (et.rs 0.0.44)

Reviewed against upstream master
[`7ee361a`](https://github.com/MisterTea/EternalTerminal/commit/7ee361a75fbb3e0900445b110188996fbe950823).
Upstream
[`TerminalServer::runTerminal`](https://github.com/MisterTea/EternalTerminal/blob/7ee361a75fbb3e0900445b110188996fbe950823/src/terminal/TerminalServer.cpp)
writes `TERMINAL_INIT` to `etterminal` as a length-prefixed packet, then each
client `TERMINAL_BUFFER` and `TERMINAL_INFO` as the type byte followed by
`writeProto` (a native `int64` length and the protobuf), and `TERMINAL_CLOSE`
as the bare type byte; the disconnect timeout and
`UserTerminalRouter::closeTerminal` write the same byte.
[`UserTerminalHandler::runUserTerminal`](https://github.com/MisterTea/EternalTerminal/blob/7ee361a75fbb3e0900445b110188996fbe950823/src/terminal/UserTerminalHandlerUnix.cpp)
and `runIdleSession` read that stream. Everything `etterminal` writes stays a
length-prefixed packet. `runJumpHost` sends the client an empty
`INITIAL_RESPONSE` itself, then `JUMPHOST_INIT`, and relays length-prefixed
packets both ways;
[`UserJumphostHandler::run`](https://github.com/MisterTea/EternalTerminal/blob/7ee361a75fbb3e0900445b110188996fbe950823/src/terminal/UserJumphostHandler.cpp)
consumes the destination's `INITIAL_RESPONSE` and exits on its error.
`UserTerminalRouter::registerTerminal` closes a refused registration without
writing.

et.rs 0.0.43 and older wrote every router message as a length-prefixed packet
and handed the destination `INITIAL_RESPONSE` back through the jump terminal,
so an et.rs `etserver` could not serve a C++ `etterminal`, or the reverse.
et.rs now writes and reads upstream's stream (`et_net::local_packet::RouterFraming`):

- A C++ peer gets upstream's stream and jumphost flow, and no
  `REGISTRATION_STATUS`, `STARTUP_STATUS` or refusal packet.
- et.rs peers still negotiate the et.rs-only registration acknowledgement
  (`<router>.cap` marker, `fd = -6` sentinel) and the jumphost
  `INITIAL_RESPONSE` relay. A terminal also sets the et.rs-only
  `TerminalUserInfo.upstream_router_stream` (tag 1000, far from upstream's
  sequential tags), and the server confirms the upstream stream with a second
  success byte. et.rs 0.0.43 and older peers do neither and keep
  length-prefixed router messages, so their live sessions survive an upgrade
  restart in either order. A terminal re-checks the marker whenever it
  re-registers, so a session also survives `etserver` switching between et.rs
  and C++.
- Local messages, registrations and `TERMINAL_INIT` environments are accepted
  as upstream accepts them; see the next section.

Three bugs surfaced in the live check and are fixed with it:

- The router waited for a `STARTUP_STATUS` from an et.rs pty that
  re-registered after an `etserver` restart. Such a pty never sends one, so
  the router read the resumed session's first output itself: the output was
  lost, or the client printed `malformed terminal output` and reconnected a
  second time. A new `etterminal` also answers the startup check of et.rs
  0.0.43 or older when it re-registers (next section), so only a 0.0.43
  `etterminal` restarting into a 0.0.43 `etserver` still has this race.
- `et --jumphost` gave the jump terminal its provisional `XXX` credentials.
  Upstream `SshSetupHandler::SetupSsh` gives it the pair the destination
  `etterminal` answered with, which an ET C++ `etterminal` regenerates.
- The jump terminal's relay waited for socket readiness before forwarding
  destination output that its read of the destination `INITIAL_RESPONSE` had
  already buffered, so the first output could wait for a keypress. et.rs
  connections read the socket ahead; upstream's `BackedReader` reads exact
  lengths and never holds a second packet.

Live check (2026-10-20, loopback, ET-C++ built from
[`7eb237e`](https://github.com/MisterTea/EternalTerminal/commit/7eb237e6d9822b674f4a527924b5f09117659321);
`7eb237e..7ee361a` changes none of these files). "Before" is et.rs 0.0.43.

| Session | Server-side mixes | Before | After |
| --- | --- | --- | --- |
| PTY shell: input, resize, 200 KB paste | et.rs and C++ clients; et.rs `etserver` + C++ `etterminal`, C++ `etserver` + et.rs `etterminal` | fail | pass |
| `-T` with 1 MiB of stdin, exit status | et.rs client; both mixes | fail | pass |
| `-W` | et.rs client; both mixes | pass | pass |
| `--jumphost`, C++ jump and destination terminals behind an et.rs jump server | et.rs and C++ clients | fail | pass |
| `--jumphost`, et.rs terminals behind a C++ jump server | et.rs and C++ clients | pass | pass |
| `etserver` restart under a live session | 0.0.43→new with 0.0.43 and new terminals, C++→new, new→C++, new→new | — | pass |
| et.rs 0.0.43 peer | new `etserver` + 0.0.43 `etterminal`, 0.0.43 `etserver` + new `etterminal` | — | pass |

No network wire, handshake, crypto or `PROTOCOL_VERSION` change.

### Local limits, environment and `-T` stdin EOF (et.rs 0.0.44)

Reviewed against upstream master
[`7ee361a`](https://github.com/MisterTea/EternalTerminal/commit/7ee361a75fbb3e0900445b110188996fbe950823).
Upstream `SocketHandler::readPacket` takes a local packet of up to 128 MiB and
`readProto` a router protobuf of up to `DEFAULT_MAX_PROTO_LENGTH` (128 MiB);
`UserTerminalRouter` refuses a registration over `MAX_REGISTRATION_LENGTH`
(4096 bytes); `UserTerminalHandler::run` calls `setenv` for every
`TERMINAL_INIT` entry and ignores failures.

- et.rs accepts the same: `MAX_LOCAL_PACKET_LEN` is 128 MiB and
  `MAX_REGISTRATION_LEN` 4096 bytes. Readers grow their buffer as bytes arrive,
  like upstream's network `BackedReader`, instead of allocating a declared
  length up front (upstream's `readPacket` allocates it). `etterminal` applies
  any number of variables of any length and skips only entries `setenv`
  rejects; 0.0.43 failed the session on more than 128 entries, a value over
  4096 bytes or a name outside `[A-Za-z_][A-Za-z0-9_]*`, and the server could
  not write a `TERMINAL_INIT` over 64 KiB.
- The `et` client keeps its own limits (128 variables, 4096-byte values,
  portable names, a 64 KiB `TERMINAL_INIT`) because every et.rs `etserver` and
  `etterminal` through 0.0.43 accepts that; upstream's client has none.
- `-T` goes beyond upstream, like `ssh -T`: when the client's stdin ends it
  sends one `TERMINAL_BUFFER` whose `buffer` is present and empty, and an et.rs
  pipe `etterminal` closes the command's stdin after the input before it.
  Upstream's `TerminalClient` never sends an empty buffer (it skips empty
  reads), its `etserver` relays this one unchanged, and its `etterminal` and
  et.rs 0.0.43 append nothing for it, so no protobuf field is needed. With a
  C++ client or terminal the command keeps reading.
- A new `etterminal` that re-registers with et.rs 0.0.43 or older (bare success
  status) sends `STARTUP_STATUS` at once, so that server's router stops
  waiting before the resumed session's output arrives.

Live check (2026-10-21, same setup; "Before" is main at
[`e572fa3`](https://github.com/minpeter/et.rs/commit/e572fa3)):

| Session | Mixes | Before | After |
| --- | --- | --- | --- |
| C++ client, `SendEnv` of a 70000-byte value, 200 variables and `ET-DASH` | et.rs `etserver` and/or et.rs `etterminal` | fail | pass |
| `et -T host 'wc -c'`, 1 MiB of stdin, then EOF | et.rs client and `etterminal`, et.rs or C++ `etserver` | hangs | pass, exit status 3 |
| Same | C++ client or C++ `etterminal` | hangs | hangs (no upstream signal) |
| `etserver` restart from the new build into 0.0.43 | et.rs client and new `etterminal` | flaky | 6 of 6 pass |

No network wire, handshake, crypto or `PROTOCOL_VERSION` change.

### Input typed while reconnecting, and wider mixed coverage (et.rs 0.0.44)

Upstream
[`TerminalClient::run`](https://github.com/MisterTea/EternalTerminal/blob/7ee361a75fbb3e0900445b110188996fbe950823/src/terminal/TerminalClient.cpp)
keeps reading the console while disconnected and queues each keystroke in the
`BackedWriter`, so recovery replays it to the shell. The et.rs client waits
between reconnect attempts reading stdin only to see Ctrl-C (its own "press
Ctrl-C to give up", from et.rs #14) and dropped every other byte. It now keeps
them and sends them after recovery, in order after input read before the
outage and before newer input. Ctrl-C still gives up.

Live check (2026-10-21, loopback; a TCP relay between client and `etserver`
cuts the link and refuses reconnects for about 3 s). Each row ran with et.rs
and C++ clients against et.rs and C++ servers (the terminal matches the
server) unless noted:

| Session | Before | After |
| --- | --- | --- |
| Output during the outage (35 lines) replayed once, in order | pass | pass |
| Command typed during the outage runs after recovery | fail with the et.rs client, pass with the C++ client | pass |
| 20 s idle: keepalives only, no reconnect, then input works | pass | pass |
| `--name`, client killed, `--attach`: same shell PID | pass | pass |
| `-D` SOCKS5 CONNECT, 256 KiB echoed | pass | pass |
| `-L`/`-R` 8 MiB each way and a 64-byte round trip, every client/`etserver`/`etterminal` mix | pass | pass |

### Forward-only session throughput and spilled upload tails (et.rs 0.0.46)

Upstream
[`TerminalClient::run`](https://github.com/MisterTea/EternalTerminal/blob/7ee361a75fbb3e0900445b110188996fbe950823/src/terminal/TerminalClient.cpp#L535-L556)
runs every client mode, `-N` included, from one loop. Each turn it polls the
transport and every forwarded socket with a 10 ms cap, so forwarding wakes on
readiness. In et.rs, `-N`, `-M` and `--ctl` sessions run the local session
pump (`crates/et-bin/src/local_session.rs`). That pump sent one forwarding
packet per turn. A started write did not count as progress, so the turn ended
in a fixed 5 ms sleep, which capped every `-N` forward at about 64 KiB / 5 ms.
The pump now counts a started write as progress. An idle turn waits in
`poll(2)` on the transport (read while it can take packets, write while a
frame is pending) and on the forwarding wake (while it can take an outbound
packet). The 5 ms cap stays because local IPC, the passenger and timers are
still serviced on that cadence. Interactive sessions already polled
forwarding descriptors through the session engine and are unchanged.

Upstream writes forwarding data synchronously from `PortForwardHandler::update`
and has no outbound queue between the forwarder and the session, so the second
fix has no upstream counterpart. The et.rs forwarding worker thread parks
packets that do not fit the 256-packet outbound channel in a spill queue. It
retried the spill only when a socket or command event woke it. With a peer
that advertises no window (ET C++), one bulk upload fills the spill. Once the
local application went quiet, no further event arrived, and the spilled tail
(up to 256 packets, about 16 MiB) never reached the transport. Before
sleeping, the worker now publishes `spill_pending`. The session's next pop
from that channel force-wakes the worker. Windowed et.rs peers bound
per-socket in-flight data, but enough parallel sockets could reach the same
state.

Live check (2026-10-21, loopback, release build, 512 MiB per run; ET C++ is
master 7ee361a built with upstream's vcpkg defaults):

| `-N -L` upload, client → server | Before | After |
| --- | --- | --- |
| et.rs → et.rs | 12 MiB/s | 557–620 MiB/s |
| et.rs → ET C++ | stalled 16 MiB short of the end | 467–507 MiB/s |
| ET C++ → et.rs | 342–366 MiB/s | 342–365 MiB/s |
| ET C++ → ET C++ (reference) | 341–370 MiB/s | — |

`-N -L` downloads (256 MiB) went from 150 to 431 MiB/s for et.rs → et.rs. For
et.rs → ET C++ they stayed at about 300–320 MiB/s. Interactive `-L` sessions
measured 537–563 MiB/s (et.rs server) and 385–398 MiB/s (ET C++ server)
before and after. The per-socket credit window (`WINDOW_BYTES`) was not a
limit at these rates and is unchanged.

No wire, handshake, crypto or `PROTOCOL_VERSION` change.

### Recovery without waiting for client traffic (et.rs 0.0.46)

Upstream
[`ServerConnection::clientHandler`](https://github.com/MisterTea/EternalTerminal/blob/7ee361a75fbb3e0900445b110188996fbe950823/src/base/ServerConnection.cpp#L105-L238)
verifies a returning client's `ConnectAuth` proof (#793). It then runs
`recoverClient` (sequence and catchup exchange) and resumes at once. Legacy
peers without the challenge capability are not authenticated at all. After
every recovery, `etserver` waited for one live packet that decrypts under the
session key (`Connection::authenticate_peer`) before it installed the new
stream. Upstream clients send nothing live after recovery until the user
types or the next keepalive arrives. Their input typed during the outage
travels in the catchup, not as live traffic. So an ET C++ client got no
terminal output for 5.1–6.0 s after each reconnect: terminal output stayed in
the recover hold, and the replayed keystrokes waited too.

The server now skips that wait in two cases:

- The challenge already verified the passkey (`PeerProof::Handshake`). This
  matches upstream.
- A legacy peer's catchup was non-empty. `BackedReader::revive` decrypts every
  catchup packet under the session key, which is the same proof.

Only a legacy peer with an empty catchup still waits for its first live
packet. That is stricter than upstream, which trusts legacy peers outright,
and is an intentional difference.

The et.rs client also authenticates recovery with the server's first live
packet and requeues it. Upstream's client keeps no such wait. The packets
after it often arrive in the same segment and then wait in the reader with
no socket readability left. The client loop slept on the socket until its
next keepalive deadline (5 s by default). This happened in about one
reconnect in five, against both servers. The loop now treats packets
already decoded in the reader as ready input
(`crates/et-bin/src/client_terminal_loop.rs`). `et -N` and `--ctl` sessions
read every turn and were not affected.

Live check (2026-10-22, loopback, load average 40–57; a TCP relay between
client and `etserver` resets the connection, then one key is typed and timed
until it echoes):

| Client → server | Before | After |
| --- | --- | --- |
| ET C++ → et.rs (15 resets) | 5085–6021 ms, median 5701 | 111–305 ms, median 187 |
| et.rs → ET C++ (15 resets) | 4 of 15 took 5068–5143 ms | 15–120 ms, median 100, none slow |
| et.rs → et.rs (15 resets) | 2 of 15 took 5017–5019 ms | 11–113 ms, median 26, none slow |
| ET C++ → ET C++ (reference) | 103–198 ms | 129–240 ms |

No wire, handshake, crypto or `PROTOCOL_VERSION` change.

### Benchmark round 2 (et.rs 0.0.47)

A cross-implementation benchmark (et.rs 0.0.46, ET C++ master
[`7ee361a`](https://github.com/MisterTea/EternalTerminal/commit/7ee361a75fbb3e0900445b110188996fbe950823),
OpenSSH 10.2p1) found the gaps below. Each fix was reviewed against the cited
upstream code. Protocol v6 and the generated wire fixtures are unchanged.

**Terminal output over a WAN, Ctrl-C and echo under a flood.**
- The rest of `#804` is now ported: `drainDiscardReadableBytes` and
  `drainDiscardJumphostTerminalBuffers` (`TerminalServer.cpp:82-99,289-302,570-596`,
  `TerminalInterruptDrain.hpp:21-51`).
  - When client input carrying an interrupt flushes at least 64 KiB of unsent
    output, the bridge (Unix, Windows and jumphost) first reads the terminal
    output already waiting on the terminal socket, plus the packets it holds.
    It drops every droppable byte, then writes the interrupt to the terminal.
  - Exit status and other non-output packets keep their order.
  - Intentional difference: one drain reads at most 1 MiB. Upstream drains until
    the socket is empty, which a fast producer could stretch indefinitely.
- The client drops its unpainted console queue on every interrupt, as
  `TerminalClient::run` does with `filterDroppable` (`TerminalClient.cpp:581-584`).
  Before, it only did so above 64 KiB.
- On Linux, live output sockets set `TCP_NOTSENT_LOWAT` to 32 KiB, like
  `TcpSocketHandlerUnix.cpp:10-24`.
  - Intentional difference: they also request a 1 MiB `SO_SNDBUF`, through
    `SO_SNDBUFFORCE` when privileged; upstream sets no send buffer.
  - Why: upstream's own output loop runs at about 5 MB/s, so it never fills a WAN
    path. With an autotuned buffer, et.rs queued up to 10 MB that Ctrl-C could not
    drop, and Ctrl-C at RTT 50 ms took up to 1.1 s.
  - The former 256 KiB cap held RTT 50 ms output to about 6.3 MB/s; with 1 MiB it
    measured 13.8 MB/s, with the Ctrl-C median at 63 ms (max 72 ms).
  - Other platforms keep the 256 KiB cap: socket2 exposes `TCP_NOTSENT_LOWAT`
    only on Linux.
- The connected bridge reads at most 256 KiB of terminal output ahead.
- Client connections read at most 64 KiB per socket read, like upstream's
  `BackedReader`.
- Measured result: keystroke echo during a flood went from 58 to 18 ms.

**Replay history.**
- Upstream `BackedWriter` keeps 64 MiB (`BackedWriter.hpp:32`) and trims only at
  that cap.
- et.rs trimmed the connected backup to 8 MiB / 32,768 packets even when the peer
  had not received those packets. A client whose stdout was blocked for about
  10 s, with a large kernel receive buffer, then fell "too far behind server" on
  reconnect and lost the session.
- Now only *acknowledged* history is trimmed to 8 MiB / 32,768 packets.
  Unacknowledged packets go only at upstream's 64 MiB / 262,144-packet hard cap,
  so peers that never acknowledge (ET C++ clients) get upstream's retention exactly.

**Dead-link detection.**
- This follows upstream `TerminalClient::run` (`TerminalClient.cpp:468-469,687-698`).
  One keep-alive interval after the last packet read, the client sends a probe. If
  the probe is still unanswered one interval later, it reconnects.
- That is two intervals (10 s by default) instead of et.rs's former three. It is
  shared by the Unix, Windows and local-session (`-N`/`-M`/`--ctl`) loops in
  `crates/et-bin/src/keepalive_clock.rs`.
- Intentional differences:
  - Any packet read answers the probe. Upstream clears `waitingOnKeepalive` only
    on a keep-alive reply.
  - Sending never moves the deadline. Upstream restarts it at `:580,:611,:725,:731`,
    so typing into a dead link could postpone the probe and the verdict.
- As before, no verdict is taken while held console output stops transport reads.
- Reconnect pacing stays as upstream's: a 3 s connect timeout plus a 1 s retry
  sleep (`TcpSocketHandler.cpp:90`, `ClientConnection.cpp:276`).

**Keep-alive acknowledgements.**
- The 8-byte delivery ack (et.rs-only) now rides only on keep-alives where it is
  news (`et_core::keepalive::AckSchedule`):
  - the first keep-alive of each connection, including the recovery proof;
  - the first one after any non-keep-alive packet;
  - every `ACK_RETAIN_FLOOR_PACKETS` keep-alives;
  - volume acks.
- etserver attaches it only after its client has acknowledged. So ET C++ peers
  get upstream's empty `KEEP_ALIVE` (`TerminalServer.cpp:603-608`) from etserver,
  and from `et` after its first keep-alive.

**Forward-only sessions.**
- `et -N`, `-M` and `--ctl` now serve forwarding from the session loop, as upstream
  `TerminalClient::run` does from one PollSet (`TerminalClient.cpp:540-556,718-734`).
  - The local session pump takes the forwarding worker over on its first poll.
  - It drains up to 128 outbound packets per turn.
  - It sends acknowledging keep-alives every 512 KiB and applies the client
    delivery gate.
- The 5 ms idle cap is gone. The pump polls its IPC listeners, peers, passenger
  and a signal-hook wake pipe, and sleeps until readiness or its next timer.
- Intentional differences:
  - An attached passenger still caps the wait at 5 ms, because its terminal size
    is sampled, not signalled.
  - During a transport outage, forwarding keeps accepting and reading up to the
    engine backlog, but nothing goes to replay until recovery.
- Loopback results:
  - 64 B round trip p50: 207 → 163 µs.
  - Idle wakeups: about 195/s → 0.4/s.
  - A single 512 MiB upload now runs on one core, the same limit as interactive
    `-L` sessions, and peaks about 8% lower.

**Port-forward window (et.rs-only; upstream has no per-socket window).**
- Each forwarded socket advertises a 4 MiB / 127-packet window, up from
  2 MiB / 63. It returns credit every eighth of the window (512 KiB or 15 packets).
- The per-socket output queue has 128 slots, as do the writer and committed
  channels in the Windows threaded model.
- This sizes the window for a 50 ms bandwidth-delay product; the old window held
  a single `-N -L` upload to about 23 MiB/s on that link.
- `decode_window` clamps peer windows to ours, so older et.rs peers interoperate
  unchanged.

**Idle-session memory (Linux, et.rs-only).**
- ET C++ uses glibc malloc and never trims.
- In et.rs, the session bridge and the per-session terminal loops (PTY and `-T`)
  use `et_server::idle_memory::IdleRelease`:
  - After 1 s without I/O, a loop disables its jemalloc thread cache, which
    flushes and frees it. The single-threaded terminal process also purges dirty
    pages.
  - A lone keep-alive afterwards is handled without the cache, so idle sessions
    get no extra wakeups. Two events within 1 s re-enable it.
- The shipped jemalloc no longer enables its `stats` feature, which only tests use.
- With 50 idle loopback sessions, per-session USS went from 836 to 676 KiB. ET C++
  measured 1239 KiB.
- Summed RSS is dominated by shared binary and libc pages and does not reflect
  per-session cost.

**Session end delivers the last output.**
- The server side follows upstream `TerminalServer::finishSession`
  (`TerminalServer.cpp:868-910`).
  - Before: `etserver` closed the client socket as soon as `finish_terminal` had
    queued the last output and `TERMINAL_EXIT_STATUS`. A client keep-alive arriving
    at the closed socket made the kernel send RST, which discarded the unsent tail,
    so `et -T` exited 0 with a short stdout.
  - Now, like upstream (which holds the connection up to 1 s after terminal EOF),
    the server keeps the half-closed transport open for up to 1 s, reading and
    dropping client bytes, and closes as soon as the client closes.
  - Client traffic does not extend the wait, so a relay that does not pass on the
    half-close cannot hold the session open.
- The client fix follows upstream `BackedReader`, which never peeks on write and
  only reports EOF from a read.
  - Before: `et`'s write-path probe (`Connection::refresh_connectivity`) discarded
    complete packets already read when it saw the peer's EOF.
  - Now it only invalidates the writer; the reader returns those packets, then EOF.
- Results: on a loaded host, 500 MB `et -T` transfers lost their tail in 40 of 800
  runs before, and in 0 of 800 after.

### Benchmark round 3 (et.rs 0.0.47)

A second run of the same benchmark (et.rs `7b1303f`, the same ET C++ build and
OpenSSH) still showed et.rs behind ET C++ on echo during a flood, recovery after a
stalled client, Ctrl-C on 10 Mbit and lossy links, and idle keep-alive bytes. Each
fix was reviewed against the cited upstream code. Protocol v6 and the generated
wire fixtures are unchanged. Numbers are same-session 5- or 8-run medians on a
netns veth pair with `tc netem`.

**Merged terminal output.**
- `etserver` merges queued terminal output into `TerminalBuffer` packets of up to
  16 KiB, following upstream `drainWriteBufferToClient` (`TerminalServer.cpp:23-62`,
  `BUF_SIZE` at `TerminalServer.cpp:15`).
  - Before: each short terminal read went out as its own segment (73% under
    1448 B during a `yes` flood, against 4% for ET C++). Linux grew the client's
    receive buffer to about 9 MB, and every keystroke echo waited behind it.
  - Packets already being written are never merged, and stdout and stderr stay
    in separate packets.
- Echo during a flood, p50/p95: 21.4/55.2 → 6.4/49.1 ms (ET C++ 7.1/149.3).

**Paused clients stay connected.**
- With flow-control output buffering, a frame stuck on a closed TCP window now
  outlives its 5 s live-write deadline for as long as the peer keeps sending. That
  means the reader sequence moves, or unread bytes arrive on the socket. The frame
  fails after 10 s of silence (`FLOW_CONTROL_PEER_SILENCE`).
- While console output holds its socket reads, the client re-sends a keep-alive
  whenever the previous one goes unanswered.
- Intentional difference: upstream never times out such a write
  (`TerminalServer.cpp:36`). et.rs keeps a bound so a vanished client is still
  dropped, now within 10 s instead of 5 s.
- Recovery after the client stops reading for 10 s: 108.8 → 13.3 ms (ET C++
  82.9). Server memory growth during the stall: 14.5 → 0.2 MiB.

**Ctrl-C on a flooded client socket.**
- On Ctrl-C the client applies upstream's server-side `drainDiscardReadableBytes`
  (`TerminalInterruptDrain.hpp:21-52`) to its own socket. Terminal output in the
  bytes already queued when the interrupt is typed is filtered like `consoleOut`
  (`filterDroppable`).
  - It only applies above upstream's 64 KiB `flushIfLarge` threshold. It keeps
    non-terminal packets such as exit status, and never touches output sent after
    the interrupt.
  - Intentional difference: upstream's client only filters `consoleOut`
    (`TerminalClient.cpp:574-592`).
- Output shown after Ctrl-C: 207 → 47 KB (ET C++ 31 KB). The rest is mostly
  output the client had already written to its local terminal.

**Ctrl-C on slow and lossy links.**
- `etserver` starts an output frame only when the client socket polls writable,
  as upstream's `drainWriteBufferToClient` checks `isSocketWritable` before each
  packet (`TerminalServer.cpp:36`).
  - A packet without room goes back to the front of the queue unsequenced, so the
    interrupt flush can still drop it.
  - Before: the loop wrote until `EAGAIN`. That left 25–65 KB unsent in the
    kernel, plus one partly written, sequenced frame, behind every Ctrl-C.
  - Output that waits a whole live-write timeout for room starts its frame with
    that deadline already due, so a stuck transport is still bounded.
  - Cost: RTT-50 output 14.8 → 13.8 MB/s (ET C++ 5.5). Without the check, 10 Mbit
    and lossy Ctrl-C fell behind ET C++.
- `etterminal` sends 16 KiB packets, upstream's `BUF_SIZE`
  (`UserTerminalHandlerUnix.cpp:295`).
- The Linux `etterminal` pauses PTY reads after forwarded input that interrupts
  the foreground job, while output is pending. That input is VINTR, VQUIT or
  VSUSP with ISIG on and NOFLSH off. The pause lasts until the foreground process
  group changes, at most 10 ms.
  - Upstream gets this implicitly: it reads one chunk per `select()` pass and
    doesn't wake when the router has room, so its PTY stays full and the kernel's
    interrupt flush applies at once (`UserTerminalHandlerUnix.cpp:391`).
  - Without the pause, 25–290 KB of a flood written after Ctrl-C reached
    `etserver`, against 4.4 KB with the C++ `etterminal`.
- On an interrupt that flushed queued output, the Unix bridge now reverses
  upstream's order. This supersedes the round-2 description above for Unix.
  - It records the bytes waiting on the terminal socket (`FIONREAD`), writes the
    interrupt, then drops at most those bytes, counting whole packets.
  - Upstream drains the socket first, then writes the interrupt (`runTerminal`,
    `TerminalServer.cpp:570-596`).
  - Everything dropped was emitted before the terminal could read the interrupt.
    Anything written after it (echo, prompt, exit status) is never dropped, with
    either `etterminal`.
  - Windows keeps upstream's order: a safe byte count there would need `peek`.
- Ctrl-C to prompt, 8 runs: 10 Mbit / 50 ms 535 → 464 ms (ET C++ 465); lossy
  (`delay 75ms loss 0.5%` each way) about 430 → 162 ms (ET C++ 257).
- Lossy-link 1 MB output was bimodal for every implementation, ET C++ included
  (slow in 11 of 25 rounds against 9 of 25 for et.rs). Packet captures show
  congestion-window collapse after an early loss, not an et.rs stall.

**Keep-alive cadence.**
- Upstream `TerminalClient::run` sends a probe when `keepaliveTime < time(NULL)`,
  after setting `keepaliveTime = time(NULL) + keepaliveDuration`
  (`TerminalClient.cpp:687-688`).
  - The comparison is strict and in whole seconds. An idle upstream client
    therefore probes every keepalive + 1 s (6.000 s apart by default) and declares
    the link dead after two such steps (12 s).
  - et.rs probed every 5.005 s: 12 instead of 10 identical 242-byte exchanges a
    minute.
- `crates/et-bin/src/keepalive_clock.rs` now sends the probe keepalive + 1 s after
  the last packet read, and keeps the verdict two intervals after that read (10 s).
  It moves the probe earlier when that would leave the reply less than 1 s, so
  `--keepalive 1` still probes every second.
- The interactive loop no longer caps its sleep at one interval when the clock has
  a later wake.
- Intentional differences: the verdict is 2 s sooner than upstream's, any packet
  read answers the probe, and writes never move the deadline.
- Idle interactive and `-N -L` sessions: 2904 → 2420 B/min, the same as ET C++,
  measured after a 20 s settle. A shorter settle also counts the one-off teardown
  of et.rs's private SSH ControlMaster (`ControlPersist=15`). Idle wakeups:
  0.6 → 0.5/s. Recovery after a 10 s silent outage: 1.13 → 1.10 s.

**Output window for acknowledging clients.**
- When the terminal drains slower than the link, the client stops reading its
  socket. Linux then autotuned the client's receive queue to 4–20 MB
  (`TcpExtPruneCalled` 560 per 10 sessions), and every keystroke echo waited
  behind it: echo during a `yes` flood was at ~40 ms in about 30% of sessions.
- On Unix, `etserver` now holds queued terminal output while an et.rs client has a
  whole window of it unacknowledged (`et_core::output_window`).
  - The window is the client's 512 KiB acknowledgement interval plus twice the
    path's bandwidth-delay product, at least 512 KiB more (1 MiB on a local
    link), capped at 16 MiB.
  - The rate comes from acknowledgement timing. The round trip is the
    authentication challenge's, and write-to-acknowledgement samples can only
    lower it.
  - It reads the keep-alive delivery acknowledgements (et@0.0.8, sent by volume
    since et@0.0.36). No wire or `PROTOCOL_VERSION` change.
  - Held output stays unsequenced in the queue, so the interrupt flush still
    drops it. Control packets and forwarded data never wait and don't count.
  - It arms only after the client has read one of the server's acknowledgements
    and then acknowledged with a whole window outstanding. ET C++ clients and
    et.rs before 0.0.36 keep the previous behavior.
  - It lifts while the session loop isn't reading the client, and releases
    after an acknowledgement has been stuck for 10 s, until one advances.
  - The Windows server is not gated: its writer thread has no wake on an
    acknowledgement.
- Intentional difference: upstream has no application-level window.
  `drainWriteBufferToClient` (`TerminalServer.cpp:23-62`) writes one `BUF_SIZE`
  (`:15`) packet per `isSocketWritable` check and runs near 5 MB/s, so the
  client's queue stays short.
- Echo during a `yes` flood, 30 sessions: sessions with p50 ≥ 15 ms went from
  5/30 to 0/30; pooled p95 34.1 → 11.9 ms (ET C++ 32.3). Throughput is unchanged
  at a 50 ms round trip (13.8 MB/s) and at 1 Gbit / 100 ms.
- Output merging stays at upstream's 16 KiB: 32 KiB gave the same echo with more
  output after Ctrl-C.

**No dead-link verdict while server data waits unread.**
- A keep-alive probe whose reply deadline passed while console output held socket
  reads produced a reconnect on the first loop turn after output resumed, before
  anything was read. The reconnect then timed out behind the paused terminal and
  the session ended. With 60 KiB output packets this happened in 4 of 5
  slow-client runs.
- Upstream `TerminalClient::run` refreshes its keep-alive deadline only on reads
  and stops reading while `consoleOut` is full, so it has the same exposure.
- et.rs treats unread server data, in the socket or already buffered by the
  reader, as proof the peer is alive. A silent socket still gets a verdict after
  the same reply window.

**Residual gaps, with cause.**
- Lossy link (`delay 75ms loss 0.5%`), Ctrl-C to prompt: 8 same-session runs gave
  a 242 ms median against 190 ms for ET C++, and both had runs at ~300 ms.
  - The slow runs are TCP head-of-line blocking: a segment lost ahead of the
    prompt holds it for one retransmission.
  - et.rs has more in flight at Ctrl-C (cwnd 60–728 against 22–411), which is also
    why its WAN output is 2.6× faster.
  - Bounding in-flight data would trade away that throughput, so it is left as is.
- Output shown after Ctrl-C: the remaining gap is the 6–17 KB already in the local
  pty. et.rs's output keeps up with the reader; upstream's slower output leaves
  the pty nearly empty. Upstream's console write path (`TerminalClient.cpp:668-677`)
  is the same as et.rs's.
- Idle traffic: the last 70 B/min seen in some benchmark windows was a kernel IPv6
  router solicitation on the test veth, hitting both implementations. et.rs's
  only extra idle cost is the 8-byte delivery acknowledgement on one keep-alive
  exchange in 16, about 10 B/min.

### Remaining-gap round (et.rs 0.0.47)

A 5-run mean benchmark of every metric left two gaps with room to improve: the
lossy-link `-N -L` upload and server CPU while streaming terminal output. Protocol
v6 and the generated wire fixtures are unchanged.

**Window credit in batches or per drained burst.**
- et.rs-only, since upstream has no per-socket window. The Unix forwarding engine
  returned a quiet socket's window credit after 50 ms, so each small
  request/response exchange cost a credit packet each way.
  - Thirty 64-byte round trips sent 61 segments each way, where ET C++ and OpenSSH
    send 30.
  - Upstream returns nothing for delivered data (`PortForwardHandler::handlePacket`,
    `PortForwardHandler.cpp:329-363`; `PortForwardData` has no window field,
    `ETerminal.proto:72-80`).
- Credit now returns in two cases, neither on a timer:
  - Once an eighth of the window the peer sends with has drained: 512 KiB or 15
    packets for current peers, an eighth of a smaller peer window otherwise.
  - As soon as a socket's queue drains after it has written out at least 16 KiB,
    one full upstream read (`ForwardSourceHandler::update`, 16 KiB buffer).
  - A sender that filled its window always has a whole batch pending once that
    window is delivered. Thirty 64-byte round trips now send 32 segments each way.
  - The Windows threaded engine keeps its idle return.
- Why a drained burst still returns credit at once:
  - The credit packet carries the receiver's TCP ACK and the window freed by
    reading the burst. Linux announces a window freed by an application read only
    once it has doubled (`tcp_cleanup_rbuf`).
  - With batch-only credit, a new connection's sender waited one round trip on the
    stale window after every burst. Receive autotuning, measuring with the next
    burst already queued, kept the buffer at 128 KiB for several round trips
    (bpftrace of `tcp_rcv_space_adjust`).
  - An RTT-50 32 MiB `-N -L` upload fell to 24–26 MiB/s in about half the runs
    (15-run mean 28.5 against 33.7). With the drained-burst credit it is 34.5
    (min 33.1).
- Lossy link (`delay 75ms loss 0.5%`): a loss among the extra exchange packets cuts
  the client's ssthresh to about 7.
  - Every 2 MiB upload after such a cut ran at 0.12–0.24 MiB/s, against a 0.90
    median otherwise.
  - The benchmark's 30 forward round trips before its upload cut ssthresh in 33.8%
    of 145 sessions before and 16.2% of 142 after (Fisher p = 0.001). ET C++ and
    OpenSSH: 13.8% of 29.
  - With the round trips, 20-run 2 MiB medians were 0.59 MiB/s (et.rs), 0.54
    (ET C++) and 0.66 (OpenSSH).
- The rest of the lossy upload gap was noise.
  - Without the round trips, 30-run 2 MiB medians were 0.99 MiB/s (et.rs), 1.00
    (ET C++) and 0.75 (OpenSSH). 10-run 32 MiB medians were 0.26, 0.29 and 0.24.
  - The client socket held 0.6–2.4 MB unsent throughout, so CUBIC under loss sets
    the rate, not et.rs.
- Unshaped 256 MiB `-N` upload (804 against 809 MiB/s) and new-connection, SOCKS
  and reverse throughput are unchanged.

**PTY reads until empty.**
- Upstream `UserTerminalHandlerUnix.cpp` reads the PTY master once per `select()`
  pass (`BUF_SIZE` 16 KiB) and sends one `TERMINAL_BUFFER` per read (`:295-296,394`).
- The Linux `etterminal` now reads until `EAGAIN` or a full 16 KiB frame.
  - Before, it stopped at the first short read. On an idle host a fast producer
    arrives in short reads, so a 101 MB `cat` crossed to `etserver` as ~46,000
    frames (mostly under 4 KiB) instead of ~6,800 mostly full ones.
  - A loop pass whose input set an interrupt hold does not read the PTY.
- Server CPU for a 101 MB loopback `cat`: 1.42 → 0.96 s (OpenSSH 1.11, ET C++
  2.39). Wire bytes per output byte: 1.045 → 1.021 (ET C++ 1.036). Echo during a
  flood, Ctrl-C and paste are unchanged.
- A 64 KiB `etserver` read-ahead on the terminal socket was tried and dropped: it
  raised echo during a flood from ~6 to ~30 ms. The frame size, the per-packet
  transport-room check and the Ctrl-C drain are unchanged.

## Ledger (classified 2026-10-14)

Twenty commits after [`e02aefa`](https://github.com/MisterTea/EternalTerminal/commit/e02aefa2301a9544fe7a40564e612dcf122291e1).
`PROTOCOL_VERSION` stays **6**. None of these commits change protobuf field
numbers or the encrypted frame layout. The recovery `CatchupBuffer` acceptance
limit moves from 80 MiB to **144 MiB** so a full upstream 64 MiB connected
history plus 64 MiB disconnect buffer, with protobuf overhead, is not rejected.
That is a size limit, not a new wire type. Upstream #891 (protocol 7) is still
open and is not ported.

| sha | date | kind | status | note |
| --- | --- | --- | --- | --- |
| [`9a987f7`](https://github.com/MisterTea/EternalTerminal/commit/9a987f7116bf596e3137aa70e7c65d495ff55b12) | 2026-10-01 | product | **ported** | #879 recorder is the bootstrap ssh `IdentityAgent` |
| [`4545da5`](https://github.com/MisterTea/EternalTerminal/commit/4545da51aed065801162dd9f02a81374284e2e66) | 2026-10-10 | security | **ported** | #890 frame length bounds and short ciphertext |
| [`bbd2c5f`](https://github.com/MisterTea/EternalTerminal/commit/bbd2c5fda81731e22b84e71371a0b2cc4d89a9da) | 2026-10-10 | security | skip | #890 malformed router packets already reject locally |
| [`fd4e166`](https://github.com/MisterTea/EternalTerminal/commit/fd4e166236c6852f614b9e6966ac267a68d358b8) | 2026-10-10 | product | skip | #890 no blocked Windows handler thread before `TERMINAL_INIT` |
| [`7d70aa2`](https://github.com/MisterTea/EternalTerminal/commit/7d70aa2c7a33bd4805d90429762ec7330fe52855) | 2026-10-10 | security | **ported** | #890 kernel peer credentials own the router session |
| [`46319d9`](https://github.com/MisterTea/EternalTerminal/commit/46319d9e9302b459b57ee18e4d1a58dfb5d0c785) | 2026-10-10 | security | **ported** | #890 malformed session packets reconnect, daemon stays up |
| [`f37750d`](https://github.com/MisterTea/EternalTerminal/commit/f37750d54c85160dfe0a2266719f03c31448532f) | 2026-10-10 | security | skip | #890 silent router peers already cannot block accept |
| [`eecfdb3`](https://github.com/MisterTea/EternalTerminal/commit/eecfdb3b6f970ed69df1d629214f6a8d14e929a4) | 2026-10-10 | security | skip | #890 bad passkeys already cannot reach crypto init |
| [`c0e36f2`](https://github.com/MisterTea/EternalTerminal/commit/c0e36f21ea5967d10a3e4cd937a418e3057fc6b1) | 2026-10-10 | security | **ported** | #890 accept exhaustion and 64 pending handshakes |
| [`9c69c81`](https://github.com/MisterTea/EternalTerminal/commit/9c69c810bcd66d6f4948a7b667e6285f72ab96c7) | 2026-10-10 | security | **ported** | #890 proto bodies allocate as bytes arrive |
| [`c87998a`](https://github.com/MisterTea/EternalTerminal/commit/c87998af7e2fb20d4ed722755c17397794c47c1b) | 2026-10-10 | security | skip | #890 pane dumps are not written to a shared temp file |
| [`e3e49d5`](https://github.com/MisterTea/EternalTerminal/commit/e3e49d5ea176f0c4c6ee2dd325b8d9a823d65b36) | 2026-10-10 | security | **ported** | #890 144 MiB catchup limit and revive trim |
| [`9d65d62`](https://github.com/MisterTea/EternalTerminal/commit/9d65d6273ce05ccb68cad1fcb9670dfd374de0d1) | 2026-10-10 | security | skip | #890 no HTM client pid file to follow |
| [`d884fbd`](https://github.com/MisterTea/EternalTerminal/commit/d884fbd17fb585ad1d18f0b55233bb74e2a708a3) | 2026-10-12 | security | **ported** | #898 `--attach` refuses unchallenged success |
| [`4f28887`](https://github.com/MisterTea/EternalTerminal/commit/4f288879dcb0666526a75a0c1e0f9a742dab5cd8) | 2026-10-10 | security | skip | #890 no pid-file SIGKILL cleanup |
| [`de5dbd9`](https://github.com/MisterTea/EternalTerminal/commit/de5dbd9b9df68a7fbd1813adad9eff871d8a50bf) | 2026-10-11 | security | **ported** | #890 nonce moves only after authentication |
| [`f8a3b18`](https://github.com/MisterTea/EternalTerminal/commit/f8a3b184260cf8d570d524611aa6378e498f1563) | 2026-10-10 | security | **ported** | #890 both ends of Unix HTM control check peer uid |
| [`f2a332d`](https://github.com/MisterTea/EternalTerminal/commit/f2a332d813817ce0c4fdf8190aeea6c229bb7307) | 2026-10-13 | security | **ported** | Merge #898 |
| [`6185ea3`](https://github.com/MisterTea/EternalTerminal/commit/6185ea3bf7b45ff1f88bab376b6c0d35e49c90a1) | 2026-10-13 | security | **ported** | Merge #890 |
| [`7eb237e`](https://github.com/MisterTea/EternalTerminal/commit/7eb237e6d9822b674f4a527924b5f09117659321) | 2026-10-13 | product | **ported** | Merge #879 |

Ported behavior at this tip:

- `#890` rejects framed lengths outside `[2, 128 MiB]`, grows protobuf bodies
  64 KiB at a time, accepts catchup up to 144 MiB, and trims writer history on
  revive. Decrypt rolls the nonce back when Poly1305 fails, and the client
  reconnects. Unix router registrations store kernel credentials. At most 64
  handshakes are in flight, and descriptor exhaustion pauses accept. Unix HTM
  drops a control peer whose uid is not the daemon's.
- `#898` makes `et --attach` (`reset_intent`) refuse an unchallenged
  `NEW_CLIENT` or `RETURNING_CLIENT`. A fresh session still accepts a legacy
  server.
- `#879` runs bootstrap ssh with `-oIdentityAgent=<recorder>
  -oControlMaster=no` and replays the recorded binds, jumphost first.

Skipped because et.rs already has the property or does not have the C++ path:
malformed router packets, silent router peers, passkey length, HTM temp-file
dumps and pid files, and the Windows pre-`TERMINAL_INIT` thread join.

Review ports against the conflict policy in
[`docs/upstream-factory.md`](upstream-factory.md). Gate any later port with
`cargo test --workspace` (especially `fixtures/wire.json`), not a GUI.

## Ledger (classified 2026-10-20)

Two commits after [`7eb237e`](https://github.com/MisterTea/EternalTerminal/commit/7eb237e6d9822b674f4a527924b5f09117659321).
`PROTOCOL_VERSION` stays **6**.

| sha | date | kind | status | note |
| --- | --- | --- | --- | --- |
| [`8caa1e8`](https://github.com/MisterTea/EternalTerminal/commit/8caa1e8c1ca833c094ac43837a9bb1272126dca0) | 2026-10-16 | product | **ported** | #900 plain `%` lines are not tmux -CC |
| [`7ee361a`](https://github.com/MisterTea/EternalTerminal/commit/7ee361a75fbb3e0900445b110188996fbe950823) | 2026-10-19 | product | **ported** | Merge #900 |

Upstream `WriteBuffer` latched control mode on any line starting with `%`, so
`top` (`%Cpu(s)`) and csh `%` prompts were reordered after Ctrl+C. #900 arms it
only on the `ESC P 1000 p` introducer or a known control token. et.rs
`TerminalStream` already worked that way (`plain_percent_lines_do_not_enter_tmux_control_mode_or_reorder_output`,
from upstream report #899); the port adds the remaining piece: a plain `%exit`
line no longer arms control mode. One difference is kept: inside control mode
et.rs leaves at the ST that follows `%exit` rather than at `%exit`, so a Ctrl+C
flush between the two cannot drop the terminator
(`dcs_introducer_and_exit_transition_tmux_control_mode_cleanly`). The
`etterminal` wall filter already enables itself only on the introducer.

Live interop smoke (2026-10-20, et.rs 0.0.42 against an ET-C++ `master` build,
loopback): an et.rs client with C++ `etserver`/`etterminal`, and a C++ client
with et.rs `etserver`/`etterminal`, both ran a PTY command stream and `-L`/`-R`
tunnels. Mixing implementations within one host's server pair (et.rs
`etserver` with C++ `etterminal`, or the reverse) failed there because the
local router stream used et.rs framing; et.rs 0.0.44 speaks upstream's stream
(see "Local router stream" above).

## Ledger (classified 2026-10-28)

Two commits after [`7ee361a`](https://github.com/MisterTea/EternalTerminal/commit/7ee361a75fbb3e0900445b110188996fbe950823).
`PROTOCOL_VERSION` stays **6**.

| sha | date | kind | status | note |
| --- | --- | --- | --- | --- |
| [`d43b348`](https://github.com/MisterTea/EternalTerminal/commit/d43b34844d6bcb22c56a18a8bf6fbbb388c5b7b9) | 2026-10-27 | other | skip | #901 project version 7.1.0, Debian changelog, release docs |
| [`59dc173`](https://github.com/MisterTea/EternalTerminal/commit/59dc173f6369411827b748fd3b8baad989b031fe) | 2026-10-27 | other | skip | Merge #901 |

Packaging and release-process only. No wire, handshake, or security change.

**Release baseline moved to `et-v7.1.0`.** The tag points at
[`0ea859f`](https://github.com/MisterTea/EternalTerminal/commit/0ea859f331db8b0d7d46e062f3ac99ff96476f78)
on upstream's `release` branch, which contains `master` through `59dc173`.
- Beyond `master` it adds only release-branch merges and the vendored
  `external_imported/` tree (299 files), plus one `CMakeLists.txt` line pointing
  `EXTERNAL_DIR` at it. None of this is product code.
- Every pull request listed in the 7.1.0 release notes (#771–#901) is already a
  ledger row. That includes the breaking short-option remap (#867), which et.rs
  ported earlier.
- `PROTOCOL_VERSION` is still 6 on `et-v7.1.0`.
- The ledger `baseline_sha` and `.github/upstream-pin.yml` now name
  `et-v7.1.0` / `0ea859f`. Rows before it stay as classification history.
