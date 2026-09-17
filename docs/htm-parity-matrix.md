# Canonical HTM parity matrix

Source pin: EternalTerminal `8a306f6d3580886f77357864fc010a4e8b78c3a6`
(#805 + #813), rechecked against master and issues on 2026-09-17. No newer
HTM commit was present. This is the canonical implementation contract, **not
the full tmux manual**. The safety/platform policies below remain intentional.

Audit method: read the dispatcher, parser/writer, state, screen and lifecycle
branches at that pin; execute unmodified C++ ControlCommands, ControlMode,
MultiplexerState and PaneScreen against Rust. The command oracle substitutes
only a deterministic TerminalHandler and collecting SocketHandler; real PTY,
IPC and process behavior therefore has separate runtime tests. Only guard
timestamps/sequence numbers and implementation-specific C++ exception wording
are normalized. Successful reply bodies, error-vs-success decisions, layout
checksums and notification ordering are compared unchanged.

`control_oracle` runs a checked-in native-generated transcript by default (174
input records, including three key-encoding records and compound commands).
Setting `HTM_CONTROL_ORACLE` regenerates expected responses from canonical C++.
`upstream_parity` and `missing_targets` give focused regressions; `htm_runtime`
executes real roles/PTYs. This matrix is a production branch audit, not a claim
of 100% instrumented C++ branch coverage or every possible terminal byte stream.

| Canonical production branches | Implementation and automated evidence |
| --- | --- |
| ControlMode argument parser: quotes, literal backslash, empty quoted args, unterminated quotes/escape, ASCII whitespace, unquoted semicolon pass, all-separator fallback | `framing`; focused parser tests; native transcript |
| Flag parser: every command's value flags, grouped/attached/repeated flags, missing values, `--`, long-looking positional operands | `control::Args`; native transcript including bare `refresh -C` |
| Numeric parsing: signs, leading ASCII whitespace, decimal/hex prefix, trailing junk, platform unsigned-long width, invalid fallback | target helpers, `integer`, `encode_keys`; missing-target/native key records |
| Writer: server/client guard flags, sequence/time pairing, empty/multiline replies, error guards, deferred notifications, command-list error abort | `framing`, `server`; native transcript, runtime guard checks, tmux 3.4 probe |
| `display-message/display`: print/no-print, default/explicit format, valid/missing %/@/$ targets, active-session context even for a foreign pane | native transcript; missing-target regressions |
| `list-sessions/list-session/ls`, `list-windows/lsw`, `list-panes/lsp`: defaults, explicit formats, all-current-session panes, missing-ID fallback, parse-before-`-a`, `$0`, empty expansions | native transcript; missing-target regressions |
| `new-window/neww`, `split-window/splitw`: names, cwd, print/format, h/v precedence, source focus, same-axis append, orthogonal nested split, ignored creation flags/operands | native transcript; creation/geometry/PID tests; real PTY cwd/env tests |
| `kill-pane/killp`, `kill-window/killw`, `unlink-window/unlinkw`: missing/no-op, active/inactive/root/nested removal, final window/session, notification order | native transcript; state regressions; runtime final-pane exit |
| `send-keys/send`: hex/literal precedence, named Enter/Escape/Tab/Space/backspace/control keys, 0x tokens, signed/partial numeric conversion, invalid hex zero fallback | native key oracle; real shell input/output |
| `select-pane/selectp`: title vs focus; `select-window/selectw`; `rename-window/renamew`: explicit name disables automatic rename | native transcript; foreground command/automatic rename test |
| `resize-pane/resizep`: absent action/no-op, Z sentinel/toggle, x/y priority, zero/negative sizes, sole pane, nearest controlling axis, donor order, clamp, unchanged-size no notification, L/R/U/D immediate-parent behavior, zoomed rectangles | native transcript; asymmetric state tests; tmux split/resize probe |
| `resize-window/resizew`, `refresh-client/refresh -C`: default/client/window sizing, `@0` sentinel even if @0 is absent, x-before-comma parsing, minimum dimensions, malformed/missing values | native transcript; real PTY geometry |
| Refresh flags: f-before-F, repeated values, no-output, wait-exit, pause-after negative/zero/positive/off, unknown flags/subscriptions, repeated A gates including future IDs and unknown actions, continue notification | native transcript; missing-target future-gate test; runtime bootstrap/takeover |
| `capture-pane/capturep`: p/no-p, P+C pending, e/a/J/N/C, ranges/defaults, missing targets, octal escaping | native screen oracle (672 comparisons), capture regressions, native command transcript |
| `select-layout/selectl`: fewer than two panes, even-horizontal/vertical, main-horizontal/vertical, substring/fallback flattening, checked output | native transcript and state tests |
| `swap-pane/swapp`: same-ID/missing no-op; root-root, sibling, nested, cross-window; focus and zoom validity | native transcript and reparenting/PID regressions |
| `move-pane/movep/join-pane/joinp`: same/missing no-op; root/nested unlink, before/after insertion, same-axis/nested destination, source final-pane close, focus | native transcript and reparenting/PID regressions |
| `break-pane/breakp`: s/t/positional source precedence, missing-ID return0/display fallback, sole-pane no-op, split removal/new window, P/F | native transcript and missing-target tests |
| `move-window/movew`: missing no-op, same-session reorder, cross-session move, final source-session removal; `link-window/linkw` success-only | native transcript and focused session/window tests |
| Options: all set/show/window aliases, p>w>g>s>session scope, o/positional name, append/unset, q/v, non-@ no-op, absent stores, no implicit global fallback | native transcript and nested-format/option tests |
| `new-session/new`: detached/attached; `attach-session/attach`; `rename-session/rename`; `kill-session`: missing/no-op, final-window removal, attached-session fallback | native transcript and state/runtime regressions |
| `set-buffer/setb`, `show-buffer/showb`: named/default, missing/empty, replacement and notification | native transcript |
| `list-commands/lscm` exact response; `copy-mode`, `list-keys/lsk`, `list-clients/lsc`, `phony-command`, `clear-history/clearhist`; unknown command error | native transcript and frontend no-op tests |
| expand/expandOne: every canonical field, session-only @ lookup, q:, recursive truthy/false/absent conditionals, nested comma/braces, unmatched braces, absent objects | source field-by-field comparison; native/focused format tests |
| Tree geometry: n-ary weights, separator minimums, f32 rounding/remainder, parent collapse/renormalization, actual-pane dump geometry and checksum, visible zoom | native transcript; asymmetric state tests and tmux oracle |
| Affinities: nonempty session→global on detach, diagnostic session/global fallback, numeric/hex groups, suffix stripping/sorting; all-session pane headers, PID/cursor/current/text | focused affinity tests; authenticated diagnostic unit/runtime tests |
| PaneScreen: UTF-8, legacy title filter/BEL/ST/fragment states, libvterm callbacks, cursor/alt, history cap/continuation/clear, resize, first-codepoint cells, SGR and trailing-cell serialization | exact libvterm 0.3.3 guest; native differential; safety and release throughput tests |
| Server: initial-only topology and every-attach session notification, takeover, framing reset with flag/gate persistence, detach/blank/stale input, abrupt EOF, command error, kill-server, natural exit, final pane output, diagnostic delivery | server tests; seven real-role runtime scenarios; canonical transcript |
| Client: DCS/ST, Unix nonblocking descriptor restoration, final drain, wedged stdout, empty quoted command, Windows gateway/raw output, bounded reader/writer channels | client tests; real-role runtime; Windows linked tests |
| TerminalHandler: shell/env/initial dimensions, explicit/inherited live cwd, Linux/macOS foreground discovery, Windows descendants/cwd fallback, bounded input/output/history, stop/wait/reap/final output | focused process tests, real PTY runtime, workspace lifecycle tests; Windows cross-build |

## Source-backed quirks, not deferred commands

- Canonical ignores creation shell operands and detached creation flags;
  `link-window` and compatibility probes succeed without additional effects.
- `select-layout` builds even splits; it does not parse saved layout strings.
- IDs0 are valid targets, but #813 still uses zero as the **zoom** and refresh
  sentinels. Zooming %0 is a successful no-op. Refresh @0 sizes the current
  session's windows even after window0 has been removed.
- `dumpNode` serializes first/last descendant pane rectangles. Nested and
  zoomed layouts can therefore differ from stock tmux's idealized split bounds.
  The native oracle caught these differences; Rust now matches canonical bytes.
- `refresh -B`, positive pause timing and wait-exit have no additional machinery
  in canonical; accepted flags/state are preserved. Unknown A gates mean on.

## Preserved safety policies and platform verification

These are not missing command implementations: authenticated Windows IPC,
owned Unix paths, read-only authenticated diagnostic IPC instead of predictable
world-readable dumps, selected-daemon shutdown instead of broad reaping, Rust
memory safety, Wasm isolation, bounded frames/queues/resources, and bounded final
drain remain stronger. Invalid session attachment does not corrupt the attached
session before returning an error. Explicit and automatic name/error notifications are octal
escaped. Detached panes continue draining into their screen models.

The pre-merge review added `review_regressions`: expansion/list aggregation
rejects before exceeding 128 KiB, process names cannot inject control records,
and a screen resize trap cannot interrupt a cross-window ownership transfer.
Poisoned screens are reaped even without further PTY output. Windows token
admission now uses at most 16 nonblocking pending connections per endpoint and
an absolute one-second deadline; shared admission tests execute on Linux TCP
as well as compiling for Windows. Diagnostic reads use one absolute ten-second
deadline across both header and body. These safety fixes do not change ordinary
canonical transcripts or ET network protocol v6.

Native macOS process/cwd and native Windows ConPTY/console behavior need their
respective hosts. MinGW links the Windows artifacts on this runner. A local
Wine installation was attempted but could not initialize shell32/kernel32;
this is not a Windows runtime pass. Actual iTerm2/Ghostty/Hyper/WezTerm/Windows
Terminal GUI automation is unavailable here. Their bootstrap/affinity/recovery
protocol workflows are exercised by the native transcript and real-role tests;
canonical's 23 GUI snapshot-comparator unit tests also run without a GUI.
