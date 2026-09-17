# HTM control-mode synchronization

The migration targets canonical EternalTerminal [#805](https://github.com/MisterTea/EternalTerminal/pull/805)
and [#813 / 8a306f6](https://github.com/MisterTea/EternalTerminal/commit/8a306f6d3580886f77357864fc010a4e8b78c3a6),
not the intermediate #805 merge. Master and current issues were rechecked on
2026-09-17. The [production parity matrix](htm-parity-matrix.md) records the
command/state/screen/lifecycle branches and their source-backed tests. This is
canonical HTM compatibility, not a claim to implement every tmux command.

## Architecture

`htm` owns DCS `ESC P 1000 p` and final ST `ESC \\`. Protected local IPC carries
tmux command/reply/notification bytes after Windows authentication. The retired
UUID/JSON/base64 protocol is gone; ET network protocol v6 is unchanged.

`htmd` owns sessions, windows, ordered n-ary split trees, PTYs and pane screens.
Initial identities are session `$1`, window `@0`, pane `%0`. Attach replaces the
selected daemon's old frontend without killing its shells. A flags-0 reply
block precedes initial topology/session notifications. Every command has a
matching flags-1 reply or error; notifications follow the completed block.
CR/LF/CRLF, quoting, command lists, grouped/attached flags and canonical numeric
prefix parsing are supported. Errors stop the rest of their command list.
Detach/empty arguments end the frontend without a reply block. Flag/gate state
survives reconnect, matching canonical `recover()`.

Canonical libvterm 0.3.3 runs in an import-free Wasm instance through safe Rust
`wasmi`. It retains 2,000 history rows and reproduces canonical PaneScreen cell,
SGR, range, wrapping, alternate-screen and title-filter semantics. Capture
supports p/t/S/E/e/a/J/N/C and empty pending P+C; recovery captures actual pane
screens rather than replaying an arbitrary byte tail. See [screen provenance
and bounds](../crates/et-htm/screen-guest/README.md).

## Command and diagnostic parity

All canonical command families and aliases are implemented: discovery/display,
creation, selection, names/titles, absolute/directional/window resize, zoom,
select-layout, pane swap/move/join/break, window move/link/unlink, sessions,
send-keys, capture, scoped user options, buffers, refresh flags/gates, detach,
kill-server and frontend compatibility probes. Missing IDs are handled by each
command's canonical lookup/fallback/no-op rule, not a global existence check.

Some deliberately narrow upstream behaviors are important:

- Creation shell operands and several creation flags are ignored upstream.
  `link-window` and compatibility probes are successful no-ops.
- `select-layout` flattens to even splits; saved-layout parsing is not present
  upstream. Checksums and serialized layouts match canonical, including its
  first/last-descendant bounds for nested and zoomed trees.
- IDs0 are real targets, but canonical still treats %0 as the no-zoom sentinel
  and refresh @0 as client-wide sizing. `$0` list-windows falls back to the
  attached session. These quirks are independently checked against C++.
- Refresh subscriptions, positive pause timing and wait-exit have no extra
  machinery upstream; their accepted command/state behavior is retained.

Session `@affinities` persists verbatim globally at detach. Native/hex affinity
groups and every pane's window/name/ID/PID/current/cursor/screen snapshot are
available through:

```sh
et htm --socket /private/path/htm.ipc --dump-panes
```

This never starts a daemon or takes over the frontend. The daemon binds a
second endpoint with `.diagnostic` appended, using the **same** private Unix
path checks or authenticated Windows transport. Responses have a bounded
status/length header, one retained snapshot, and a two-second nonblocking send
deadline. There is no predictable public dump file or signal-triggered secret
disclosure. This replaces canonical's diagnostic delivery mechanism, not its
pane/affinity snapshot format.

Shells are non-login, use `TERM=screen`, clear `PROMPT_EOL_MARK`, and start at
the current client dimensions. Explicit cwd and live Linux/macOS source cwd
are supported; Windows uses its initial-cwd fallback. Automatic names follow
foreground processes until explicit rename disables them.

## Preserved protections

- Windows loopback IPC requires its token before any state/output; endpoints
  stay under LOCALAPPDATA with reparse-point checks and exclusive lifetime locks.
  Each endpoint admits at most 16 pending nonblocking token handshakes with an
  absolute one-second deadline. A slow unauthenticated peer cannot stall PTYs.
- Unix endpoints use an owned 0700 directory and 0600 sockets. Explicit socket
  parents must be private. Files/symlinks are not removed as stale sockets.
- `htm -x` stops only the selected daemon. No broad process-name killing or
  upstream macOS same-UID reaper is copied. Old private-protocol daemons must
  be stopped using the old binary before upgrade.
- Command/reply/queue limits remain 64/128/256 KiB. PTY channels are bounded.
  Format expansion and list aggregation enforce the reply limit before append,
  not after allocating the complete expanded response.
  Saturated input returns an error; a stalled frontend disconnects while its
  shells/screens survive. Final output/ST gets a bounded 250ms best-effort drain.
- Geometry is limited to 512×256, with at most 64 panes, 32 sessions, 256 user
  options and 32 buffers. Explicit future pane gates are capped at 4,096.
  Closed panes discard their gates, preventing automatic-pause state from
  accumulating across repeated pane creation and exit.
  Wasm memory is capped at 64 MiB/pane and 512 MiB aggregate, with per-call fuel.
  Guest traps poison only that pane; oversize captures do not poison it.
  Resize traps do not unwind partially updated ownership; topology changes
  complete before the next poll reaps poisoned panes, including idle panes.
- Invalid attachment does not leave a corrupt session identity after an error.
  Detached panes keep draining into screen state. Rust ownership and scoped
  child cleanup replace unsafe C++ pointer/process assumptions.
- Windows console output uses the canonical `CSI ?777;byte;...q` gateway in
  groups of 15; redirected output stays raw. Unix restores descriptor flags and
  clears stale terminal input. Neither uses a blocking global stdout exit flush.

## Reproducible verification

Build/run the independent command oracle (the fixture also runs in ordinary
`cargo test`, without a C++ compiler):

```sh
CANONICAL_HTM=/path/to/canonical/src/htm \
CANONICAL_LIBVTERM=/path/to/canonical/external/libvterm \
  sh crates/et-htm/tests/control-oracle/build.sh
HTM_CONTROL_ORACLE="$PWD/target/control-oracle/oracle" \
  cargo test -p et-htm --test control_oracle
```

The oracle's TerminalHandler is a deterministic stub: it proves command/state
behavior, not PTY/process behavior. Native PTY runtime tests separately cover
takeover, frontend bootstrap, diagnostics, retained PIDs, captured shell state,
live resizing, stale input, scoped restart and final-pane exit. The native
screen oracle compares 672 captures; canonical GUI snapshot-comparator tests
run headlessly. Stock tmux independently checks common split/resize layouts
and guard flags, rather than overriding canonical-specific quirks.

Screen review: no guest imports or native guest pointers, bounded allocation,
fixed output/input/title buffers, checked capture arithmetic, traps before CSI
array/decimal overflow, permanent trap poisoning, reproducible Wasm artifact.
A release test processed 995,328 bytes in 1.53s on this runner, checked the
resulting screen/cursor, rejected an oversized history capture, and continued
processing. This is a measured throughput sample, not a latency guarantee.

Pre-merge Linux review on 2026-09-17: formatting and workspace/all-target Clippy
with warnings denied passed; serial workspace tests passed 640 with zero failures.
The two normally ignored screen differential/throughput tests also passed when
explicitly invoked. Seven real-role HTM tests, the 174-record live C++ command
oracle, 672 screen comparisons, 23 canonical GUI comparator tests, and isolated
tmux 3.4 layout/guard probes passed. WASI SDK rebuild reproduced the recorded
artifact hash. Ledger self-test/live comparison passed: 22 commits classified,
zero unclassified, unchanged canonical tip.

An isolated synthetic integration with origin/main
`201d645f505b97c77f6ee672b66c4b44e3788324` had no conflicts, passed workspace
Clippy with warnings denied and 679 serial workspace tests, and linked Windows
workspace binaries and HTM test executables. No branch merge was performed.
The reconnect-status change already present on main integrated without duplicate
behavior. The stray global IsTerminal import was returned to its Unix-only scope.

Platform verification limits: this Linux runner cannot execute native macOS
process/cwd behavior or native Windows ConPTY/console/ACL behavior. MinGW was
installed locally for Windows linked binaries/tests. Local Wine installation
was attempted, but its shell32/kernel32 bootstrap failed before the Rust tests.
Windows workspace libraries/binaries, all HTM tests and the real-role HTM runtime
test executable link. HTM all-target Windows Clippy passes with warnings denied.
Full Windows workspace test compilation is blocked by existing unconditional
Unix/nix/PermissionsExt imports in terminal/reconnect tests and et-server's
`tests/support` and `tests/runtime_support`. Those imports were verified in main,
not introduced by HTM. The older branch base also has a `new_with_lifecycle`
dead-code warning that is absent from the current-main integration.
Actual iTerm2/Ghostty/Hyper/WezTerm/Windows Terminal GUI automation needs the
corresponding platform; protocol/oracle tests do not certify GUI rendering.
There are no intentionally deferred canonical command implementations.
