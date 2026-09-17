# Sandboxed canonical screen

`libvterm/` contains the `include/` and `src/` trees from canonical
EternalTerminal commit `8a306f6d3580886f77357864fc010a4e8b78c3a6`,
`external/libvterm` (0.3.3), with its MIT license. `screen.c` adapts that
commit's `PaneScreen.cpp`: history callbacks, legacy title filtering, cell
serialization, and capture ranges. It is not linked into native Rust code.

The checked-in `screen.wasm` is built with WASI SDK 34.0, Linux x86_64 archive
SHA-256 `b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4`:

```sh
WASI_SDK_PATH=/path/to/wasi-sdk-34.0-x86_64-linux sh crates/et-htm/screen-guest/build.sh
sha256sum crates/et-htm/screen-guest/screen.wasm
```

Current artifact SHA-256:
`055b8a9b922c25a35f337475d94457437e8f70e8d73a05eb0d6df20ce3530c4e`.
Normal Cargo builds need neither a C compiler nor the WASI SDK.

The safe Rust host rejects any module import. WASI libc's otherwise-linked
file operations trap inside the guest; its clock wrapper returns a constant.
No host I/O, process, filesystem, or network capability exists. ABI offsets
are copied through checked Wasm memory APIs, never dereferenced as host
pointers. Instances have 64 MiB linear-memory limits, a 512 MiB aggregate
reservation limit, and per-operation fuel. A trapped instance is permanently
poisoned; the daemon closes its pane instead of resuming corrupted guest state.
Oversized capture replies return an error without poisoning a valid screen.
Fuel is an instruction bound, not a real-time deadline.

Local changes to upstream libvterm are limited to `src/parser.c`: trap before
overflowing the CSI argument array or its 32-bit signed decimal accumulator.
These malformed-input cases otherwise invoke undefined C behavior and are not
meaningful compatibility targets. Capture indexing uses 64-bit intermediates
to avoid overflow for extreme user-supplied offsets. Input, title, output, and
screen dimensions are separately bounded. Other upstream parser behavior is
retained inside the sandbox, rather than reimplemented in Rust.

The independent oracle builds **unmodified** canonical `PaneScreen.cpp` and
libvterm as a native executable, not this adapter:

```sh
CANONICAL_HTM=/path/to/canonical/src/htm \
CANONICAL_LIBVTERM=/path/to/canonical/external/libvterm \
  sh crates/et-htm/tests/screen-oracle/build.sh
HTM_SCREEN_ORACLE="$PWD/target/screen-oracle/oracle" \
  cargo test -p et-htm --test screen_oracle -- --ignored
```

The differential test compares 672 captures with identical feed boundaries,
covering all combinations of capture flags, three ranges, Unicode, colors,
alternate screen, scrolling, resizing, insert/delete, and legacy title states.
This is evidence for those cases, not exhaustive screen or GUI parity.
