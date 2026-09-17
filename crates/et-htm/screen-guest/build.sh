#!/bin/sh
# Rebuild only; normal Cargo builds embed the checked-in artifact.
set -eu
: "${WASI_SDK_PATH:?set WASI_SDK_PATH to wasi-sdk-34.0}"
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$WASI_SDK_PATH/bin/clang" -O2 -DNDEBUG -std=c11 -fno-ident \
  -ffile-prefix-map="$root"=. -I"$root/libvterm/include" \
  -mexec-model=reactor -Wl,--initial-memory=1048576 -Wl,--max-memory=67108864 \
  -Wl,-z,stack-size=131072 -Wl,--strip-all \
  -Wl,--wrap=__wasi_fd_close,--wrap=__wasi_fd_seek,--wrap=__wasi_fd_write,--wrap=__wasi_clock_time_get \
  "$root/screen.c" "$root"/libvterm/src/*.c \
  -o "$root/screen.wasm"
