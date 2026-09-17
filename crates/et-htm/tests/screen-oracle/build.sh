#!/bin/sh
# Supply the reviewed canonical source directory; never link the Rust adapter.
set -eu
: "${CANONICAL_HTM:?directory containing canonical PaneScreen.cpp and .hpp}"
: "${CANONICAL_LIBVTERM:?canonical libvterm directory}"
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="$root/../../../../target/screen-oracle"
mkdir -p "$out"
for file in "$CANONICAL_LIBVTERM"/src/*.c; do
  cc -O2 -DNDEBUG -I"$CANONICAL_LIBVTERM/include" -c "$file" -o "$out/$(basename "$file" .c).o"
done
c++ -std=c++17 -O2 -I"$root" -I"$CANONICAL_HTM" -I"$CANONICAL_LIBVTERM/include" \
  "$root/main.cpp" "$CANONICAL_HTM/PaneScreen.cpp" "$out"/*.o -o "$out/oracle"
printf '%s\n' "$out/oracle"
