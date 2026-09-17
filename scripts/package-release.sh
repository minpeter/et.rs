#!/usr/bin/env bash
# Run from the repository root. Output the archive name for release automation.
# Usage: package-release.sh <version> <target> <binary>
set -euo pipefail

version="$1"
target="$2"
binary="$3"
name="et-${version}-${target}"
mkdir "$name"
case "$target" in
  *windows*)
    cp "$binary" "$name/et.exe"
    archive="$name.zip"
    7z a "$archive" "./$name/*" >&2
    ;;
  *)
    cp "$binary" "$name/et"
    # Busybox-style role dispatch: symlinks select the role by argv[0].
    for role in etserver etterminal htm htmd; do
      ln -s et "$name/$role"
    done
    if [[ "$target" == *linux* ]]; then
      mkdir "$name/etc" "$name/systemctl"
      cp etc/et.cfg "$name/etc/"
      cp systemctl/et.service "$name/systemctl/"
    fi
    archive="$name.tar.gz"
    tar -czf "$archive" "$name"
    bash scripts/check-release-archive.sh "$archive" "$target"
    ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$archive" > "$archive.sha256"
else
  shasum -a 256 "$archive" > "$archive.sha256"
fi
echo "$archive"
