#!/usr/bin/env bash
# Assert the extracted Unix release contract, not just the staging directory.
set -euo pipefail
archive="$1"
target="$2"
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
tar -xzf "$archive" -C "$work_dir"
root="$work_dir/$(basename "$archive" .tar.gz)"
[[ -f "$root/et" && -x "$root/et" && ! -L "$root/et" ]]
for role in etserver etterminal htm htmd; do
  [[ -L "$root/$role" && "$(readlink "$root/$role")" == et ]]
done
if [[ "$target" == *linux* ]]; then
  cmp etc/et.cfg "$root/etc/et.cfg"
  cmp systemctl/et.service "$root/systemctl/et.service"
  grep -Fxq 'ExecStart=/usr/bin/etserver --cfgfile=/etc/et.cfg --logtostdout' "$root/systemctl/et.service"
  [[ "$(find "$root" -type f | wc -l | tr -d ' ')" == 3 ]]
else
  [[ "$(find "$root" -type f | wc -l | tr -d ' ')" == 1 ]]
fi
