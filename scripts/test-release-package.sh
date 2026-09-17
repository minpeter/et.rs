#!/usr/bin/env bash
# Offline packaging QA; pass a built native et binary (absolute path).
set -euo pipefail
binary="$1"
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
cp -R scripts etc systemctl "$work_dir/"
cd "$work_dir"
version="$("$binary" --version | head -n1 | cut -d' ' -f3)"
target=x86_64-unknown-linux-gnu
name="et-${version}-${target}"
archive="$(bash scripts/package-release.sh "$version" "$target" "$binary")"
sha256sum --check "$archive.sha256"
mkdir extracted
tar -xzf "$archive" -C extracted
for role in et etserver etterminal htm htmd; do
  output="$("extracted/$name/$role" --version)"
  [[ "${output%%$'\n'*}" == "$role version $version (et.rs)" ]]
done

# Generate and execute the actual AUR package() with offline checksum responses.
curl() { printf '%064d  fixture.tar.gz\n' 0; }
export -f curl
bash scripts/generate-pkgbuild.sh "$version" > PKGBUILD
unset -f curl
(
  source PKGBUILD
  [[ "${backup[*]}" == etc/et.cfg ]]
  CARCH=x86_64
  pkgdir="$work_dir/installed"
  cd extracted
  package
  cmp etc/et.cfg "$pkgdir/etc/et.cfg"
  cmp systemctl/et.service "$pkgdir/usr/lib/systemd/system/et.service"
  for role in etserver etterminal htm htmd; do
    [[ "$(readlink "$pkgdir/usr/bin/$role")" == et ]]
  done
  "$pkgdir/usr/bin/etserver" --help | grep -Fq '/etc/et.cfg'

  # Exercise the installed service command without root or a host systemd unit.
  python3 - "$pkgdir" <<'PY'
import os
from pathlib import Path
import selectors
import shlex
import socket
import subprocess
import sys
import time

root = Path(sys.argv[1])
config = root / 'etc/et.cfg'
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
# A non-default port proves the packaged file was read, not merely accepted.
config.write_text(config.read_text().replace('port = 2022', f'port = {port}')
                  .replace('# bind_ip = 0.0.0.0', 'bind_ip = 127.0.0.1'))
unit = (root / 'usr/lib/systemd/system/et.service').read_text()
command = shlex.split(next(line.removeprefix('ExecStart=')
                          for line in unit.splitlines() if line.startswith('ExecStart=')))
command[0] = str(root / command[0].lstrip('/'))
command[1] = f'--cfgfile={config}'
command += [f'--serverfifo={root}/router.sock', f'--logdir={root}/logs']
env = {key: value for key, value in os.environ.items()
       if key not in ('ET_DEBUG', 'ET_VERBOSE', 'ET_LOGDIR')}
with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) as server:
    output = b''
    ready = f'ETSERVER_READY tcp=127.0.0.1:{port} '.encode()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(server.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 10
            while ready not in output and time.monotonic() < deadline:
                if selector.select(timeout=0.1):
                    chunk = os.read(server.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output += chunk
        assert ready in output, output
        assert b'etserver logging enabled' in output, output
        server.terminate()
        remaining, errors = server.communicate(timeout=10)
        assert server.returncode == 0, (server.returncode, errors)
        assert b'Server is shutting down' in output + remaining, output + remaining
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()
print('Installed service config, stdout logging and graceful shutdown passed')
PY
)

# Negative controls: missing templates and copied role binaries must fail QA.
rm "$name/etc/et.cfg"
tar -czf "$archive" "$name"
if bash scripts/check-release-archive.sh "$archive" "$target"; then
  echo 'Missing config was accepted' >&2
  exit 1
fi
cp etc/et.cfg "$name/etc/et.cfg"
rm "$name/etserver"
cp "$name/et" "$name/etserver"
tar -czf "$archive" "$name"
if bash scripts/check-release-archive.sh "$archive" "$target"; then
  echo 'Copied role binary was accepted' >&2
  exit 1
fi
echo 'Release archive and AUR staging QA passed'
