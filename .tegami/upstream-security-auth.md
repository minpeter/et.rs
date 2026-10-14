---
packages:
  et:
    type: patch
---

## Replay ssh-agent host-key bindings

Forwarded ssh-agent connections replay the OpenSSH
`session-bind@openssh.com` request recorded during bootstrap ssh, including
the destination host key. A private recorder keeps the last non-forwarded
bind and writes it before client data on each new forwarded connection.
Jumphost binds are included. The agent's replies to those binds are stripped.
A refusal or a missing bind is logged, and forwarding continues. Protocol v6
is unchanged.

## Bound forwarding and harden private daemon paths

Accepted port-forwards waiting on a destination reply are capped at 128 and
expire after 30 seconds. A reply that arrives after its token has expired
closes that destination. Incomplete dynamic-forward SOCKS handshakes are
capped at 64 and closed after 30 seconds.

Daemon pid files refuse symlinks, extra hard links, fifos, and writable
ancestors, and truncate stale contents only after those checks. Creating the
etserver directory checks every ancestor. Root-owned sticky directories such
as `/tmp` stay allowed. Log rotation truncates the open inode. A tmux control
line that was already partly sent is finished from the backlog in one loop,
including a large hostile prelude, so the client receives a complete control
record.

## Harden the daemon, router, and session recovery

Encrypted frames must be at least the 2-byte packet header and at most 128
MiB. Framed bodies grow in 64 KiB chunks. A packet that fails Poly1305
verification leaves the decrypt nonce unchanged, so a retransmission still
matches.

Unix router sessions and HTM control sockets take their identity from kernel
peer credentials. When descriptors or memory are exhausted, the daemon keeps
listening, with at most 64 handshakes in flight.

`et --attach` refuses an unchallenged `NEW_CLIENT` or `RETURNING_CLIENT` and
reports that etserver needs an upgrade. A new session still accepts a legacy
server. Recovery catchup allows 144 MiB. Revive drops the oldest history
above the 64 MiB backup cap and keeps the newest packets for the next
catchup.

## Keep Windows sessions responsive during forwarding writes

Windows client and server transports retain a partial forwarding write and
continue reading while it drains. Terminal input, output, and keepalives stay
live during a large forward, and input and forwarding take turns across those
writes.
