---
packages:
  et: patch
---

## Survive network outages during reconnect and restore leaked terminal modes

A laptop waking from sleep has no route to the server for several seconds.
The client attempted exactly one reconnect and treated its failure as fatal,
so a live session died with "could not reach the ET server: connection timed
out" the moment the first attempt raced the returning Wi-Fi. Transient
network failures (unreachable endpoint, DNS outages, connect/transport I/O
errors) are now retried every second until the link returns — matching
upstream ET, which keeps a session alive until the server ends it. The
client announces the retry loop once, and Ctrl-C gives up (raw mode turns
ISIG off, so the byte is read from stdin); protocol mismatches and server
rejections still fail immediately.

Separately, exiting only restored the local termios. Terminal modes a remote
application had enabled in the local emulator — the kitty keyboard protocol,
bracketed paste, mouse and focus reporting, the alternate screen — survived
the client, leaving the shell prompt printing key reports like `2618;9u` as
garbage text. The client now emits the matching reset sequences when it
leaves raw mode; every reset is a no-op when the mode is off or unsupported.
