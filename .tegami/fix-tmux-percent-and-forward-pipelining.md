---
packages:
  et:
    type: patch
---

## Fix plain `%` output reordering and pipeline forwarding reads

- Only enter `tmux -CC` control-mode output handling on a real `tmux -CC` DCS
  introducer (`\x1bP1000p`) or a known tmux control notification/block token
  (`%begin`, `%output`, `%extended-output`, `%exit`, etc.), and leave control
  mode on `%exit` (EternalTerminal #899). Plain terminal output starting with
  `%` (such as `top` `%Cpu(s):` or a `%` shell prompt) is no longer reordered
  or retained across an interrupt flush.
- Pipeline windowed port-forwarding socket reads up to the negotiated window
  without blocking after every 16 KiB read chunk, assemble non-blocking
  transport frames with a 64 KiB read buffer, and reuse the server bridge's
  polled client socket handle across iterations.
