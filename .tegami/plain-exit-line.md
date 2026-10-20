---
packages:
  et:
    type: patch
---

### A plain `%exit` line no longer looks like tmux control mode

Ctrl+C output discarding keeps tmux `-CC` control lines (`%begin`, `%output`, …) so a tmux client never sees a broken record. Control mode starts only at tmux's `ESC P 1000 p` introducer or a known control token at the start of a line, so `top` (`%Cpu(s)`) or a csh `%` prompt stays ordinary output, as upstream #900 now does too. A line that happens to read `%exit`, tmux's goodbye, still entered control mode, and later `%` lines then survived a Ctrl+C flush. It is now ordinary output. Inside real control mode the session still leaves at the string terminator that follows `%exit`, so a Ctrl+C between the two cannot drop it.
