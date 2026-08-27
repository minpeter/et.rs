---
packages:
  et: patch
---

## Preserve Ghostty truecolor detection

Ghostty clients now forward the standard `COLORTERM=truecolor` hint to POSIX
sessions while continuing to use the compatible `TERM=xterm-256color`
fallback. Applications such as Neovim and tmux can retain automatic 24-bit
color detection on remote hosts without Ghostty's terminfo entry.
