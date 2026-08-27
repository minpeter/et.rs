---
packages:
  et: patch
---

## Restore remote colors for Ghostty clients

ET clients launched from Ghostty now send the widely supported
`TERM=xterm-256color` fallback instead of `xterm-ghostty`. This restores
ordinary remote prompt and application colors on hosts without Ghostty's
terminfo entry. Other terminal types remain unchanged.
