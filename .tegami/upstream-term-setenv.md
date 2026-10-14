---
packages:
  et:
    type: patch
---

## Match upstream TERM forwarding and SetEnv TERM overrides

Forward the local `TERM` value unchanged during SSH bootstrap (defaulting to
`xterm-256color` only when `TERM` is unset or empty) and allow `SetEnv TERM`
and `SendEnv TERM` from SSH configuration or `-o` to override the session
`TERM`, matching upstream EternalTerminal (#679, #725, #870). Remove the
non-upstream `xterm-ghostty` fallback and automatic `COLORTERM` injection.
