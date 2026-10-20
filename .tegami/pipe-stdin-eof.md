---
packages:
  et:
    type: patch
---

### `et -T` passes the end of your input to the remote command

Like `ssh -T`, `et -T host 'wc -c' < file` now finishes: when the client's stdin ends, the remote command sees end of input. On a terminal, Ctrl-D in `et -T` now ends the command's input instead of closing `et`.

This needs an et.rs client and an et.rs `etterminal`. ET C++ has no way to signal it, so with a C++ client or terminal the command keeps waiting as before.
