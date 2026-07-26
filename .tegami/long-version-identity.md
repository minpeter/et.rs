---
packages:
  et: patch
---

### Identify the et.rs port in `--version` output

`--version` on every role (`et`, `etserver`, `etterminal`, `htm`, `htmd`) now
prints the et.rs identity and project URL:

```
et version 0.0.3 (et.rs)
A Rust port of Eternal Terminal
https://github.com/minpeter/et.rs
```

`-V` keeps the short upstream-compatible `et version X.Y.Z` line for scripts.
`etterminal` gains `--version`/`-V` support.
