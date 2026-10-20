---
packages:
  et:
    type: patch
---

### `etserver` and `etterminal` accept what ET C++ sends

On the server host, `etserver` and `etterminal` now accept a message of up to 128 MiB, as upstream does (it was 64 KiB). `etterminal` also sets the session environment the way upstream does: any number of variables, of any length, with names such as `MY-VAR`. It skips only entries the system cannot set. A C++ `et` client with a large `SendEnv`/`SetEnv` environment therefore no longer fails to start a session on an et.rs `etserver` or `etterminal`.

The et.rs `et` client still sends only what et.rs 0.0.43 and older accept, so it keeps working with servers that have not been upgraded.
