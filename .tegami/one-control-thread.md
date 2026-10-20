---
packages:
  et:
    type: patch
---

### One server control thread on Linux and macOS

- **The terminal router runs on the control thread:** `etserver` accepted terminal registrations on an `et-router` thread of its own, next to the `et-runtime` thread that accepts TCP connections and handles terminal lifecycle events. Both waited in `poll(2)`, so the control thread now also polls the router socket, pending registrations and registered terminals, with the same registration timeout, rejection and disconnect handling. Shutdown still closes the router after the sessions and before the registry is cleared. An idle server with one session runs three threads instead of four (OpenSSH's `sshd-session` pair: two; ET-C++: ten).
- Windows keeps the router thread: its router loop cannot wait on the router pipe together with the TCP listeners.
