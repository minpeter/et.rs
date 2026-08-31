---
packages:
  et:
    type: patch
---

## Harden SSH configuration port forwarding

SSH-configured forwards now preserve their destination and OpenSSH bind
semantics without duplicating operational SSH listeners. Reverse listeners are
also bound with the authenticated session identity, reject wildcard and
privileged authority escalation, and enforce a per-session resource limit.
