---
packages:
  et:
    type: patch
---

## Harden SSH configuration port forwarding

Operational SSH commands now suppress OpenSSH forwarding before user options,
while configuration queries still import supported forwarding rows. Imported
TCP destinations are limited to localhost, and local binds preserve
GatewayPorts loopback and wildcard behavior.

Reverse listeners bind with the authenticated session identity, reject wildcard
or privileged authority escalation, and enforce a transactional per-session
listener limit. Bind failures are reported by bounded row index: SSH-config-only
rows warn and continue, while an unavailable explicit reverse row aborts the
client and releases sibling listeners.
