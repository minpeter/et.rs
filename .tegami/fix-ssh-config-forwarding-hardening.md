---
packages:
  et:
    type: patch
---

## Harden SSH configuration port forwarding

Operational SSH commands now force isolated forwarding, command, and control
socket settings after filtering conflicting user options, while configuration
queries still read supported `LocalForward` rows.

Reverse listeners bind with the authenticated session identity, reject wildcard
or privileged authority escalation, and enforce a transactional per-session
listener limit without capping client-side local listeners. Unix forwarding
helpers clear supplementary groups, authenticate router peers, and roll back
socket paths and created directories on every failed setup or descriptor
transfer. Any explicit reverse bind failure aborts the session and releases
sibling listeners without adding a protocol extension.
