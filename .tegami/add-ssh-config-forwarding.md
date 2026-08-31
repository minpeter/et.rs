---
packages:
  et:
    type: patch
---

## Apply SSH configuration port forwarding

The client now reads effective `LocalForward` entries from OpenSSH
configuration and applies them as ET tunnels alongside command-line tunnels.
Configured destination hostnames, explicit bind addresses, `GatewayPorts`, and
`ExitOnForwardFailure` are preserved. `RemoteForward` remains available through
the explicit `-r` option and is not imported from SSH configuration.
