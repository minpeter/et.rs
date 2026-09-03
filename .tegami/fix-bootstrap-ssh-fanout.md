---
et: patch
---

Give each ET SSH bootstrap a private ControlMaster and route its configuration
query, login-shell probe, and terminal bootstrap through the ET-owned socket.
The socket lives at `<short-temp>/et-ssh-<pid>-<serial>/master` in a mode-0700
directory. ET asks OpenSSH to stop the master after bootstrap and removes the
whole private directory; a startup failure falls back to ordinary independent
SSH invocations. Long Unix temporary-directory paths fall back to `/tmp` so the
socket remains below conservative `sockaddr_un` limits.

User `ControlMaster` and `ControlPath` options remain filtered, so ET neither
reuses nor removes a user's socket. Isolation remains forced with
`ClearAllForwardings=yes`, `RemoteCommand=none`, `PermitLocalCommand=no`, and
`SessionType=default`.

Local OpenSSH 10.2 diagnosis against the machine's localhost sshd:

- Baseline `ssh -vvv -G -T ... localhost` emitted no `Connecting to` or mux
  line: `-G` is configuration-only and opens no TCP connection.
- Baseline shell-probe and bootstrap-shaped commands each emitted
  `debug1: Connecting to localhost [::1] port 22.`
- Starting the ET-shaped master emitted one `Connecting to` line and
  `new mux listener [.../master]`.
- The probe and bootstrap through that socket emitted
  `mux_client_request_session` and no `Connecting to` line.
- `ssh -O exit` emitted `Exit request sent.`; the socket was absent afterward.
