---
et: patch
---

Reuse an existing SSH ControlMaster during probe and bootstrap instead of
forcing a fresh sshd connection for every ET session. Isolation of
`RemoteCommand`, `PermitLocalCommand`, `SessionType`, and
`ClearAllForwardings` is unchanged; ET still refuses to own or override a
control socket from user `-o` flags.
