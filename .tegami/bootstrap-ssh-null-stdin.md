---
packages:
  et:
    type: patch
---

## Do not inherit client stdin in bootstrap ssh

Redirect the bootstrap `ssh` subprocess's `stdin` from `/dev/null`
(`Stdio::null()`) instead of inheriting the `et` client's `stdin`, matching
upstream `SubprocessToStringInteractive` (EternalTerminal #867). When `et` is
invoked with piped input (such as `printf ... | et -T host ...` or VS Code
Remote-SSH writing its install script to `stdin`), bootstrap `ssh` no longer
consumes the input stream before the ET session starts. Interactive password,
passphrase, and host-key prompts continue to use `/dev/tty` because `ssh`
remains in the client's process group.
