---
packages:
  et:
    type: patch
---

## Parse et options after the destination

Flags placed after the destination are et options, matching EternalTerminal's
cxxopts parser. `et host --command 'echo hi'` runs `echo hi` on the remote
shell. An explicit `--` ends option parsing, and the following words are the
remote command, including tokens that look like flags. A token that is not an
et option, such as `echo -n`, also stays in that command. Protocol v6 is
unchanged.
