---
packages:
  et:
    type: patch
---

### Bootstrap cleanup spares detached descendants

After the `IDPASSKEY` marker, the client's ssh cleanup sent `SIGKILL` to every local descendant of `ssh`, including processes that had already left ssh's session with `setsid()`. When the bootstrap command runs `etterminal` on the local machine (an `ssh` wrapper, the test and benchmark harnesses), the scan could catch the freshly registered terminal daemon while its launcher was still exiting, and the client then failed with `client is not registered`. Cleanup now stops only descendants still in ssh's session, plus anything holding the captured stdout pipe.
