---
packages:
  et:
    type: patch
---

### `etserver` no longer burns a CPU core on a session whose shell exited while the client was away

When the client's connection dropped and the shell then exited with output the server could not deliver yet, such as a full output buffer or the final exit status, the session's thread kept waking without pause, using a whole CPU core until `etserver` stopped. Stopping `etserver` could then hang on that thread. Like ET C++, the server now stops watching a terminal it cannot read from. A session that no client can resume any more now ends.
