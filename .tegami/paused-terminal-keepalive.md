---
packages:
  et:
    type: patch
---

### No reconnect when a paused terminal resumes during an output flood

If the local terminal stopped reading for a few seconds during a fast output flood, the client could decide the connection was dead at the moment the terminal resumed, although the server's output was still waiting to be read. It then reconnected, and the reconnect could fail while the terminal was still catching up, ending the session. The client now treats server data it has not read yet as proof that the connection is alive.
