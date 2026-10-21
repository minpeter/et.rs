---
packages:
  et:
    type: patch
---

### Reconnects no longer freeze the session for about 5 seconds

When an ET C++ client reconnected to `etserver`, the server held the recovered session until that client sent something new. Usually that was the client's next keepalive, about 5 seconds later. Until then the server did not send terminal output, and keystrokes typed during the outage did not reach the shell. The handshake already proves which clients hold the session key, so the server now resumes those sessions at once, as ET C++ does. Older clients without that handshake now resume at once if they had input queued, because those queued packets also prove the key.

The `et` client had a similar stall: if the server's first packets after a reconnect arrived together, `et` showed them only at its next keepalive. It now handles them at once.

On loopback, reconnecting an ET C++ client to `etserver` went from 5.7 s to about 0.2 s, and the occasional 5 s reconnects of `et` (about one in five) no longer happen.
