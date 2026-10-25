---
packages:
  et:
    type: patch
---

### Echo stays fast through every output flood

When the remote side floods the terminal (`yes`, a large `cat`) faster than the local terminal can draw, some sessions still answered keystrokes 30 to 50 ms late. The local terminal could not keep up, so output waited in the client's receive buffer, and Linux kept growing that buffer to several megabytes. On Linux, `etserver` now stops sending terminal output while an et.rs client has about 1 MiB of it that it has not yet confirmed reading, and sends more as the client confirms. The client already sends these confirmations, so nothing changes on the wire. Output held back stays on the server, where Ctrl+C still drops it. Forwarded ports and keep-alives are never held back.

Over 30 sessions of a `yes` flood on a local link, no session's median echo was above 10 ms, where 5 of 30 sat between 16 and 43 ms before. The 95th percentile went from 34 to 12 ms (ET C++: 32 ms). On a slow or distant link the limit grows with the link's capacity times its round trip, which the server measures during the connection handshake, so throughput stays the same: about 14 MB/s at a 50 ms round trip.

ET C++ clients, and et.rs clients older than 0.0.36, do not confirm often enough to use this, and their output is sent as before. A client that stops confirming for 10 seconds, for example a terminal paused with Ctrl+S, also gets the previous behavior until it confirms again.
