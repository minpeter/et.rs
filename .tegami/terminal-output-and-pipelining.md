---
packages:
  et:
    type: patch
---

### Cheaper terminal output and pipelined tunnel messages

- **Terminal output scans use SIMD:** the tmux control-mode tracking behind Ctrl+C output filtering (`TerminalStream::observe` and `may_contain_control`) walked every output byte on the server and the client. It now uses `memchr2`/`memrchr`, so plain output costs two SIMD passes; in a PTY output stream those scans were about a fifth of all CPU.
- **Terminal stdout:** the client's console worker waits for room (still cancellable) and then writes a whole queued batch through the inherited blocking terminal description, instead of a poll and a write for every 4 KiB the PTY accepts, and it reuses its batch buffer. A 64 MiB PTY stream: 108 → 132 MiB/s with 29 % less CPU across client, server and terminal.
- **Frame-aligned socket reads:** once a bulk-sized frame has been decoded, a connection asks for the rest of the pending frame plus whole frames of that size, so a uniform bulk stream no longer leaves a partial frame to move to the front of the buffer before every read.
- **Smaller reads on the server:** a server connection reads at most 96 KiB (one aligned 64 KiB-packet frame) instead of 256 KiB, because a server holds one read buffer per session. With 16 concurrent saturated uploads on one server, `etserver` peaks at 17.4 MB RSS instead of 20.4 MB (ET-C++: 18.0 MB) for about 5 % more server CPU (still 40 % below ET-C++); clients keep 256 KiB reads.
- **Pipelined tunnel messages:** a forwarded socket holding up to four packets (about 256 KiB) is read in four parts of at least 16 KiB, so the peer decrypts and forwards the first part while the rest is still encrypted and sent. 64 KiB request/response round trips are 23 % faster (now below OpenSSH) and 32 KiB ones 11 %; bulk transfers keep full 64 KiB packets.
