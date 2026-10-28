---
packages:
  et:
    type: patch
---

### Faster terminal output over high-latency links, cleaner Ctrl+C, and quicker echo during floods

On Linux, `etserver` kept at most about 512 KiB of a session's output in the kernel, which held a 50 ms round trip to about 6 MB/s. That bound is now 2 MiB, and output not yet sent is held to 32 KiB, like ET C++. At a 50 ms round trip, terminal output went from about 6 to 14 MB/s and `-N` downloads from about 9.5 to 29 MiB/s. Ctrl+C still brings the prompt back in about one round trip. With no bound at all, a fast flood would pile megabytes of output in flight that Ctrl+C cannot drop. A server running as root may raise its send buffer above `net.core.wmem_max` for this.

On Ctrl+C the server now also drops the output the remote program already wrote but `etserver` had not read yet, like ET C++. Before, that tail (often a few hundred KB) still reached the screen. An exit status in that tail still arrives. Jumphost sessions do the same. The client now drops its own unpainted output on every Ctrl+C, not only past 64 KiB, like ET C++.

Keystrokes echo faster while the terminal floods. The server reads at most 256 KiB of terminal output ahead, and the client reads the connection 64 KiB at a time instead of 256 KiB, so an echo waits behind less output. During a `yes` flood, echo went from about 55 to 20 ms.
