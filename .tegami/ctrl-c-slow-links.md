---
packages:
  et:
    type: patch
---

### Ctrl+C brings the prompt back sooner on slow and lossy links

During a flood, `etserver` used to keep writing until the kernel refused more. That left up to about 65 KB of output unsent in the kernel, plus part of one more 32 KiB chunk already committed, and Ctrl+C could drop none of it. It now starts each chunk only when the connection has room for it, like ET C++, so output that has not started can still be dropped. `etterminal` also hands the server terminal output in 16 KiB chunks, like ET C++.

`etterminal` used to read the terminal as fast as a flooding program wrote, so the program's write never paused, and Linux applies Ctrl+C only once that write ends. Another 25 to 290 KB of output still reached the screen after Ctrl+C. Now, when forwarded input interrupts the foreground job (Ctrl+C, Ctrl+\ or Ctrl+Z with signals enabled) while output is pending, `etterminal` stops reading output until the shell takes the terminal back, for at most 10 ms. The kernel then discards the rest of the flood. This applies to the Linux terminal runtime.

On a lossy link (150 ms round trip, 0.5% loss each way), the prompt came back after Ctrl+C in about 290 ms instead of about 430 ms. On a 10 Mbit link with a 50 ms round trip, it now comes back in about the same time as with ET C++ (420–495 ms, against 535 ms before).
