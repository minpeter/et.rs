---
packages:
  et:
    type: patch
---

### Ctrl+C brings the prompt back sooner on lossy links

`etterminal` used to read the terminal as fast as a flooding program wrote, so the program's write never paused, and Linux applies Ctrl+C only once that write ends. Another 25 to 290 KB of output still reached the screen after Ctrl+C. Now, when forwarded input interrupts the foreground job (Ctrl+C, Ctrl+\ or Ctrl+Z with signals enabled) while output is pending, `etterminal` stops reading output until the shell takes the terminal back, for at most 10 ms. The kernel then discards the rest of the flood. This applies to the Linux terminal runtime. `etterminal` also hands the server terminal output in 16 KiB chunks, like ET C++.

On a lossy link (150 ms round trip, 0.5% loss each way), the prompt came back after Ctrl+C in about 200 ms instead of about 480 ms.
