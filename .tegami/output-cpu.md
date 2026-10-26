---
packages:
  et:
    type: patch
---

### Less server CPU for terminal output

On Linux, `etterminal` now reads the terminal until it has nothing more to give, or until it has 16 KiB, before passing output to `etserver`. Before, it stopped at the first small read. On an idle machine a fast `cat` arrives in pieces of a few hundred bytes to a few KiB, so a 101 MB `cat` went to `etserver` as about 46,000 small chunks, mostly under 4 KiB. It now goes as about 6,800, most of them 16 KiB. `etserver` also reads several chunks at a time from `etterminal` instead of making three or four reads for each one.

For that 101 MB `cat` on a local link, the server side (`etserver` plus `etterminal`) went from about 1.43 to 1.0 s of CPU. OpenSSH's `sshd-session` uses about 1.1 s and ET C++ about 4 s. The client and server together now use less CPU than OpenSSH. Output also takes about 2% fewer bytes on the wire (ET C++: 3.6% more than the output, et.rs now 2.1%). Nothing changes on the wire, and Ctrl+C still drops the output that was already read but not yet sent.
