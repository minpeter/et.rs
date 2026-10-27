---
packages:
  et:
    type: patch
---

### Less server CPU for terminal output

On Linux, `etterminal` now reads the terminal until it has nothing more to give, or until it has 16 KiB, before passing output to `etserver`. Before, it stopped at the first small read. On an idle machine a fast `cat` arrives in pieces of a few hundred bytes to a few KiB, so a 101 MB `cat` went to `etserver` as about 46,000 small chunks, mostly under 4 KiB, each read, encrypted and sent on its own. It now goes as about 6,800 chunks, most of them 16 KiB.

For that 101 MB `cat` on a local link, the server side (`etserver` plus `etterminal`) went from about 1.4 to 1.0 s of CPU (ET C++: about 2.4 s), below OpenSSH's `sshd-session`, and the client also uses less. Output takes slightly fewer bytes on the wire. On a busy machine the reads were already full and nothing changes. Nothing changes on the wire format, and Ctrl+C still pauses reading the terminal until the interrupt has taken effect.
