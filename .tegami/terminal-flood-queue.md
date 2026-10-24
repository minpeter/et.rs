---
packages:
  et:
    type: patch
---

### Quicker echo during output floods and no reconnect after a paused terminal

When the remote side floods the terminal faster than the local terminal can show it, `etserver` used to send each short piece of output as its own network packet. Linux then kept growing the client's receive buffer to many megabytes, and every keystroke echo waited behind all of it. Output that is waiting to be sent is now merged into packets of up to 16 KiB, like ET C++. During a `yes` flood on a local link, the client receive buffer now stays around 400 KB instead of growing to 9 MB or more, and echo is about 6 ms at the median instead of 20 ms.

If the local terminal stopped reading for more than 5 seconds during a flood (a slow terminal, Ctrl+S, a paused pager), `etserver` decided the client was gone and dropped the connection, so the client had to reconnect before the next prompt. The server now keeps the connection while the client is still sending, and the client keeps sending keep-alives while its output is held. A client that really disappears is still dropped after 10 seconds of silence. Getting the prompt back after a 10 second pause went from about 100 ms to about 13 ms.

After Ctrl+C during a flood, the client no longer paints the output that was already waiting in its connection when the key was pressed. The server sent that output before it could see the interrupt, and ET C++ drops output it has already read in the same way on the server. It only happens when at least 64 KiB was waiting, never touches what the server sends after the interrupt, and keeps exit status and other non-terminal packets. Output shown after Ctrl+C went from about 145 KB to about 45 KB.
