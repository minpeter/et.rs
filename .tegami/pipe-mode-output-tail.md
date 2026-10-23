---
packages:
  et:
    type: patch
---

### `et -T` and `et --command` no longer drop the end of the output and exit 0

A command's last output and its exit status could go missing, and `et` then exited with code 0 as if nothing had happened. On a busy machine, about 1 in 20 runs of `et -T localhost --command "head -c 500000000 /dev/zero"` printed from about 1 KB to 10 MB too little. There were two causes.

`etserver` closed the connection as soon as it had queued the last output. Often the client had not read it all yet. If the client then sent anything, such as its regular keepalive, the server's operating system reset the connection and threw away the output it still held. Like ET C++, `etserver` now keeps the connection open for up to a second after the command ends, and closes it as soon as the client has read everything and closed its side.

`et` could also throw away output it had already received. When it sent a keepalive just as the server finished, it noticed the closed connection and discarded its unread input, including the exit status. `et` now reads everything the server sent before it treats the connection as closed. This also applies when `et` connects to an ET C++ server.

With both fixes, 400 of 400 runs of the command above delivered every byte, against 40 short runs out of 800 before.
