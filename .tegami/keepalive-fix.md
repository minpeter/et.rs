---
packages:
  et:
    type: patch
---

### `et` notices a dead connection after two keep-alive intervals instead of three

When the network path to the server silently disappears (an IP address change, a NAT dropping the connection), no error ever arrives, and `et` finds out only through keep-alives. It used to reconnect after three keep-alive intervals without hearing from the server, 15 seconds with the default `--keepalive 5`. It now works like ET C++: one interval after the last packet from the server it sends a keep-alive, and if that is still unanswered one interval later it reconnects. That is 10 seconds by default. Typing into the dead connection no longer delays this; in ET C++ it does.

Idle sessions also send fewer bytes. Keep-alives only carry `et`'s 8-byte delivery acknowledgement when it tells the other side something new: on the first keep-alive of each connection, after terminal or forwarding traffic, and after every 16 keep-alives. Toward ET C++, which ignores the acknowledgement, `etserver` now sends ET C++'s empty keep-alives, and `et` does so after its first one.
