---
packages:
  et:
    type: patch
---

### Tunnelled request/response traffic no longer sends an extra packet each way per exchange

On Linux and macOS, a forwarded socket (`-L`, `-R`, `-D`) that went quiet for 50 ms returned its window credit even when only a few bytes had drained. Each small request/response exchange through a tunnel therefore cost one extra packet in each direction: thirty 64-byte round trips sent 61 packets each way, against 30 for ET C++ and OpenSSH. Credit now goes back only once an eighth of the window has drained, as it already did during transfers, and those round trips send 32 packets. A peer with a smaller window gets its credit back after an eighth of its own window.

On a lossy link every extra packet is another chance of a loss, and a loss while the connection is still warming up leaves TCP with a small congestion window, so the next upload through the tunnel crawls. On a 150 ms link with 0.5% loss each way, thirty round trips cut that window in 34% of sessions before this change and in 16% now (ET C++ 14%). Every 2 MiB upload that started after such a cut ran at 0.12 to 0.24 MiB/s, against a median of 0.90 MiB/s otherwise.
