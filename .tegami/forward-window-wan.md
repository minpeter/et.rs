---
packages:
  et:
    type: patch
---

Faster `-L`/`-R` port-forward uploads over high-latency links. Each forwarded
socket may now have 4 MiB in flight (was 2 MiB) and returns credit every
eighth of that window, so a single `-N -L` upload is no longer capped near
23 MiB/s on a 50 ms RTT link. Older et.rs peers still negotiate the smaller
window safely.
