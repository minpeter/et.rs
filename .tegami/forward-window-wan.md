---
packages:
  et:
    type: patch
---

### Port-forward uploads are faster over high-latency links

Each forwarded socket may now have 4 MiB in flight (was 2 MiB) and returns credit every eighth of that window, so a single `-N -L` upload is no longer capped near 23 MiB/s on a 50 ms round trip. Older et.rs peers still negotiate the smaller window safely.
