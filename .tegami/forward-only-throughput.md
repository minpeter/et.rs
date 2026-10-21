---
packages:
  et:
    type: patch
---

### `et -N` port forwards are no longer capped at about 12 MiB/s, and large uploads to ET C++ servers no longer stall

`et -N` (and `-M`/`--ctl` sessions) sent one forwarded packet and then slept for 5 ms, which held every forward to about 12 MiB/s even on loopback. These sessions now keep sending while there is data and wake as soon as the connection or a forwarded socket is ready, like ET C++'s client loop. On loopback, `-N -L` uploads went from 12 to about 590 MiB/s and downloads from 150 to about 430 MiB/s. Interactive sessions with `-L` were not affected.

Uploading through `-L` to an ET C++ server could also stop for good before the end. The last 16 MiB of a large transfer stayed queued in the client once the local application stopped writing. The client now sends that data too.
