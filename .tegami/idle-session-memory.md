---
packages:
  et:
    type: patch
---

### Idle sessions use less server memory on Linux

An idle session used to keep the memory its last burst of output had freed. The `etserver` session thread and the per-session terminal process kept it in their allocator caches, which jemalloc only trims while a thread keeps allocating. After one second without traffic, both now return that memory. A keep-alive that arrives later does not rebuild the cache, and normal traffic gets it back right away.

Each terminal process also skips jemalloc's statistics tables now. Nothing reads them, and they cost every process about 120 KiB once it used the allocator's control interface.

With 50 idle sessions on loopback, private memory (USS) per session, `etserver` and terminal process together, dropped from about 840 KiB to about 680 KiB. ET C++ uses about 1240 KiB. Memory summed by RSS still looks higher for et.rs than for ET C++, because RSS counts the shared `et` binary and libc pages again in every process.
