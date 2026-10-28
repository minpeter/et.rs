---
packages:
  et:
    type: patch
---

### Idle sessions send fewer keep-alives, at ET C++'s pace

An idle `et` session, interactive or `-N`, sent a keep-alive every 5 seconds. ET C++ only sends one once more than 5 whole seconds have passed, which in practice is every 6 seconds. `et` now waits the same 6 seconds (the `--keepalive` value plus one second) before it sends a probe. An idle session now sends about 2420 bytes a minute, the same as ET C++, down from about 2900. A link that stops answering is still declared dead and reconnected 10 seconds after the last packet arrived, 2 seconds sooner than ET C++. With `--keepalive 1`, `et` still probes every second.
