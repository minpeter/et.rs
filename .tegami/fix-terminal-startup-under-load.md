---
packages:
  et:
    type: patch
---

## Keep terminal startup reliable under heavy load

Terminal startup now allows heavily loaded servers more time to create and
register a session process, while still reporting child startup failures
immediately instead of hiding them behind a generic timeout.
