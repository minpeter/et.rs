---
packages:
  et:
    type: patch
---

## Mark log timestamps as UTC

`et`, `etserver`, and `etterminal` log lines now use an RFC3339 timestamp with
an explicit `Z` UTC marker, for example `2026-10-14T02:48:00.123Z`. The
previous `YYYY-MM-DD HH:MM:SS,mmm` form was UTC with no zone, so a reader
could treat `02:48` as local time. Log file names are unchanged. Protocol v6
is unchanged.
