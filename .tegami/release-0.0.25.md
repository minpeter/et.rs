---
packages:
  et:
    type: patch
---

## Interrupt large terminal output without losing session state

Keep unsent terminal output in interruptible queues. Ctrl+C drops large pending
floods while preserving small output, replay-owned frames, and control traffic.
Tmux responses can bypass queued pane floods without splitting incomplete control
records. Default nonterminal packet ordering remains unchanged during recovery.

## Run native Windows HTM sessions

Enable `et.exe htm` and `et.exe htmd` with ConPTY panes, authenticated local IPC,
resize, and retained-state reattachment. Restarting with `-x` replaces only the
selected daemon, including when its UI remains attached.

When Windows forbids job breakaway, HTM reports that its daemon remains inside
the supervising job. It survives the launching UI, not termination of that job.
The existing ET server and terminal breakaway policy remains unchanged.

## Exercise Windows runtime behavior in CI

Run native server, ConPTY, same-session recovery, HTM, and process cleanup tests
on Windows. Downloadable test artifacts run without a compiler on the QA host.
Failure cleanup covers early setup errors and concurrent process exits.
