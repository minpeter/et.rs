# PR98 corrected-tree delta gate review

recommendation: APPROVE
blockers: []
goalId: windows-runtime-025
reviewerTask: st_01a0727f
head: e1e376cd579dca8857f28ca03fb97aa24b4738f1
reviewTree: /home/minpeter/.cache/et025-win-ci-review
scope: 4b0e2e7..dd09ed2 plus merge resolution e1e376c

This supersedes the REJECT report at this path from st_01a07256, which was read in full before replacement. All three original blockers are resolved. This is a delta approval, not a second architecture review of independently approved HTM main df9e5d8.

`omo-agent-toolkit ulw-loop status --json` returned ULW_LOOP_PLAN_MISSING for this child. The required no-plan fallback report path is used. Only this report was written. No source edits, commits, PR comments, checkout changes or remote files were made. Native isolated runtime checks and in-memory PowerShell controls completed with cleanup.

## originalIntent

Carefully and independently review each feature PR before releasing 0.0.25. PR98 must replace Windows compile-only confidence with real foreground server/terminal/ConPTY execution, same-session recovery retaining shell identity and state, and observed descendant cleanup. A relocatable QA runner must preserve arguments and failures; fixture cleanup must work on early failure as well as successful teardown.

## desiredOutcome

A merge-ready native Windows runtime CI artifact with trustworthy real-surface tests, correct PowerShell command/exit behavior, deterministic failure cleanup and green CI on the corrected integrated head. Keep the approved HTM native coverage when resolving the workflow merge.

## Criterion mapping and userOutcomeReview

- C3: Native Windows server/ConPTY/same-session recovery passes; targeted production mutations reject regressions; no sleep/polling-based correctness.
- C3-RUNNER: Original gate label for the explicitly requested relocatable runner and PowerShell argument/exit behavior.
- C3-CLEANUP: Original gate label for the explicitly requested normal/lost-router descendant cleanup, panic cleanup and early failure cleanup.
- C4: Lead surface evidence, independent verdict, resolved blockers and green CI before merge.
- Scope: no production mutations, protocol/fixture/version changes, unsafe additions or test suppression in this PR. Approved HTM changes inherited from main are not PR98 production changes.

The corrected artifact satisfies the three failed behaviors. I independently ran the relocated native suite: 6 passed, 0 failed, 0 ignored, 6.43s, runner exit 0. Initial and recovered observations preserve shell PID 9156, descendant PID 8956 and GUID 3279afe713fc4abbb5d7952230e150cb. Both runtime exit scenarios observed shell/descendant completion and removed their fixtures. The setup-panic regression also printed its fixture removal and passed. The fallback regression both passes the corrected code and genuinely rejects the old fallback on native Windows.

Changed-head hosted MSVC execution is now verified, not pending or inferred: run 33979272953 and all five Actions jobs report SUCCESS at e1e376c. The Windows job actually executes the six runtime tests and both retained HTM targets. All seven reported PR checks pass. No remaining delta blocker is supported by the inspected artifacts.

## Original blocker delta

### B1 / C3-RUNNER: RESOLVED

Original failure: scalar PowerShell assignment discarded one argument; `--list` executed tests and a single invalid option incorrectly returned 0.

Fix: commit 428c819, `crates/et-bin/tests/windows_runtime_support/Run-WindowsRuntime.ps1:10-12`, explicitly declares `[string[]]$testArguments` and retains `exit $LASTEXITCODE`.

Independent native commands:

```
ssh -o BatchMode=yes -o ConnectTimeout=10 windows 'powershell -NoProfile -File C:\Users\minpeter\AppData\Local\Temp\et025-win-ci-st_01a071f8\Run-WindowsRuntime.ps1 --list'
# Six named tests, "6 tests, 0 benchmarks"; no runtime execution; exit 0.

ssh -o BatchMode=yes -o ConnectTimeout=10 windows 'powershell -NoProfile -File C:\Users\minpeter\AppData\Local\Temp\et025-win-ci-st_01a071f8\Run-WindowsRuntime.ps1 --gate-invalid-argument'
# error: Unrecognized option: 'gate-invalid-argument'
# INVALID_RUNNER_EXIT=101, explicitly asserted by the Linux command wrapper.
```

The default no-argument runner also executed the full six-test suite successfully. Remote runner SHA256 exactly matches the committed script.

### B2 / C3-CLEANUP: RESOLVED

Original failure: directory acquisition preceded reservation/address/config operations with no Stack cleanup owner yet constructed.

Fix: commit 696083c, `windows_runtime_support/mod.rs:40-70`. Reservation/address acquisition occurs before directory creation. Stack is constructed immediately after successful `create_dir`, without intervening fallible setup. The hook and config write run only after Stack owns cleanup.

Regression: `windows_runtime_support/setup_tests.rs:3-21` catches an injected panic after actual directory acquisition and before server spawn. It records directory existence BEFORE its own emergency cleanup, then asserts the recorded value is false. Thus its fallback cannot make the assertion pass. This is an actual filesystem ownership assertion, not an assertion that source text was removed.

Independent native suite receipt:

```
setup_failure_removes_the_acquired_directory ...
... injected configuration setup failure
FIXTURE_REMOVED C:\Users\minpeter\AppData\Local\Temp\et-win-1148-kjLiTUL1BHc4dcxP
ok
```

The hosted changed-head six-test target separately runs and passes this regression. The old ownership ordering with the same injected hook necessarily leaves `directory.exists()` true, so the new assertion rejects that behavior; this conclusion is control-flow inspection, not a claim of independently executing a compiled old Rust tree. The lead's claimed native setup RED is not counted as independently reproduced because its separate raw receipt was not located; see evidence gaps.

### B3 / C3-CLEANUP: RESOLVED

Original failure: one Stop/Wait exception in the probe finally abandoned later targets and their disposal.

Fix: commit dd09ed2, `windows_runtime_support/process_cleanup_probe.ps1:56-69`. Each target receives its own try/catch/finally, cleanup errors accumulate, disposal occurs for every processed target, and the aggregate is thrown only after the loop.

Regression: `fallback_probe.ps1:1-38` and `process_tests.rs:31-47` run the actual Test-ProcessCleanup function using two real ready, event-blocked native targets. The narrow overrides force an early body error, actually kill/wait each cleanup target, then inject a first-target cleanup exception. The test requires two cleanup calls and a visible failure. Its explicit exit 0 occurs only AFTER assertions and external cleanup; an uncaught assertion cannot reach it.

I additionally executed the committed fallback regression in memory with (a) the old `4b0e2e7:.../process_cleanup_probe.ps1` and (b) the current committed file. The shared helper and regression were identical between controls; only the actual function under test changed. Commands used PowerShell -NoProfile -NonInteractive -EncodedCommand via SSH, with gzip transport decoded entirely in memory to stay under Windows command-line limits. No script was written or source mutated.

```
OLD_FALLBACK_EXIT=1
probe fallback abandoned a remaining target
FIXED_FALLBACK_EXIT=0
FALLBACK_PROBE_PASS
```

The old run's external finally cleaned its remaining real target. This independently proves both genuine old-code rejection and that the explicit successful exit does not suppress assertion failures. The compiled native suite and hosted MSVC target also pass this test.

The injected error is a Win32 error category after a real process kill/wait, not a claim of manufacturing actual OS access denial. The count assertion proves that remaining native targets were processed; the aggregate implementation was separately read rather than inferred from the count alone.

## Manual QA / adversarial matrix

| Criterion / class | Evidence | Result |
| --- | --- | --- |
| C3-RUNNER zero args | Personal native runner, six tests, exit 0 | PASS |
| C3-RUNNER single list arg | Personal native runner lists six without running | PASS |
| C3-RUNNER single invalid arg | Personal native runner returns 101 | PASS |
| C3-CLEANUP setup panic before spawn | Personal native compiled regression; hosted MSVC regression; direct ownership trace | PASS |
| C3-CLEANUP first fallback error | Personal OLD exit 1 / FIXED exit 0 control, two real targets | PASS |
| PowerShell assertion failure cannot reach exit 0 | OLD control throws the intended assertion and returns 1 | PASS |
| C3 real ConPTY recovery | Same PID/PID/GUID before and after ReturningClient in personal run | PASS |
| C3-CLEANUP normal/lost-router exit | Both observed shell/descendant exits and fixtures removed in personal run | PASS |
| Earlier competing exit and error probes retained | Both native compiled probes pass personally and in hosted CI | PASS |
| Production output/recovery/cleanup mutation oracles | Raw historical RED receipts inspected; no changed oracle in delta | RETAINED |
| Merge resolution retains HTM coverage | Combined workflow diff plus actual hosted unit16/runtime6 | PASS |
| Scope/no suppression/no sleeps | Entire six-file correction diff, merge diff, caller grep | PASS |
| C4 changed-head CI | Exact run head and all five successful Actions jobs; all seven PR checks pass | PASS |
| Review-owned cleanup | Final native inspection: zero QA executables, probe targets and fixtures | PASS |

## Source and binary identity

- Locked detached tree is clean at e1e376cd579dca8857f28ca03fb97aa24b4738f1, lock reason `review:windows-runtime-025`.
- `git diff --check 4b0e2e7..e1e376c`: passed.
- Full `4b0e2e7..dd09ed2` correction diff inspected: six test/support files only.
- `git show --cc e1e376c`: only conflict resolution is the Windows workflow, preserving server artifact build/run/upload and HTM native unit/runtime commands.
- `git diff dd09ed2..e1e376c -- crates/et-bin/tests/windows_runtime_support`: empty.
- `git diff df9e5d8..e1e376c -- crates/et-bin/src crates/et-server/src Cargo.toml Cargo.lock`: empty. The full file list against approved main contains only workflow and Windows runtime tests/support.
- Local cross-build artifacts match remote Get-FileHash:
  - et.exe: a32e10b651a9eaecfc54aa4cb60ca729886f036ff43577bc130d180b76590242
  - windows_runtime.exe: 053aae01cf885dea7ed11affc8af08e0ee3d141b974dfb7435ff99d1a9ba8d88
  - committed runner: 1f9999091370bc62cd0dcb6c5f1acd31caf4855ce43635b92b53fdffd7fcb34a
- Local executable sources for those hashes: `/home/minpeter/.cache/et025-win-ci-target/x86_64-pc-windows-gnu/debug/et.exe` and `debug/deps/windows_runtime-a8cc739692c4dc49.exe`.

## Changed-head hosted CI evidence

Run: https://github.com/minpeter/et.rs/actions/runs/33979272953
Windows job: https://github.com/minpeter/et.rs/actions/runs/33979272953/job/101341418655

Fetched directly with:

```
gh api repos/minpeter/et.rs/actions/runs/33979272953
gh api repos/minpeter/et.rs/actions/runs/33979272953/jobs
gh api repos/minpeter/et.rs/actions/jobs/101341418655/logs
gh api repos/minpeter/et.rs/actions/jobs/101341418514/logs
gh pr checks 98 --repo minpeter/et.rs
```

Run head: e1e376cd579dca8857f28ca03fb97aa24b4738f1, status completed, conclusion success. Checkout log: `HEAD is now at 150e18d Merge e1e376c... into df9e5d8...`.

Actual native commands/results:

- `cargo test -p et --test windows_runtime -- --test-threads=1 --nocapture`: 6 passed, 0 failed, 0 ignored, 8.54s. INITIAL and RECOVERED both `3828:904:c3bdc1317c264c2ca00a449bfadcb19b`; all three fixtures removed; race/error/fallback probes pass.
- `cargo test -p et-htm -- --test-threads=1 --nocapture`: 16 passed, 0 failed, 0 ignored.
- `cargo test -p et --test htm_runtime -- --test-threads=1 --nocapture`: 6 passed, 0 failed, 0 ignored, 5.09s. The nested one-test restricted-job subprocess is additional output, not a replacement for the complete six-test result.
- Lint job actually runs `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`, successfully. This is hosted Linux workspace lint; it is not represented as fresh independent Windows-target clippy.

## Direct remove-ai-slops and programming review

Consulted the actual skill files:

- `/home/minpeter/.senpi/agent/omo-senpi/plugin/skills/remove-ai-slops/SKILL.md`
- `/home/minpeter/.senpi/agent/omo-senpi/plugin/skills/programming/SKILL.md`
- `/home/minpeter/.senpi/agent/omo-senpi/plugin/skills/programming/references/rust/README.md`

Applied their criteria directly to the diff, tests and relevant fixture implementation; no implementation/refactoring authorized.

- Excessive/useless tests: no finding. Two added regressions distinguish two concrete original failure paths. Existing real-runtime and competing-exit/error narratives remain intact.
- Deletion-only/requested-removal tests: none. The setup test observes actual resource cleanup, not removal of source tokens; no prose or inventory pins.
- Tautological tests: none. Setup checks filesystem state before emergency removal. Fallback requires real kill/wait completion and a failure; OLD native control rejects the old implementation.
- Implementation mirroring/over-mocking: the fallback uses narrow function overrides to reach the real finally with ready native processes. It does not replace the finally under test. Its call count is narrower than exhaustive OS-error coverage; that limit is explicit. No production ConPTY behavior is mocked.
- Unnecessary production extraction/parsing/normalization: none; no PR98 production delta against approved main. Existing machine-sentinel/protocol parsing is unchanged.
- Needless abstraction: `start_with_setup` is a private fixture seam with actual normal/test callers, necessary to inject a deterministic early failure. No new public production API or speculative generalized abstraction.
- Boundary/resource handling: Stack now acquires ownership at the correct point. Per-target broad catch is justified by the cleanup boundary and rethrows aggregated errors. Panic/unwrap usage is test-only. Explicit successful PowerShell exit does not hide uncaught assertions, as native RED demonstrates.
- Async/determinism: readiness tasks and kernel process/event waits are bounded; no added sleeps, polling delays, retries or suppression. Existing helpers are reused rather than copied into production.
- Comments explain injection/cleanup responsibility and the PowerShell implicit-status workaround; BDD markers are appropriate.
- Measured nonblank/noncomment line counts: runner 9, fallback probe 35, mod.rs 190, process cleanup probe 63, process_tests.rs 39, setup_tests.rs 17. No oversized changed module.
- No scope drift, new dependency, unsafe addition, dead production code or gratuitous normalization found in this correction.

### Code-review report coverage check

The original gate report explicitly documents the same skill perspectives and every requested overfit/slop class; it was read in full. The supplied earlier standalone review/delivery reports (`DELIVERY.md`, `reviewer-p2-assessment.md`, `reviewer-p2-delivery.md`) do not explicitly enumerate deletion-only, tautological, implementation-mirroring and unnecessary-production-parsing coverage. No separate updated correction code-review report was supplied/found in the evidence directory. This remains a report-coverage NOTE, not a new runtime criterion or a blocker. Neither previous report coverage nor its absence substitutes for the direct review above.

## Checked artifact paths

- Original report at this same path, read before replacement, including original criterion mapping and manual QA matrix.
- `/home/minpeter/.cache/omo-tmp/ulw-20260905-232253.pLyeqO.md` (full notepad supplied at review start).
- All six changed correction files under the locked tree; complete correction diff and combined merge/workflow diff.
- Relevant unchanged `windows_runtime_support/process.rs` and `process_cleanup.ps1` for ownership/error flow and shared callers.
- `/tmp/et025-win-ci-evidence/FINAL-PROOF-INDEX.md`.
- `/tmp/et025-win-ci-evidence/DELIVERY.md`.
- `/tmp/et025-win-ci-evidence/reviewer-p2-assessment.md`.
- `/tmp/et025-win-ci-evidence/reviewer-p2-delivery.md`.
- `/tmp/et025-win-ci-evidence/mutation-cleanup-native-red.log` and `mutation-cleanup-fallback.log`.
- `/tmp/et025-win-ci-evidence/mutation-output-native-red.log` (both missing INITIAL, 20 observed descendants exited).
- `/tmp/et025-win-ci-evidence/mutation-recovery-native-red.log` (missing RECOVERED after ReturningClient; 3 pass/1 fail; 32 descendants exited).
- Local current GNU binary paths and remote bundle named in Source and binary identity.
- Direct GitHub run/job/check API responses and native command outputs, embedded above; this report is the durable receipt of this review's executions.

## Exact evidence gaps and nonblocking notes

1. The lead's separate setup RED, corrected 6/6 GREEN and integrated 7.96s raw logs were not located in the supplied lane evidence directory or notepad-linked receipts. Their claimed timing/RED execution is not counted as reproduced. B2 is established by ownership/control-flow inspection plus independently executed current native and hosted regressions. B3 OLD/FIXED was independently reproduced here; current complete-suite proof is 6.43s and hosted proof is 8.54s.
2. No old compiled Rust setup tree was rebuilt or run in this read-only review. Old setup regression rejection is a direct source-level argument, explicitly distinguished from native OLD execution. The native setup failure itself was exercised on the corrected artifact.
3. Archived production mutation RED receipts were inspected, not rerun. They predate these fixture corrections; their unchanged runtime assertions and absence of PR98 production deltas preserve their relevance. Stale restoration requests in FINAL-PROOF-INDEX.md are not evidence of a current mutant: the clean integrated tree and diff against approved main establish current source state.
4. Local/remote GNU artifact hashes establish byte identity, not an independently reproduced source build. Current hosted checkout/build/MSVC execution independently binds the six-test result to e1e376c. The uploaded MSVC archive was not downloaded or re-executed here.
5. Fresh Windows-target clippy and the lead's integrated Unix HTM5 command were not independently rerun. Hosted Linux fmt/clippy and all platform checks were verified; hosted Windows executes both HTM targets. HTM implementation re-review is outside this delta's scope.
6. The first in-memory fallback control exceeded Windows command-line length; BOTH OLD and FIXED returned `The command line is too long`. Those are transport failures, not behavioral RED evidence. Gzip transport resolved that concrete limit without source/file changes; only the subsequent intended assertion failure and FIXED pass are counted.
7. New-head CI is no longer pending. Exact-head all-success responses were fetched after the lead update. This gate approval does not perform a merge or release.

## Final cleanup

After native full-suite and OLD/FIXED fallback controls, read-only Windows process/path inspection returned:

```
QA_EXECUTABLES=0 PROBE_TARGETS=0 FIXTURES=0
```

Final locked worktree status was empty at e1e376c. Existing shared artifact staging was retained for the lead; no fleet service or HTM QA resource was modified.
