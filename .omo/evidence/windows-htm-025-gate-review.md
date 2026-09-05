# PR #99 lifecycle-fix delta gate review

recommendation: APPROVE
blockers: []
reviewedCommit: 598dd0b862100631128f90bf28063e64386bbfc7
comparisonBase: d5bd375be1874f62e4df6eec51ed5358003a744f
releaseBase: 214e81c
reviewWorktree: /home/minpeter/.cache/et025-htm-review
reviewer: omo-senpi-gate-reviewer / st_01a0723c

Both previous P1 blockers are resolved in this delta. No new requirement-violating finding was identified. This report supersedes the earlier REJECT for d5bd375; it does not retroactively approve that old head or reopen unaffected pane/protocol areas.

`omo-agent-toolkit ulw-loop status --json` again returned ULW_LOOP_PLAN_MISSING, so this is the required fallback report artifact. The only report/source write was replacement of this gate report; no implementation edits, commits or PR comments were made.

## originalIntent

Carefully review each PR before et@0.0.25. This re-review is explicitly limited to d5bd375..598dd0b: resolve native Windows automatic-start failure and the inability of `-x` to replace an attached session. Preserve selected-daemon isolation, Unix behavior, the shared SSH-bootstrap detach contract, protocol v6, fixtures, no-project-unsafe and no-test-suppression constraints.

## desiredOutcome

HTM starts and survives its launching UI inside a non-breakaway Windows host job, while honestly documenting that it cannot outlive termination of that job. A new UI can take over an attached daemon; `-x` closes the old UI, replaces only the selected daemon and leaves an unrelated daemon usable. Native hosted CI remains a merge gate, never inferred from GNU-built QA artifacts.

## userOutcomeReview

The delta delivers the requested outcomes. The Windows fallback is local to HTM, preserves handle-isolated/console-detached spawning and readiness rollback, propagates fallback errors, and emits an explicit host-job lifetime warning. `detach.rs` is unchanged. Moving authenticated acceptance to every server loop lets an already-attached UI be replaced without changing frame layouts or pane state logic.

I independently executed the retained Unix runtime artifact (5 passed) and the current native Windows runtime artifact (6 passed, 5.16s, exit 0). Both include the formerly failing attached-client path; native Windows also exercises a real non-breakaway Job. Native and Unix process checks found zero lane-owned ET processes afterward.

Hosted CI was pending at the first status check, but completed during review. The changed-head Windows job is now independently verified GREEN, including 16 native unit and 6 runtime tests. Linux/macOS tests, lint and ARM musl build statuses are also green. The separate cubic external review was still pending at the final status check. Approval is for this exact delta; normal merge gates and any subsequent changed-head checks still apply.

## Previous blockers: resolution and evidence

### B1 - resolved (formerly P1, C2-AUTO)

Original violatedCriterion: C2-AUTO, the task's automatic-start requirement; C4 required green CI before merge.

- Original observation: d5bd375's hosted autostart failed at `htm_daemon::spawn` with Access is denied (os error 5).
- Fix: `crates/et-bin/src/htm_daemon.rs:35-56`, commit 5ba9d62. Attempt the existing independent spawn first. Only native error 5 enables one HTM-local retry without BREAKAWAY_FROM_JOB; DETACHED_PROCESS, NEW_PROCESS_GROUP, explicit handle isolation and DropPolicy::Detach remain. Other errors and retry failures propagate.
- User-visible policy: README's Windows HTM section and the emitted warning say the daemon survives its launching UI but not its supervising job. This is not a silent relaxation of the etserver/etterminal SSH-bootstrap contract.
- Regression: `crates/et-bin/tests/htm_runtime.rs:124-173` creates a real Job, enables kill-on-close, assigns the child atomically through SpawnOptions::job, and runs the existing real-role scenario. The strengthened scenario at lines 104-109 proves pane identity survives the launching client's actual exit before requesting replacement.
- evidencePointer RED: `/home/minpeter/.cache/et025-htm-evidence/native-host-job-red.log` shows native error 5, nested failure, and outer `host-job HTM role scenario failed`.
- evidencePointer GREEN: `pr99-fix-native-host-job-green.log`; direct native run transcript below; changed-head hosted job https://github.com/minpeter/et.rs/actions/runs/33977437328/job/101336513852 .
- Verdict: resolved, including changed-head hosted native proof rather than only a separate QA-host pass.

### B2 - resolved (formerly P1, C2-X / C2-UNIX)

Original violatedCriterion: C2-X, selected-daemon-only `-x`, and C2-UNIX compatibility.

- Original observation: a second connection carrying `-x` remained unaccepted while the first UI was attached, causing timeout/exit 2 and leaving the old daemon alive.
- Fix: `crates/et-htm/src/server.rs:34-45`, commit 598dd0b. Service the nonblocking listener on every iteration, not only while detached.
- Authentication relationship: `poll_accept` closes the old endpoint only after `Listener::accept` succeeds. The unchanged Windows transport verifies the token before returning a stream, and returns WouldBlock on authentication failure; that path does not replace the current UI.
- Regression: `crates/et-bin/tests/htm_support/attached.rs:6-33` keeps selected and unrelated UIs initialized/open before `-x`, then asserts old UI exit, fresh selected pane identity and unrelated pane retention. The second test at lines 36-53 verifies ordinary takeover closes only the old UI and preserves pane identities.
- evidencePointer RED: `/home/minpeter/.cache/et025-htm-evidence/unix-attached-client-red.log` shows error 11 and failure to obtain replacement state with the old implementation.
- evidencePointer GREEN: `pr99-fix-unix-attached-green.log`; direct Unix/native runtime executions below; changed-head hosted job above.
- Verdict: resolved on both Unix and native Windows. Tests no longer detach before exercising this contract.

## Direct verification and QA matrix

| Criterion / scenario | Evidence personally checked | Result |
| --- | --- | --- |
| Restricted-job autostart and survival after client exit | Native RED/GREEN files, source, direct Windows runtime run, hosted Windows log | PASS |
| Attached `-x`, old UI exit, fresh selected daemon, unrelated daemon survives | Unix RED/GREEN files, source, direct Unix and Windows runtime runs | PASS |
| Ordinary attached-UI takeover preserves panes | Source, direct Unix and Windows runtime runs | PASS |
| Pane input/output, 37x113 resize, retained state and SESSION_END adjacent regressions | Existing scenarios included in direct runtime suites; no unrelated re-review | PASS |
| Shared detach policy and protocol boundary unchanged | Exact delta; explicit no-diff checks for detach.rs, et-core, Cargo.lock and CI workflow | PASS |
| No unsafe/test suppression introduced | Complete five-file delta inspected | PASS |
| Native hosted gate for changed head | Fetched job checkout and native test log, not status alone | PASS: 16 unit + 6 runtime |
| Cleanup | Native bounded wrapper's post-run process query; Linux /proc query | Zero lane-owned ET processes |

Direct Unix command, executed once:

```text
ET_HTM_TEST_BINARY=/home/minpeter/.cache/et025-htm-target/debug/et /home/minpeter/.cache/et025-htm-target/debug/deps/htm_runtime-05da8a22d4d9c248 --test-threads=1 --nocapture
Result: 5 passed; 0 failed; 0 ignored; finished in 3.95s
GATE_UNIX_LANE_ET_PROCESSES_REMAINING=[]
```

Direct native run: sent an in-memory PowerShell command through `ssh -o BatchMode=yes -o ConnectTimeout=10 windows`, without creating a script/log artifact. The command verified the lane was idle, set ET_HTM_TEST_BINARY to the adjacent et.exe, used cmd.exe as SHELL/COMSPEC, and ran:

```text
C:\Users\minpeter\AppData\Local\et025-htm-qa-st_01a071f7\htm_runtime.exe --test-threads=1 --nocapture
```

Stdout/stderr readers were active before the 120-second bounded process wait. Failure cleanup was restricted to the lane's absolute et.exe/runtime executable paths; no process-name fleet cleanup. The runner wrote no separate report/log files. Observed:

```text
attached::kill_replaces_an_attached_session_without_stopping_an_unrelated_daemon ... ok
attached::new_ui_takes_over_an_attached_daemon_and_preserves_its_panes ... ok
auto_start_and_kill_other_sessions_replace_only_the_selected_daemon ... ok
autostart_survives_client_exit_inside_a_nonbreakaway_host_job ... ok
panes_resize_and_reattach_through_real_roles ... ok
session_end_detaches_without_a_length_field ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; finished in 5.16s
GATE_NATIVE_RUNTIME_EXIT=0
GATE_NATIVE_OWNED_PROCESSES_REMAINING=0
```

The restricted-job scenario emitted the explicit lifetime warning twice. Its nested real-role test also passed; no assertion pins the warning text.

Local retained artifact hashes were recomputed and matched `pr99-fix-native-cleanup.log`; the remote et.exe and runtime hashes were printed by the direct run and matched as well:

```text
et.exe          11e92b5b6653fcbb5f16b484df7cb60114194a551f0177389605385169e52a7e
et_htm-unit.exe 943d7fa67a7117d30a126eb365f8c19e3e2e2cf34054445392e3a8fc40ba3587
htm_runtime.exe d9443103ca0b97486f77aa8c57b3296831758b3ac6387db92e924547b92abf48
```

## Hosted CI evidence: pending became verified GREEN

Fetched `gh pr checks 99 --repo minpeter/et.rs` before and after execution. Final statuses were green for build-windows, Linux and macOS tests, lint and ARM musl build; cubic remained pending.

Fetched the actual Windows job log:

```text
gh run view 33977437328 --repo minpeter/et.rs --job 101336513852 --log
HEAD is now at cfd2926 Merge 598dd0b862100631128f90bf28063e64386bbfc7 into 214e81ceab554c48c5c5696263372401d8ef7326
cargo test -p et-htm -- --test-threads=1 --nocapture
16 passed; 0 failed; 0 ignored; finished in 0.15s
cargo test -p et --test htm_runtime -- --test-threads=1 --nocapture
6 passed; 0 failed; 0 ignored; finished in 6.81s
```

The job includes attached-restart, autostart and real restricted-job markers, the explicit fallback warning, shell value 73 and geometry 37x113. Thus the previous hosted failure is not being waived based on GNU cross-build evidence.

## Direct remove-ai-slops / programming pass

The skill files were unavailable in the locations inspected earlier in this same review session; their supplied context criteria were applied directly. The executor's `FINAL-PR99-FIXES.md` section "Direct programming / overfit / cleanup review" was read and checked against the delta, rather than treated as approval evidence by itself.

- Excessive/useless tests: none found. Restricted host-job execution, attached restart, ordinary takeover and survival after launching-client exit cover distinct observable contracts affected by this delta.
- Deletion-only/requested-removal tests: none. No assertion merely checks removal of an error, flag or old source line.
- Tautological tests: none. Pane identity comparisons span actual process exit/replacement or takeover, and the job test checks a real nested process's behavioral assertions.
- Implementation-mirroring/overfit: no simulated AccessDenied return or mocked accept loop. The real OS Job reproduces B1; deliberately open UIs reproduce B2. RED files show these tests fail on the old behavior. Sharing an existing real-role scenario avoids duplicating its implementation, while the added post-exit reattach assertion closes a genuine false-positive path.
- Prose coupling: no warning/README text assertions. Tests consume process status, protocol state, pane identities and exact test-selection names.
- Timing/nondeterminism: channel/process/pipe/state waits are bounded; no new sleeps or polling-delay correctness. Job assignment uses PROC_THREAD_ATTRIBUTE_JOB_LIST, not spawn-then-assign. On timeout the job is terminated before joining the output worker. The new acceptance schedule retains the existing production cadence only when detached.
- Production extraction/parsing/normalization: none added. Fallback stays at the HTM policy call site; server change is a narrow admission-order fix. The extra file is test-only scenario organization, not speculative production abstraction.
- Cleanup/scope: existing Startup rollback remains around the successful child/readiness transaction; fallback failures propagate. The host-job test owns kill-on-close lifetime and terminates on timeout. Shared detach, protocol and dependency files are untouched. No suppression or unsafe added.
- Report coverage cross-check: the executor review explicitly addresses real behavioral REDs, non-mocked tests, atomic job assignment, bounded waits, no prose pinning, no speculative production helpers/dependencies/unsafe, limited cleanup claims, and no source/test suppression. It does not individually title every slop subtype; the complete explicit subtype pass above is this reviewer's own check. No independent second code-review artifact was supplied; that provenance limitation is a NOTE, not a new failed product criterion.

No maintenance-burden, false-confidence or scope-drift finding tied to a stated requirement remains in this delta.

## Checked artifact paths

Under `/home/minpeter/.cache/et025-htm-review/`, all five changed files were inspected:

- `README.md` (changed Windows HTM lifetime section)
- `crates/et-bin/src/htm_daemon.rs`
- `crates/et-bin/tests/htm_runtime.rs`
- `crates/et-bin/tests/htm_support/attached.rs`
- `crates/et-htm/src/server.rs`

Additional affected-boundary checks: unchanged Windows `transport_windows.rs:135-153`; unchanged `detach.rs` by exact diff; relevant windows-spawn 0.1.0 `command.rs`, `options.rs`, `handles.rs`, `sys.rs` job-list setup and `child.rs` concurrent output drainage. Dependencies were only read, not edited.

Under `/home/minpeter/.cache/et025-htm-evidence/`, read:

- `FINAL-PR99-FIXES.md`
- `native-host-job-red.log`, `unix-attached-client-red.log`
- `pr99-fix-native-host-job-green.log`, `pr99-fix-unix-attached-green.log`
- `pr99-fix-native-full-green.log`, `pr99-fix-native-cleanup.log`, `pr99-fix-unix-cleanup.log`
- `pr99-fix-unix-clippy.log`, `pr99-fix-windows-clippy.log`, `pr99-fix-windows-unit-clippy.log`
- `pr99-fix-unix-build-final.log`, `pr99-fix-windows-build-final.log`, `pr99-fix-fmt.log`

Also re-read the prior gate report before replacing it. The original notepad remains `/home/minpeter/.cache/omo-tmp/ulw-20260905-232253.pLyeqO.md`, already consulted in this review session; no new notepad claims were needed for the delta.

Worktree status was clean before and after execution. `git diff --check d5bd375..598dd0b` passed. At execution time, the executor worktree's Rust/Cargo source comparison against 598dd0b was empty.

## Exact evidence gaps / nonblocking notes

1. The external cubic review was pending at the final status check. Hosted build/test/lint gates are now observed green, not assumed pending or inferred from local runs.
2. No fresh reviewer Cargo build/clippy/LSP was run. Build/clippy logs were inspected; retained real-runtime artifacts were executed, and hosted source checkout/test execution was independently verified for this exact head. Empty fmt log alone is not a new independent formatter execution.
3. The supplied lead's native-run claim was not treated as an independently verified transcript; this reviewer separately obtained the 6-test/5.16s native result above.
4. Process cleanup observations cover the QA lane's ET/runtime executables, not an exhaustive descendant audit. Test fixture cleanup and supplied zero-fixture logs were inspected; no stronger fleet claim is made.
5. Survival after termination of a non-breakaway host job is explicitly not provided or promised. README and stderr disclose this limitation; the requested local-client lifetime contract is verified.
6. Unchanged pane/protocol implementation areas, aliases, other architectures and GUI behavior are outside this delta re-review. No new requirements were added for them.

Final disposition: APPROVE d5bd375..598dd0b. B1 and B2 are closed; no current delta blockers.
