# PR100 final gate review - re-review 1

recommendation: APPROVE
blockers: []

Reviewed head: `f40b1bae1c5bf20a9bff8afebd1bed2fe28dea43`
Reviewed delta: `4af16313bb71fabc93ee68dd93552d43062202a6..f40b1bae1c5bf20a9bff8afebd1bed2fe28dea43`
Base remains: `230e442141a3a5dc206a979dba9e64790f752418`
Locked tree: `/home/minpeter/.cache/et025-output-review`
Goal: `output-025`; reviewer task: `st_01a07296`

`omo-agent-toolkit ulw-loop status --json` again returned `ULW_LOOP_PLAN_MISSING`; this is the requested fallback report. This report supersedes the REJECT at `4af1631`. It is the same reviewer's blocker/delta re-review, not a new review panel or a reopening of approved Windows work.

## originalIntent

Port upstream #804's user-visible output interruption for 0.0.25: a default ET session must stop a large flood on Ctrl+C and accept the next command, preserving small output, reconnect/replay correctness, protocol v6, and tmux control records. Each feature PR requires independent review and green integrated CI before merge.

## desiredOutcome

The user reaches a usable prompt and sees `ET_CTRL_C_OK` from a subsequent shell command within the existing five-second surface contract, without corrupting encrypted frame ordering or fragmented tmux notifications/responses. Exact source-language parity with the C++ fd-drain loop is not required.

## userOutcomeReview

Both original source defects are corrected. The shared physical-write lock now protects sequence assignment through full send across the default terminal and synchronous control paths. Tmux promotion leaves incomplete records and response blocks behind an ordering barrier. Existing generic synchronous/recovery behavior is retained.

Independent current-head execution passed the frame-order regression, all 11 core interrupt tests, all 40 server unit tests, 12 runtime recovery tests, and the actual ET client/server + PTY flood/Ctrl+C/next-command scenario. Exact-head hosted CI is SUCCESS, including the full serialized Ubuntu workspace suite and native Windows integration. No remaining success-criterion failure was found in this six-file delta.

## Criteria and original blocker disposition

- **C1:** deterministic behavioral regression, real flood -> Ctrl+C -> next command, small-output and reconnect preservation.
- **C1-WIRE:** C1 plus the brief's explicit protocol-v6 and control/in-flight/replay ownership preservation requirements.
- **C1-TMUX:** the brief's tmux filtering/promotion requirement and intended preservation of response/control records.
- **C4:** independent per-PR review and green exact-head integrated CI before merge.

The suffixes identify the same stated requirements used by the original review; no new architecture or hardening criterion is added.

### B1 / C1-WIRE - RESOLVED by ca11ed1

Original finding: default asynchronous terminal writes could race synchronous control writes after encryption but before physical send.

Checked evidence:

- `crates/et-server/src/session.rs:40-49,268-271`: shared `write_serial` ownership; synchronous writes acquire it before `connection` and retain it through the write result.
- `crates/et-server/src/session_flow_write.rs:38-41,56-79,88-91`: both platform paths acquire the same lock before preparing/encrypting and keep it through complete physical transmission and result handling. Unix still releases the connection mutex during physical send, permitting connection-only reads.
- `crates/et-server/src/session_recovery.rs:99-103,141-143`: candidate installation and held-packet flushing use the same ordering before the connection mutex.
- `crates/et-server/src/session_output_interrupt_test.rs:17-77`: prepared-frame gate and actual peer decryption/order assertions.

The default routing predicate remains TerminalBuffer-only for new asynchronous staging; generic packets are not routed asynchronously again. Existing headers 31/32 catchup and header 40 live-write-timeout regressions pass.

Lock/cancellation audit: the physical write paths consistently acquire serial before connection. Recovery pauses flow admission and waits for in-flight completion before taking its snapshot; candidate network I/O remains off the session connection lock. Queue admission during recovery remains plaintext holding, not a second physical sender. Flow-state waits release their mutex, and no new opposite connection-then-serial acquisition was found in the affected paths. The writer checks hard-stop after obtaining serialization; existing bounded live-send behavior and before-replay/replay-owned result distinctions are unchanged. The full server unit run passed hard shutdown, graceful drain, failed preparation, replay reset, hold-flush recovery, and terminal-HUP recovery cases.

The new regression passes on the current production code and checks two actual encrypted frames rather than a callback or mutex boolean. See the nonblocking coverage note below about its adaptive scheduling probe.

### B2 / C1-TMUX - RESOLVED by f40b1ba

Original finding: promotion could append earlier pane bytes inside an incomplete notification or unfinished response block.

Checked evidence:

- `crates/et-core/src/output_interrupt.rs:131-150`: scan from the existing stream state, record only newline boundaries outside a response block, partition only that complete prefix, append the untouched suffix after the reordered prefix.
- `crates/et-core/tests/output_interrupt.rs:213-230`: fragmented `%window-add` and `%begin`/reply awaiting `%end`, with termination arriving after the initial drain; expected complete stream is derived from the original pane/fragment/ending inputs.
- Existing complete-response-priority and partial-owned-line filtering tests remain unchanged and pass.

The prefix boundary cannot exceed the input slice and does not split a line. A trailing incomplete notification or still-open response block cannot be moved ahead of previous pane output. When the suffix later closes, normal complete-record promotion remains available. Already-observed stream state participates in boundary scanning; no reset of response/prefix ownership was introduced. Packet reconstruction and queue admission limits are unchanged.

## Independently executed current-head verification

All local commands ran in the locked review tree with:

```text
TMPDIR=/home/minpeter/e25tmp
CARGO_TARGET_DIR=/home/minpeter/.cache/et025-output-target
CARGO_INCREMENTAL=0
CARGO_BUILD_JOBS=6
```

| Command | Result |
| --- | --- |
| `cargo test -p et-server --lib -- --test-threads=1` | 40 passed, including new encrypted frame-order test and both original interrupt tests |
| `cargo test -p et-core --test output_interrupt -- --nocapture` | 11 passed, including fragmented notification/block and complete-response promotion |
| `cargo test -p et-server --test runtime_recovery -- --test-threads=1` | 12 passed |
| `cargo test -p et --test output_interrupt_tty_qa -- --nocapture` | 1 passed, 2.78 seconds total |
| `cargo fmt --all --check` | exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| `cargo build --workspace` | exit 0 |
| `git diff --check 4af1631..HEAD` | exit 0 |

These commands passed in a single execution each. No source mutation, test suppression, test deletion, or retry-to-green was performed. No new LSP-clean claim is made; compiler and clippy were executed. The earlier full-diff review and its successful golden/protobuf checks remain historical evidence; they are not relabeled as new local executions.

### Native user surface

Read `/home/minpeter/.cache/et025-output-tmp/native-reviewed/default-output.txt` and inspected marker-bearing lines 34,38,39,41 of `default-output.ansi`.

- Native Unix ET client/server and PTYs, `mode=none`.
- Encrypted path throttled to 102400 bytes/second; saturation event at 131072 bytes.
- Lead artifact: `ctrl_c_prompt_millis=485`, `scenario=Ok(())`, client killed/reaped, proxy cleanup OK, `stack_removed=true`.
- Transcript contains `ET_FLOOD_START`, `ET_INTERRUPTED`, `ET_FLOOD_STOPPED`, and shell-produced `ET_CTRL_C_OK` in order.
- Independent reviewer rerun: same shipped real-surface test passed in 2.78 seconds total. This total is not claimed as the measured Ctrl+C-only latency.

The SSH replacement is a local bootstrap adapter, not an emulated ET data path. No Windows output-flood GUI, iTerm2 GUI, or real SSH-authentication proof is claimed.

### Exact-head hosted CI - C4 met

Independently ran:

```text
gh run watch 33981990289 --repo minpeter/et.rs --exit-status --interval 10
gh run view 33981990289 --repo minpeter/et.rs --json headSha,conclusion,status
```

Watch exited 0; final metadata is `completed`, `success`, exact head `f40b1bae1c5bf20a9bff8afebd1bed2fe28dea43`.

Inspected real job logs using `gh api repos/minpeter/et.rs/actions/jobs/<job>/logs`:

- **Ubuntu 101348733526:** `cargo test --workspace -- --test-threads=1`; the log explicitly shows the new frame-order and fragmented-tmux tests passing, native flood QA passing in 2.92 seconds, core 11/11, server 40/40, recovery 12/12, and all other workspace test results passing.
- **Windows 101348733509:** native runtime 6/6 with `CONPTY_RECOVERED`; HTM unit 16/16 and role 6/6. Confirms integration of the lock delta with approved base functionality, not a new review of that functionality.
- Run job metadata also confirms lint, macOS scoped tests, and ARM musl build success.

Run: https://github.com/minpeter/et.rs/actions/runs/33981990289

## Direct remove-ai-slops / programming delta pass

Consulted the criteria loaded during the original review from:

- `/home/minpeter/.senpi/agent/omo-senpi/plugin/skills/remove-ai-slops/SKILL.md`
- `/home/minpeter/.senpi/agent/omo-senpi/plugin/skills/programming/SKILL.md`
- `/home/minpeter/.senpi/agent/omo-senpi/plugin/skills/programming/references/rust/README.md`

Applied them directly to the six-file delta, production paths and added tests. No cleanup/refactor procedure overrides the read-only assignment.

- **Excessive/useless tests:** two focused regression additions cover the two actual review findings; no count-based or speculative test expansion.
- **Deletion-only / requested-removal-only tests:** none. Both regressions assert delivered data/record ordering, not absence of source code or a removed symbol.
- **Tautologies/prose pins:** none. Expected frames and stream bytes come from test inputs; no production parser is used to construct an equivalent expected projection, and no prose is pinned.
- **Implementation-mirroring/overfit NOTE:** the frame-order test uses `write_serial.try_lock()` to choose its schedule. When the original implementation lacks serialization, it waits for control completion before releasing the prepared frame; actual decryption then distinguishes the original defect. On the fixed path it releases without an event proving the control thread has entered its send call. Consequently this test is not independent evidence against every partial-lock mutation (for example, removing only the synchronous guard while retaining the flow guard). This is a coverage/maintenance note, not proof of a failure in the inspected implementation, whose two guards and complete lifetimes were checked directly. No partial-lock mutation was executed.
- **Timing:** new waits are bounded channel events, not sleeps or guessed saturation delays. Fixed-path correctness does not require the sender to win a scheduling race because production serialization holds. Existing unchanged recovery-test sleep limitations from the first review remain notes, not new delta changes.
- **Extraction/parsing/normalization:** no new abstraction or normalization layer. The extra stream scan is necessary to locate a complete record/block boundary and reuses the existing observer. Shared serialization fixes the common physical-write ownership requirement across the relevant paths.
- **Types/errors/resources:** lock guards are RAII, poisoned locks propagate existing typed failures, test hooks are cfg(test), and no unsafe block, dependency or warning suppression is added. Tests join the sender and shut down the session before final byte assertions on the normal exercised paths.
- **Scope:** six files only, 131 insertions/1 deletion; no unrelated platform, fixture, protocol-version or vendor changes.

### Lead review report coverage

Re-read `LEAD-REVIEW.md`: it still describes head `4af1631` and does not explicitly contain the requested remove-ai-slops/programming and overfit/slop checklist. The updated notepad supplies the two fixes and their validation narrative, not that complete explicit perspective check. This remains a report-coverage NOTE; the direct current-head skill-perspective review above was performed independently and is not replaced by executor claims.

## Checked artifact paths

Current-head files, relative to `/home/minpeter/.cache/et025-output-review`:

```text
crates/et-core/src/output_interrupt.rs
crates/et-core/tests/output_interrupt.rs
crates/et-server/src/session.rs
crates/et-server/src/session_flow_write.rs
crates/et-server/src/session_output_interrupt_test.rs
crates/et-server/src/session_recovery.rs
```

Affected context consulted: `crates/et-server/src/session_io.rs`, `crates/et-server/src/session_flow.rs`, and the original ownership/transport context already inspected in the first review.

Evidence artifacts inspected:

- Prior version of this gate report (original B1/B2 and full-diff audit).
- `/home/minpeter/.cache/omo-tmp/ulw-20260905-232253.pLyeqO.md`, especially the original criteria and appended PR100 blocker/fix/validation entries.
- `/home/minpeter/.cache/et025-output-tmp/LEAD-REVIEW.md`.
- `/home/minpeter/.cache/et025-output-tmp/native-reviewed/default-output.txt`.
- `/home/minpeter/.cache/et025-output-tmp/native-reviewed/default-output.ansi` marker-bearing lines.
- Exact-head PR/run metadata and hosted job logs identified above.

Historical evidence retained from the first review: the actual principal server RED at `/home/minpeter/.cache/et025-output-tmp/red-server-real-output.log`, upstream production comparison at `initial-evidence/upstream.diff`, `RESUME-QA.md`, and native-final transcript. These are not claimed as newly reproduced historical executions.

## Exact evidence gaps / nonblocking limitations

1. The new fixes' RED exits and `OUTPUT_REVIEW_FIXES_PASS` local full-suite sentinel are recorded in the notepad/lead delivery, but no separate raw logs for those commands were supplied in the evidence directory. I did not mutate the locked tree to replay RED. Current GREEN was independently executed, and current full-workspace success was verified from exact-head hosted logs.
2. The adaptive frame-test coverage limitation and missing explicit skill checklist in the lead report are described above; neither establishes a remaining C1/C4 failure.
3. No exhaustive interleaving/partial-lock mutation proof, new combined interrupt/reconnect GUI scenario, native Windows Ctrl+C flood UI, iTerm2 UI, or real SSH-authentication validation is claimed.
4. The upstream ledger checker was not rerun. The delta does not change its files or prematurely mark #804 ported.
5. External review comments inspected were attached to old head `4af1631`; they are not evidence that the new fixes pass or fail. This assigned re-review assesses B1/B2 and the six-file delta, rather than starting another whole-PR review panel.

## Cleanup and final state

The actual PTY test performs its existing client kill/reap, reader/proxy join and Stack cleanup before final behavior assertions. After this re-review's runtime execution, process inspection found no matching `et025-output-target/debug/et` or `et-rs-flow-control-qa` processes; no matching private QA stack directories remained under `/home/minpeter/e25tmp`. Shared fleet services were untouched.

The locked review tree remained clean at `f40b1bae1c5bf20a9bff8afebd1bed2fe28dea43`. The only authored artifact is this gate report. No source edits, commits or PR comments were made.

**Final decision: APPROVE at f40b1ba. Both original blockers are resolved and exact-head integrated CI is green.**
