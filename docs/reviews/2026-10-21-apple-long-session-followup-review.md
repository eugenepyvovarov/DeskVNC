# Review of changes after the Apple long-session task list

Date: 2026-10-21. Baseline: `abfaecbc5f0ced4b8673b97fe3b97d5a40b0c627`. Reviewed HEAD: `cf2e6658f52c89cc1960c2329a1fe6d1e4d293b8` on `feature/apple-screen-sharing-driver`.

Scope: all 15 subsequent commits, including 13 fix commits, the new production tests, [progress claims](../plans/2026-10-20-apple-long-session-progress.md), and review harness changes. The working tree was clean at review start. This review adds only this report and offline reproduction files; production code and live sessions were unchanged.

The pass fixes several real defects, but it is **not yet a complete freeze/recovery fix**. Five high-priority findings below concern unsafe stream replacement, connection-boundary ordering, and incomplete loss/backlog handling. Four smaller lifecycle/feedback issues also need correction. Existing tests pass where the environment permits them, but miss these boundary cases.

## Findings

### F1 — P1: evicting a stream also discards its replay protection

**New regression:** `dcf7351`. **Tasks:** STREAM-01/EPOCH-01. **Evidence:** current-source packet probe.

**Code:** [video.rs:77](../../crates/apple-core/src/video.rs#L77), particularly removal at 87 and fresh-context creation at 134. Selection at 190–202 permits the candidate to replace the current stream after a stall or a local generation change.

Eviction removes the entire retired entry, including its accepted packet index and replay bitmap. A previously accepted packet from that SSRC is subsequently treated as unknown and authenticated with a fresh clone of the media keys. Authentication succeeds because the packet is genuine old traffic; its replay history is gone. If it contains configuration and a key picture, it can be adopted and published again.

Reproduced sequence:

1. Accept SSRC 1, sequence 0, containing configuration/key picture K. Confirm its exact duplicate is rejected.
2. Adopt SSRCs 2 through 33, evicting the oldest retired entry.
3. After more than 750 ms without a completed picture, submit the **same bytes** of K again, in the current generation. Normal idle can also meet this selection threshold.
4. One AU is published and `active()` changes from SSRC 33 back to SSRC 1.

This is a reference/display correctness and anti-replay regression. It does not require forged authentication. Delayed/replayed old media can replace current content after sufficient stream churn.

**Correction:** separate reclaimable decoder/assembler memory from retired cryptographic identity/replay records. Define a bounded identity/tombstone policy tied to verified key/encoder epochs; if safe reclamation is unavailable, use a controlled fresh-key/full-connection transition rather than recreating an old identity from the same keys. Preserve active replay state and prevent authenticated old traffic from allocating a clean slate.

**Required regression:** after more than 32 replacements, the exact accepted old packet remains rejected even after picture silence exceeds the selection timeout; a genuine new replacement still succeeds and memory remains bounded. Existing `an_encoder_replacement_beyond_the_stream_limit_is_adopted` checks adoption and map size, not this property.

### F2 — P1: a new local generation lets delayed retired video take over

**New regression:** `dcf7351`. **Tasks:** STREAM-01/EPOCH-01. **Evidence:** current-source packet probe; no eviction needed.

**Code:** [video.rs:156](../../crates/apple-core/src/video.rs#L156), especially 161–166, followed by selection at 190–202.

The change clears retirement when a packet arrives under a generation newer than the retirement generation. The replay window is retained, which rejects packets already consumed, but it does not reject an **unseen delayed** packet from the old encoder. A local re-offer counter does not prove that the packet belongs to a newly restarted encoder.

Reproduced sequence: adopt A/seq0 in generation 1; hold A/seq1 key picture in flight; adopt B in generation 2; increment to generation 3 and perform the current epoch reset; deliver A/seq1. It authenticates as unseen, becomes eligible again, replaces healthy B, and is published as replacement video. No 750 ms stall is required because the generation difference permits replacement immediately.

**Correction:** do not equate local request generation with authenticated sender incarnation. Correlate replacement negotiation/configuration and epoch state before readopting a retired SSRC. Retaining replay state alone cannot distinguish a late unseen old packet from legitimate reuse. Design this together with F1 and the still-open EPOCH-01 work.

**Required regression:** a delayed previously unseen key picture from a retired encoder cannot satisfy a later re-offer or replace a healthy current stream. A separately validated legitimate SSRC reuse must still work. The new reuse test supplies a packet with a greater sequence number but no wire-level new-incarnation discriminator, so it currently blesses this ambiguity.

### F3 — P1: the connected effect can destroy the new attempt's first decoder

**New regression:** `1bf645a`. **Tasks:** REN-01/OBS-01. **Evidence:** actual React scheduling reproduction plus current renderer methods.

**Code:** [Session.tsx:1119](../../ui/src/screens/Session.tsx#L1119), [WebGLRenderer.ts:784](../../ui/src/render/WebGLRenderer.ts#L784), and independent frame dispatch in [useSession.ts:420](../../ui/src/hooks/useSession.ts#L420).

`beginConnectionAttempt()` is destructive: it closes all H.264 contexts. The new call runs in a passive React effect after `connected` state commits. Connection events only schedule React state, whereas binary frame callbacks immediately deliver frames to the renderer. The first IDR can therefore create/configure the **new** decoder before the passive effect runs; the effect then closes that decoder. Subsequent deltas find no context and are discarded without a fresh-picture request from this path.

The probe uses real React `useState`, `useEffect`, `createRoot`, and `act` with equivalent lifecycle wiring: queue connected, submit the first IDR before effects flush, then flush and send a delta. The new decoder is closed, the delta is not decoded, and no recovery callback is called. This establishes a permitted scheduling failure, not its frequency in the native application.

There is a related incomplete boundary: `beginConnectionAttempt()` does not advance renderer `generation` or invalidate `pending`, `pendingBytes`, or `pendingLayout`. An old queued IDR can instantiate a decoder after the boundary. That underlying stale-message architecture predates this patch; the new reset API has not completed the epoch fencing claimed by the progress note.

**Correction:** deliver an ordered attempt boundary before any media belonging to it, outside a delayed UI effect. Make the boundary idempotent per attempt; invalidate prior queued/in-flight work independently of framebuffer size while deliberately retaining the last displayed texture. Wire identity is needed to reject late old IPC messages as well as locally queued messages.

**Required regressions:** connected plus first IDR before passive effects, same-size reconnect, an old queued IDR/layout across the boundary, and new-epoch IDR followed only by deltas. Current-attempt references must survive; old work must not configure the new decoder.

### F4 — P1: loss of the first slice of a new picture still publishes its surviving tail

**Incomplete fix:** `4f71327`. **Tasks:** RTP-01. **Evidence:** current-source packet probe. This loss case existed before the patch; the new damage flag only fixes a subset of the task.

**Code:** [h264.rs:335](../../crates/apple-core/src/h264.rs#L335) marks `self.timestamp`, and [h264.rs:367](../../crates/apple-core/src/h264.rs#L367) clears damage when the arriving packet carries a different timestamp.

Reproduced sequence: complete seq1/timestamp100; lose seq2, the first slice of timestamp200; receive seq3, a marker-terminated IDR tail at timestamp200. On reorder expiry the gap damages timestamp100, the last observed timestamp. Assembly then sees 200, clears the damage flag, and publishes the surviving tail as a complete key picture.

The new regression starts with an already-observed first slice of the damaged timestamp, so it cannot detect this case. Publishing incomplete independent pictures can reintroduce the reference corruption the task intended to prevent.

**Correction:** handle uncertainty about which access unit contains missing packets. Conservatively abandon the affected first post-gap timestamp unless a verified picture-start/completeness contract establishes it is complete; do not assume a changed timestamp means the surviving packet is a complete new picture. Keep useful repair before abandonment separate from this decision.

**Required regressions:** missing first/middle/last slice, a whole lost picture, first observed packet being a tail, wraparound gaps, and a clean subsequent independent picture. Never publish a damaged timestamp as a complete independent AU.

### F5 — P1: the picture that triggers backlog reset can still be decoded unconfigured

**Incomplete fix:** `40a59c6`. **Tasks:** REN-02. **Evidence:** standards-faithful decoder mock.

**Code:** [WebGLRenderer.ts:1366](../../ui/src/render/WebGLRenderer.ts#L1366), with the earlier configuration check at 1343 and actual decode at 1389.

The new `configured === false` check happens before the queue threshold. If a configured decoder already has four pending requests when an independent **non-IDR** picture arrives (`key=true`, `reset=false`), the same call resets it, sets `configured=false`, clears `h264Behind` because the input is a key picture, and then calls `decode()` on the unconfigured decoder. It throws; the silent catch closes the context and drops the recovery picture.

The added production test triggers overload using a delta and sends the key on a later call. That case is repaired. It does not cover a key picture triggering overload itself. Ordinary Apple IDRs usually recreate the context before this branch, so this finding specifically concerns the supported independent non-IDR path. A prior fresh-picture request may eventually recover again; permanent failure is not proven by this case alone.

**Correction:** after reset, recreate/reconfigure before submitting the current independent picture, or retain it for immediate submission to a configured replacement. Clear `behind` only after configuration and submission succeed.

**Required regression:** queue4 + current independent non-IDR picture decodes on its first attempt, without an unconfigured decode exception. Also retain delta-overload/key-later and IDR cases.

### F6 — P2: closing the event consumer becomes a retryable publisher failure

**New interaction:** `f471112`. **Tasks:** LIFE-02/REC-02. **Evidence:** traced control flow; fake-peer integration not executed.

**Code:** [session.rs:1272](../../crates/apple-core/src/session.rs#L1272), worker classification at 2166–2173, error return at 2289–2293, and ignored event emission failures at 784/791–799.

`publish()` returns false when the event sink is closed, so its task exits. The new supervision treats that intentional consumer disappearance as an unexpected media-worker fault and reconnects. If the command sender remains alive, the driver can keep attempting remote authentication with no consumer able to receive the output. Application shutdown may independently cancel/drop commands, but that lifetime invariant is not enforced here.

**Correction:** obtain typed worker outcomes and stop on `EventSinkClosed`/cancellation. Treat a failed reconnect-state emission as a terminal consumer failure, as the shared supervisor does. An unexpected worker panic with an open sink should still reconnect after cleanup.

**Required regression:** retain commands, close events after connected/first AU, and assert bounded teardown with no additional authentication attempts. Separately test a real worker failure with an open consumer.

### F7 — P2: the stable-uptime reset includes handshake and teardown time

**Incomplete fix:** `49c4021`. **Task:** REC-02. **Evidence:** source-confirmed timestamp provenance; fake-peer timing not executed.

**Code:** [session.rs:748](../../crates/apple-core/src/session.rs#L748) through 765, then 789 and 824–827.

`started` is captured before `connect()`, and `uptime` is measured when it returns. A 61-second handshake that never reaches connected resets the backoff just like a stable session. Connected time plus up to 25 seconds of teardown can also satisfy the threshold. The arithmetic unit test only tests a supplied duration and cannot distinguish these cases.

**Correction:** capture `connected_at` at the connected transition and measure actual connected time at failure, excluding handshake and teardown. Reuse the shared supervisor contract where possible.

**Required regression:** distinguish 61 seconds never connected, 59 seconds connected plus 25 seconds cleanup, and 61 seconds connected. The first two must preserve consecutive-failure backoff. Fast repeated failures now correctly grow the delay; that improvement is real.

### F8 — P2: FIR numbering is global, not per sender/target pair

**Incomplete fix:** `b4d5779`. **Task:** RTCP-01. **Evidence:** production packet-builder probe and current ownership.

**Code:** [session.rs:139](../../crates/apple-core/src/session.rs#L139), its single receiver-task instance at 1310, and use at 187; [rtcp.rs:35](../../crates/apple-core/src/rtcp.rs#L35).

One counter serves every media target. A/B/A produces 10/11/12, advancing A by two. After 255 intervening commands for B, A gets its previous sequence again. [RFC 5104 section 4.3.1.1](https://www.rfc-editor.org/rfc/rfc5104.html#section-4.3.1.1) defines this sequence space per source/target pair and requires incrementing within that space.

**Correction:** retain pair-specific sequence state under the stream-identity policy; keep rate limiting separate. Test returning targets, wrap, new commands, and repetitions. The single-target primitive is improved and correct for that narrow case. Actual macOS impact remains unmeasured, and PLI/legacy feedback are also sent, so this is not evidence that every recovery request fails.

### F9 — P2: ReconnectNow during backoff no longer resets the attempt ladder

**Changed behavior:** `49c4021`. **Task:** REC-02. **Evidence:** source-confirmed retry-state trace.

**Code:** [session.rs:800](../../crates/apple-core/src/session.rs#L800), `wait_for_retry` at 831–861, versus explicit reconnect handling at 772–777.

Removing the unconditional reset correctly preserves automatic backoff, but `wait_for_retry()` still returns the same boolean for elapsed time and ReconnectNow. A manual retry interrupts the wait immediately; if it then fails, the previous attempt count remains, unlike the connected-session manual path and shared supervisor behavior.

**Correction:** distinguish elapsed/retry-now/stop outcomes and reset the ladder only for explicit retry-now or verified stable connected time. If sticky manual backoff is intentional, document that policy divergence.

**Required regression:** build up an eight-second backoff, interrupt manually, fail the immediate attempt, and check the intended next delay. This finding does not mean the button fails to retry immediately.

## Changes that hold up in this review

The pass is substantive. The following corrected behavior has production test coverage and no counterexample was found for the stated narrow case:

| Change | Verified improvement | Qualification |
|---|---|---|
| BUF-01 | Removes pre-recovery delta prefix and retains valid successors | Stream/epoch fencing is separate |
| PAD-01 | Reads padding from plaintext after decrypting; valid padded packets round-trip | Empty padding-only payload still needs downstream sequence integration |
| Fragment cap | Bounds an unfinished FU while growing | Not a total process/queue byte budget |
| RTP-02 | Counts every far-gap sequence, orders configuration, expires nearest sequence across wrap | Empty payload sequencing and full AU damage policy remain incomplete |
| REN-01 policy | Healthy output clears sparse accumulated errors; async errors ask for a fresh picture | Attempt orchestration has F3; no-output/presentation escalation remains open |
| Renderer metadata/resources | Timing map is count-bounded; refused decoder is closed | This is not a decoder no-output watchdog |
| REN-02 common path | Delta causes reset, then a later independent picture rebuilds configuration | F5 covers the independent picture causing reset itself |
| STREAM-01 capacity | More than 32 distinct replacements can be adopted with a bounded map | F1/F2 make the current identity policy unsafe |
| Retry arithmetic | Fast consecutive failures grow 500 ms to 8 s | F7/F9 concern reset semantics, not the growing ladder |
| Display admission | Rejects a concurrent request; closed reply no longer panics | Not a queued second request; fake-session verification absent |
| Worker outcome | Unexpected video/publisher exit can return an attempt error | F6 needs terminal consumer closure classification; common joined cleanup remains open |

No measured performance improvement or long-session readiness is established by these unit tests alone.

## Verification performed

| Command/check | Result in this environment | Interpretation |
|---|---|---|
| `cargo test --offline -p apple-core` | **119 passed; 4 failed at loopback bind with EPERM** out of 123 | Same four environment-blocked tests as the original review; not observed production assertion regressions |
| `cd ui && npm test -- --reporter=dot` | **488 passed, 30 files** | Full current UI suite |
| `cd ui && npm run typecheck` | Passed | Current TypeScript check |
| Resolution review Rust/UI harnesses | **5 Rust + 3 UI passed** | Previous eight resolution reproductions remain green |
| Original long-session Rust characterization harness | **66 passed, 8 ignored** | Includes new imported tests and three still-active old defect characterizations; not a release gate |
| Original long-session renderer characterizations | **5 failed** | They still assert old bugs that have changed/fixed; these failures are not five production regressions |
| Fresh follow-up Rust harness | **68 passed: 63 imported tests + 5 new characterizations** | Reproduces F1/F2/F4 plus two inherited integration gaps |
| Fresh follow-up UI harness | **5 passed, 2 files** | Reproduces F3/F5, incomplete local fencing, and inherited synchronous-error feedback omission |
| FIR packet-builder probe | A/B/A = 10/11/12; returning A repeats after 255 B commands | Demonstrates current global-counter ownership, not actual Mac response |

The socket-blocked tests are `a_lost_picture_is_asked_for_again`, `a_request_is_not_sent_twice_in_a_row`, `interrupted_record_read_keeps_partial_ciphertext`, and `releasing_everything_held_says_so_on_the_wire`. No permission bypass or live Mac test was used.

Reproduction source, commands, and limitations: [follow-up probes](apple-long-session-followup-probes/README.md). These new probes assert **observed unwanted behavior**, so passing confirms the reproduction rather than a fix.

## Progress claims to correct

- STREAM-01 is capacity-improved but not safe/completed: F1/F2 directly violate its stale/replayed-stream constraints.
- RTP-01 and REN-02 need the missing boundary cases F4/F5 before their fixed labels cover the requested behavior.
- REN-01's reset method exists, but its attempt ordering/fencing is not fixed (F3).
- RTCP-01 numbering is session-global, not yet per sender/target pair (F8).
- REC-02's ladder grows, but stable connected time and manual reset semantics need F7/F9.
- DISPLAY-01 rejects a second operation with a notice. It does not make it wait in a queue. Rejection is a reasonable safe policy, but the progress description should say so.
- The progress introduction says every fixed item has a production regression, but its DISPLAY-01/LIFE-02 rows explicitly have none. Distinguish implemented logic from integration-verified behavior.
- The old probe README's statement that a red harness means a fix regressed is incorrect for inverse characterization assertions. Identify which corrected-behavior or historical assertion failed. Rust ignores and still-active UI inverse tests also need separate run instructions/status.

## Important unchanged backlog

Do not count these as new regressions introduced by this diff; they remain central to the original freeze report:

- **EPOCH-01:** the local re-offer still resets SRTP ROC/replay history. The active old characterizations still demonstrate ROC-2 continuation rejection and replay readmission. The new cache policy does not solve it.
- **OBS-01/REC-01:** backend assembly can continue while decoding/drawing is frozen; no end-to-end progress acknowledgement or bounded stage-driven escalation exists. Ineffective re-offers can still repeat indefinitely.
- **LIFE-01:** early `?` exits bypass common cleanup; workers are not consistently cancelled/joined, and display timeout can detach work. Do not claim a universal permanent socket leak: closing the request channel can eventually stop media.
- **REC-02:** prompted credential retention, error classification, configured retry policy/limits/jitter, and needs-user-action handling are still unfinished, as the progress note acknowledges.
- **IO-01/CTRL-01/AUTH-01:** establishment/write bounds, parsing and mutual proof enforcement remain open. Not every part requires a live capture before work can begin; cancellation/overall deadlines can be improved independently.
- **Renderer recovery:** synchronous `decode()` exceptions still close silently; three consecutive failures can intentionally latch video without upstream escalation; count-bounded timing metadata does not detect consumed input with no output.
- **RTP integration:** an all-padding RTP packet decrypts to empty payload and returns before depacketizer sequence accounting, producing a false gap. A truncated FU can still be skipped without damaging its whole timestamp. Both are reproduced but their downstream paths predate the patch; include them when completing RTP-01/02.
- **QA/PERF:** no live Mac transition, installed-binary verification, matched-scene benchmark, or 2/8/24-hour qualification was run. Faster/stable long sessions are not yet measured outcomes.

Recommended next order: correct F1/F2 with the epoch identity design, fix F3's ordered lifecycle boundary and F5's same-call reset, complete F4's AU-loss policy, then finish typed worker/retry outcomes and the fake-server/end-to-end progress work. Keep the existing narrower fixes and their regressions.
