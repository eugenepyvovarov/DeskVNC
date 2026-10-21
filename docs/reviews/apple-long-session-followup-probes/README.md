# Apple long-session follow-up probes

Review target: `cf2e6658f52c89cc1960c2329a1fe6d1e4d293b8`, 2026-10-21. Companion [review report](../2026-10-21-apple-long-session-followup-review.md).

These are review-only **characterizations of unwanted behavior**, using current production modules plus synthetic packets/mock decoders. Passing confirms the described problem; it is not a fix or release qualification. Add desired-behavior regressions to production tests when repairing the issue, then retire/update the corresponding characterization explicitly.

From the DeskVNC root, using existing cached dependencies:

```sh
cargo test --offline --manifest-path docs/reviews/apple-long-session-followup-probes/Cargo.toml --lib
ui/node_modules/.bin/vitest run --config docs/reviews/apple-long-session-followup-probes/vitest.config.mts
cargo run --offline --manifest-path docs/reviews/apple-long-session-followup-probes/Cargo.toml --bin fir_sequence
```

Expected current results:

- Rust: **68 passed**, comprising 63 imported production-module tests and five new characterizations.
- UI: **five characterizations passed in two files**; one uses real React state/passive-effect scheduling with equivalent lifecycle wiring, rather than mounting the complete native Session screen.
- FIR executable: A/B/A sequences 10/11/12; after 255 intervening B commands, A repeats its prior sequence.

Rust cases:

1. Accept an old key picture, churn past 32 SSRCs, replay its exact bytes, and observe it replace current video (F1).
2. Deliver a previously unseen delayed key from a retired stream after a local generation change and observe takeover (F2).
3. Lose the first slice of a new timestamp and observe the surviving IDR tail published as complete (F4, incomplete fix).
4. Decrypt an RTP padding-only payload and observe its sequence later reported lost (inherited downstream integration gap).
5. Insert a truncated FU within a timestamp and observe the remaining partial picture published (inherited incomplete AU-damage coverage).

UI cases:

1. An independent non-IDR picture itself trips queue overload and is decoded unconfigured (F5).
2. A permitted first-IDR-before-connected-effect ordering closes the new decoder (F3).
3. An old queued IDR is still decoded after the new local attempt boundary (F3's incomplete epoch fencing).
4. A synchronous decoder exception requests no fresh picture (explicitly inherited/deferred).
5. The connected-effect case repeated with actual React batching/passive effects (F3).

Minimal NAL/configuration payloads isolate sequencing and state management; they are not valid-pixel conformance fixtures. No Mac is contacted and no desktop, credentials, network state, installed application, or production source is modified. A few packet expiry tests use short sleeps because the production code owns its clock. The FIR executable mirrors the one-counter ownership visible in `session.rs` and imports the actual packet builder; it does not execute the socket sender or prove macOS feedback behavior.

The complete application suites and historical characterization harnesses have separate results/meanings recorded in the review. In particular, failures of inverse historical assertions are not automatically production regressions.
