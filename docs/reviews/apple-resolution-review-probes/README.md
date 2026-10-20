# Apple resolution audit probes

Audit target: `6933f0d`, 2026-10-20.

These probes assert desired corrected behaviour against unchanged production
code. They are intentionally outside the normal test suite and are expected to
fail until the findings in
`../../plans/2026-10-20-apple-resolution-stabilization-plan.md` are fixed.
They do not connect to a Mac, send input, change a display, modify application
storage, restart an app, or install a binary.

Run from the DeskVNC repository root:

```sh
python3 docs/reviews/apple-resolution-review-probes/run_rust.py
ui/node_modules/.bin/vitest run \
  --config docs/reviews/apple-resolution-review-probes/vitest.config.mts
```

The Rust script extracts the actual pure resize/descriptor helpers from
`crates/apple-core/src/session.rs`, compiles them in a temporary directory,
and removes the temporary binary afterwards. It needs the installed `rustc`,
not another Cargo dependency tree. The tests do not reimplement those helpers.
If the helpers are renamed or moved, update the extraction boundaries before
interpreting a compilation failure as a regression.

The UI harness imports the real renderer and geometry-cache module, with a
fake VideoDecoder and GL allocation functions. It does not run a GUI or prove
actual decoded content.

## Results at the audit target

Rust: **4 failing, 1 passing**.

- FAIL: 1800x1170 requested, 1800x1169 acknowledged, unchanged desktop points
  triggers an unnecessary rollback.
- FAIL: unchanged backing with smaller desktop points does not trigger the
  pixel-only shrink check.
- FAIL: a queued round retains the first round's rollback snapshot instead of
  the latest accepted geometry.
- FAIL: a 1600x1200 requested picture is serialized as 1800x1170 after ratio
  averaging/clamping, so reported intent and actual wire mode differ.
- PASS: the current descriptor already bounds its first requested mode even
  when the previous desktop is smaller. A separate inspection of the parent
  of `4a897d8` shows it also used `max(request, prior bound)`. This contradicts
  the earlier claim that a small initial cap necessarily prevented growth.

UI: **3 failing**.

- FAIL: after layout 2700x1754 and matching decoded output, an active continuous
  renderer still reports its old 3600x2338 framebuffer.
- FAIL: an unrelated 1600x1200 fallback replaces the last valid Retina picture
  and is stretched into the old framebuffer rather than being surfaced as a
  mismatch.
- FAIL: a reduced-stream layout with unchanged point dimensions overwrites
  the same cache entry later used as initial/native geometry.

These are narrow regression reproductions, not a full protocol test. In
particular, they do not validate which `0x451` acknowledges which request or
prove why macOS selected a particular fallback. The implementation plan calls
for a fake-session transaction test and an authorized live validation matrix.

The normal suites still pass at this target: 103 apple-core tests and 480 UI
tests. Their success does not cover these seven failing cases. Migrate these
requirements into production tests as the fixes are implemented; do not make
them pass by asserting the current wrong behaviour.
