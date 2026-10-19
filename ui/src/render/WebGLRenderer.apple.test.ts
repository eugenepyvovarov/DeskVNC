import { afterEach, expect, it, vi } from "vitest";
import { WebGLRenderer } from "./WebGLRenderer";
import { RectFormat } from "./frameProtocol";

afterEach(() => vi.unstubAllGlobals());

it("keeps only the latest decoded continuous picture until the next paint", () => {
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
  });
  const upload = vi.fn();
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false,
    continuousH264: true, latestVideo: null,
    fbWidth: 3600, fbHeight: 2338,
    uploadVideoFrame: upload,
  });
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  const first = { displayWidth: 3600, displayHeight: 2338, close: vi.fn() };
  const newest = { displayWidth: 3600, displayHeight: 2338, close: vi.fn() };
  output(first);
  output(newest);
  expect(first.close).toHaveBeenCalledOnce();
  expect(newest.close).not.toHaveBeenCalled();
  expect(renderer.latestVideo.frame).toBe(newest);
  expect(upload).not.toHaveBeenCalled();
});

it("feeds continuous AVC without waiting for output and converts Annex-B lengths", async () => {
  vi.stubGlobal("VideoDecoder", class {});
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const decode = vi.fn();
  const wait = vi.fn(() => { throw new Error("continuous video must not wait"); });
  // No GL is used by chunk submission; output/upload is separately driven
  // by WebCodecs. A decoder retaining its first picture must not block the
  // second submission (GStreamer's normal one-frame delay).
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false,
    continuousH264: true,
    h264: new Map([[0, { avc: true, timestamp: 0, submitted: new Map(), decoder: { state: "configured", decode } }]]),
    awaitH264Frame: wait,
  });
  const rect = {
    h264Key: true,
    payload: new Uint8Array([0, 0, 0, 1, 0x65, 0xaa, 0, 0, 1, 0x61, 0xbb]),
  };
  await renderer.decodeH264(rect);
  await renderer.decodeH264({ ...rect, h264Key: false });
  expect(wait).not.toHaveBeenCalled();
  expect(decode).toHaveBeenCalledTimes(2);
  expect(Array.from(decode.mock.calls[0][0].data)).toEqual([
    0, 0, 0, 2, 0x65, 0xaa, 0, 0, 0, 2, 0x61, 0xbb,
  ]);
});

/** A renderer with texture allocation but no real browser/GPU. */
function sizedDecoderHarness(extra: Record<string, unknown> = {}) {
  return decoderHarness({
    fbWidth: 3600, fbHeight: 2338, sawFrame: true,
    mediaPictureWidth: 3600, mediaPictureHeight: 2338,
    mediaDecoded: 0,
    frameTex: {}, scratchTex: {},
    gl: {
      bindTexture: vi.fn(), texImage2D: vi.fn(), texSubImage2D: vi.fn(),
      TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4,
    },
    clearViewRect: vi.fn(), markDirty: vi.fn(),
    ...extra,
  });
}

it("does not let a previous H.264 rectangle override a normal framebuffer resize", () => {
  const renderer = sizedDecoderHarness({
    continuousH264: false, mediaPictureWidth: 320, mediaPictureHeight: 240,
  });
  renderer.setRemoteSize(1920, 1080);
  expect(renderer.getRemoteSize()).toEqual({ width: 1920, height: 1080 });
});

it("adopts decoded dimensions even when they already match the new context rectangle", () => {
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  for (const [w, h] of [[1800, 1170], [2700, 1754], [3600, 2338]]) {
    renderer.closeAllH264();
    renderer.createH264({ x: 0, y: 0, w, h }, 0, new Uint8Array());
    const frame = { displayWidth: w, displayHeight: h, timestamp: 1, close: vi.fn() };
    output(frame);
    expect(renderer.getRemoteSize()).toEqual({ width: w, height: h });
    expect(renderer.latestVideo.frame).toBe(frame);
  }
});

it("keeps the last continuous picture until replacement output, not the layout, arrives", () => {
  let output: (frame: unknown) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { output: typeof output }) { output = callbacks.output; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  const ctx = renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  renderer.setRemoteSize(2700, 1754);
  expect(renderer.getRemoteSize()).toEqual({ width: 3600, height: 2338 });
  expect(renderer.h264.get(0)).toBe(ctx);
  expect(renderer.gl.texImage2D).not.toHaveBeenCalled();
  output({ displayWidth: 2700, displayHeight: 1754, close: vi.fn() });
  expect(renderer.getRemoteSize()).toEqual({ width: 2700, height: 1754 });
  expect(renderer.h264.get(0)).toBe(ctx);
});

it("ignores output and errors from a retired decoder sharing the replacement's slot", () => {
  const callbacks: { output: (f: unknown) => void; error: (e: Error) => void }[] = [];
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(c: typeof callbacks[number]) { callbacks.push(c); }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = sizedDecoderHarness();
  renderer.createH264({ x: 0, y: 0, w: 3600, h: 2338 }, 0, new Uint8Array());
  renderer.closeH264(0);
  const replacement = renderer.createH264({ x: 0, y: 0, w: 2700, h: 1754 }, 0, new Uint8Array());
  const stale = { displayWidth: 1800, displayHeight: 1170, close: vi.fn() };
  callbacks[0].output(stale);
  expect(stale.close).toHaveBeenCalledOnce();
  expect(renderer.latestVideo).toBeNull();
  expect(renderer.mediaPictureWidth).toBe(3600);
  callbacks[0].error(new Error("late old decoder error"));
  expect(renderer.h264.get(0)).toBe(replacement);
  expect(renderer.h264Failures).toBe(0);
});

/** A renderer with just enough state for the decoder paths. */
function decoderHarness(extra: Record<string, unknown> = {}) {
  return Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false,
    continuousH264: true, latestVideo: null, notices: new Set(),
    h264Failed: false, h264Unsupported: false, h264Failures: 0,
    h264Acceleration: "prefer-hardware",
    notice: vi.fn(),
    ...extra,
  });
}

it("does not rebuild the decoder for a key picture that is not a reset", async () => {
  // The driver marks only an IDR as a reset. An intra picture is a key
  // chunk, so it can start a decoder, but rebuilding the decoder would
  // throw away the reference pictures the next delta picture needs, and the
  // corruption that follows outlives the picture that caused it.
  vi.stubGlobal("VideoDecoder", class { state = "configured"; configure() {} close() {} });
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const existing = {
    avc: true, timestamp: 0, generation: 1, waiters: new Map(), submitted: new Map(),
    decoder: { state: "configured", decode: vi.fn() },
  };
  const closeH264 = vi.fn();
  const createH264 = vi.fn();
  const renderer = decoderHarness({
    sawFrame: true, gl: {}, h264: new Map([[0, existing]]), closeH264, createH264,
  });
  await renderer.decodeH264({
    h264Key: true,
    h264Reset: false,
    payload: new Uint8Array([0, 0, 0, 1, 0x61, 0xaa]),
  });
  expect(closeH264).not.toHaveBeenCalled();
  expect(createH264).not.toHaveBeenCalled();
  expect(existing.decoder.decode).toHaveBeenCalledOnce();
});

it("reports what the decoder is doing", () => {
  // The queue is how much the decoder has been given and has not finished,
  // and the delay is how old the picture on screen is.
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map([[0, { decoder: { decodeQueueSize: 3 } }]]),
    mediaSubmitted: 10,
    mediaDecoded: 8,
    mediaLatencyMs: 42.4,
  });
  expect(renderer.getMediaStats()).toEqual({
    queued: 3,
    submitted: 10,
    decoded: 8,
    latencyMs: 42,
  });
});

it("does not latch a decoder failure across a resize", () => {
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    fbWidth: 3600, fbHeight: 2338, generation: 1, sawFrame: true,
    h264Failed: true, h264Unsupported: false, h264Failures: 3,
    frameTex: {}, scratchTex: {},
    gl: { bindTexture: vi.fn(), texImage2D: vi.fn(), TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4 },
    clearViewRect: vi.fn(), closeAllH264: vi.fn(), markDirty: vi.fn(),
  });
  renderer.setRemoteSize(1920, 1080);
  expect(renderer.h264Failed).toBe(false);
  expect(renderer.h264Failures).toBe(0);
});

it("keeps the fact that this webview has no H.264 decoder across a resize", () => {
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    fbWidth: 3600, fbHeight: 2338, generation: 1, sawFrame: true,
    h264Failed: true, h264Unsupported: true, h264Failures: 3,
    frameTex: {}, scratchTex: {},
    gl: { bindTexture: vi.fn(), texImage2D: vi.fn(), TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4 },
    clearViewRect: vi.fn(), closeAllH264: vi.fn(), markDirty: vi.fn(),
  });
  renderer.setRemoteSize(1920, 1080);
  expect(renderer.h264Failed).toBe(true);
});

it("reports an asynchronous decoder failure and keeps the stream recoverable", () => {
  let error: (e: Error) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { error: typeof error }) { error = callbacks.error; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = decoderHarness();
  renderer.createH264({ x: 0, y: 0, w: 1920, h: 1080 }, 0, new Uint8Array());
  error(new Error("No hardware decoder for this reconfigured stream"));
  // The failure is reported rather than swallowed, the hardware path is
  // given up on, and one failure is a hiccup rather than a dead end: the
  // next independent picture builds a fresh decoder.
  expect(renderer.notice).toHaveBeenCalled();
  expect(renderer.h264Acceleration).toBe("prefer-software");
  expect(renderer.h264Failed).toBe(false);
  expect(renderer.h264Failures).toBe(1);
});

it("gives up on a stream whose decoder keeps failing", () => {
  let error: (e: Error) => void = () => {};
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(callbacks: { error: typeof error }) { error = callbacks.error; }
    configure() {}
    close() { this.state = "closed"; }
  });
  const renderer = decoderHarness();
  for (let i = 0; i < 3; i++) {
    renderer.createH264({ x: 0, y: 0, w: 1920, h: 1080 }, 0, new Uint8Array());
    error(new Error("decoder died"));
  }
  expect(renderer.h264Failed).toBe(true);
});

it("does not count an accepted compressed chunk as a presented frame", async () => {
  vi.stubGlobal("VideoDecoder", class { state = "configured"; configure() {} close() {} });
  vi.stubGlobal("EncodedVideoChunk", class {
    constructor(public init: unknown) { Object.assign(this, init); }
  });
  const firstFrame = vi.fn();
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false, continuousH264: true, sawFrame: false, disposed: false,
    generation: 1, latestVideo: null, gl: {}, notices: new Set(),
    h264: new Map([[0, { avc: false, timestamp: 0, generation: 1, submitted: new Map(), decoder: { state: "configured", decode: vi.fn() } }]]),
    onFirstFrame: firstFrame, markDirty: vi.fn(),
  });
  await renderer.applyFrameOrdered(
    [{ format: RectFormat.H264, h264Key: true, payload: new Uint8Array([0, 0, 0, 1, 0x65, 0xaa]) }],
    [null],
    1,
  );
  expect(firstFrame).not.toHaveBeenCalled();
  expect(renderer.sawFrame).toBe(false);
});

it("counts a painted rectangle as the first frame", async () => {
  const firstFrame = vi.fn();
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false, continuousH264: true, sawFrame: false, disposed: false,
    generation: 1, latestVideo: null, notices: new Set(),
    gl: { bindTexture: vi.fn(), texSubImage2D: vi.fn(), TEXTURE_2D: 1, RGBA: 3, UNSIGNED_BYTE: 4 },
    frameTex: {},
    onFirstFrame: firstFrame, markDirty: vi.fn(),
  });
  await renderer.applyFrameOrdered(
    [{ format: RectFormat.Rgba, x: 0, y: 0, w: 2, h: 2, payload: new Uint8Array(16) }],
    [null],
    1,
  );
  expect(firstFrame).toHaveBeenCalledOnce();
  expect(renderer.sawFrame).toBe(true);
});
