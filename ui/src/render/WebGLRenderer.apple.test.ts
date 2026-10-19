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
    h264: new Map([[0, { avc: true, timestamp: 0, decoder: { state: "configured", decode } }]]),
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
    avc: true, timestamp: 0, generation: 1, waiters: new Map(),
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
    h264: new Map([[0, { avc: false, timestamp: 0, generation: 1, decoder: { state: "configured", decode: vi.fn() } }]]),
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
