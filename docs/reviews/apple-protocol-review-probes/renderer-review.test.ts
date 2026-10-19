import { afterEach, expect, it, vi } from "vitest";
import { WebGLRenderer } from "../../../ui/src/render/WebGLRenderer";
import { RectFormat } from "../../../ui/src/render/frameProtocol";

afterEach(() => vi.unstubAllGlobals());

it("a recoverable H264 failure must not remain latched across a framebuffer resize", () => {
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    fbWidth: 3600, fbHeight: 2338, generation: 1, sawFrame: true, h264Failed: true,
    frameTex: {}, scratchTex: {},
    gl: { bindTexture: vi.fn(), texImage2D: vi.fn(), TEXTURE_2D: 1, RGBA8: 2, RGBA: 3, UNSIGNED_BYTE: 4 },
    clearViewRect: vi.fn(), closeAllH264: vi.fn(), markDirty: vi.fn(),
  });
  renderer.setRemoteSize(1920, 1080);
  expect(renderer.h264Failed).toBe(false);
});

it("an asynchronous hardware configure failure must retry or report a visible failure", () => {
  let callbacks: { error: (error: Error) => void };
  const configurations: any[] = [];
  vi.stubGlobal("VideoDecoder", class {
    state = "configured";
    constructor(c: typeof callbacks) { callbacks = c; }
    configure(c: any) { configurations.push(c); }
    close() { this.state = "closed"; }
  });
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false, continuousH264: true,
    latestVideo: null, notices: new Set(), notice: vi.fn(),
  });
  renderer.createH264({ x: 0, y: 0, w: 1920, h: 1080 }, 0, new Uint8Array());
  callbacks!.error(new Error("No hardware decoder for this reconfigured stream"));
  // Do not mandate software: this project requires a verified hardware path.
  // A controlled hardware retry or an explicit visible failure is acceptable;
  // silently closing the context is not.
  expect(configurations.length > 1 || renderer.notice.mock.calls.length > 0).toBe(true);
});

it("a non-IDR intra picture must not destroy the decoder's reference pictures", async () => {
  // The driver labels any access unit containing an intra slice as a key
  // picture and sets `reset`. The renderer then closes the decoder and builds
  // a new one, which discards every reference picture the decoder held.
  // The next delta picture then references pictures that no longer exist:
  // visible corruption that persists until the next IDR.
  const existing = {
    avc: true, timestamp: 0, generation: 1, waiters: new Map(),
    decoder: { state: "configured", decode: vi.fn() },
  };
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false, continuousH264: true, sawFrame: true, disposed: false,
    generation: 1, latestVideo: null, gl: {}, h264: new Map([[0, existing]]),
    closeH264: vi.fn(function (this: any, id: number) { this.h264.delete(id); }),
    createH264: vi.fn(function (this: any) {
      const ctx = { avc: true, timestamp: 0, generation: 1, waiters: new Map(), decoder: { state: "configured", decode: vi.fn() } };
      this.h264.set(0, ctx);
      return ctx;
    }),
    onFirstFrame: vi.fn(), markDirty: vi.fn(),
  });
  await renderer.applyFrameOrdered(
    [{ format: RectFormat.H264, h264Key: true, h264Reset: true, payload: new Uint8Array([0, 0, 0, 1, 0x61, 0xaa]) }],
    [null],
    1,
  );
  expect(renderer.closeH264).not.toHaveBeenCalled();
  expect(renderer.createH264).not.toHaveBeenCalled();
  expect(existing.decoder.decode).toHaveBeenCalled();
});

it("compressed input accepted by WebCodecs must not count as a first presented frame", async () => {
  vi.stubGlobal("VideoDecoder", class {});
  vi.stubGlobal("EncodedVideoChunk", class { constructor(options: any) { Object.assign(this, options); } });
  const firstFrame = vi.fn();
  const renderer = Object.assign(Object.create(WebGLRenderer.prototype), {
    h264Failed: false, continuousH264: true, sawFrame: false,
    disposed: false, generation: 1, latestVideo: null, gl: {},
    h264: new Map([[0, { avc: false, timestamp: 0, generation: 1, decoder: { state: "configured", decode: vi.fn() } }]]),
    onFirstFrame: firstFrame, markDirty: vi.fn(),
  });
  await renderer.applyFrameOrdered([{ format: RectFormat.H264, h264Key: true, payload: new Uint8Array([0, 0, 0, 1, 0x65, 0xaa]) }], [null], 1);
  expect(firstFrame).not.toHaveBeenCalled();
  expect(renderer.sawFrame).toBe(false);
});
