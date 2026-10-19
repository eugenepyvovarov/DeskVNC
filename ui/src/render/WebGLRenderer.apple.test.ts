import { afterEach, expect, it, vi } from "vitest";
import { WebGLRenderer } from "./WebGLRenderer";

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
