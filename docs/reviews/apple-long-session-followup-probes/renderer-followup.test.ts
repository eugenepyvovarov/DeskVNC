// Review-only reproduction; see README.md for expected meaning.
import { afterEach, expect, it, vi } from 'vitest';
import { WebGLRenderer } from '../../../ui/src/render/WebGLRenderer';
import { RectFormat } from '../../../ui/src/render/frameProtocol';
afterEach(() => vi.unstubAllGlobals());
function harness(extra: Record<string, unknown> = {}) {
  return Object.assign(Object.create(WebGLRenderer.prototype), {
    h264: new Map(), generation: 1, disposed: false,
    continuousH264: true, latestVideo: null, notices: new Set(),
    h264Failed: false, h264Unsupported: false, h264Failures: 0,
    h264Acceleration: 'prefer-hardware', h264Behind: false,
    behindAskedAt: 0, mediaSubmitted: 0, mediaDecoded: 0,
    mediaLatencyDropped: 0, pending: [], pendingBytes: 0, draining: false,
    droppedRects: 0, droppedUpdates: 0,
    fbWidth: 1920, fbHeight: 1080, pendingLayout: null,
    notice: vi.fn(), ...extra,
  });
}
function installDecoder(extra: Record<string, unknown> = {}) {
  const instances: any[]=[];
  vi.stubGlobal('EncodedVideoChunk', class { constructor(init: unknown) { Object.assign(this, init); } });
  vi.stubGlobal('VideoDecoder', class {
    state='unconfigured'; decodeQueueSize=0;
    callbacks: any;
    configure=vi.fn(() => { this.state='configured'; });
    reset=vi.fn(() => { this.state='unconfigured'; this.decodeQueueSize=0; });
    decode=vi.fn(() => { if(this.state !== 'configured') throw new Error('InvalidStateError'); });
    close=vi.fn(() => { this.state='closed'; });
    constructor(c: any) { this.callbacks=c; Object.assign(this,extra); instances.push(this); }
  });
  return instances;
}
const key = { format: RectFormat.H264, x: 0, y: 0, w: 1920, h: 1080, h264Context: 0, h264Key: true, h264Reset: true, payload: new Uint8Array([0,0,0,1,0x65,0xaa]) };
const intra = { ...key, h264Reset: false, payload: new Uint8Array([0,0,0,1,0x61,0xb0]) };
const delta = { ...intra, h264Key: false };

it('reproduces remaining REN-02: overload reached on non-IDR independent picture loses that same picture', async () => {
  const decoders=installDecoder();
  const r=harness({onDecoderBehind:vi.fn()});
  await r.decodeH264(key);
  decoders[0].decodeQueueSize=4;
  await r.decodeH264(intra);
  expect(decoders[0].reset).toHaveBeenCalledOnce();
  expect(decoders[0].decode.mock.results[1].type).toBe('throw');
  expect(r.h264.size).toBe(0);
  expect(r.h264Behind).toBe(false);
});

it('reproduces permitted connected-effect interleaving dropping a fresh first IDR without recovery', async () => {
  const decoders=installDecoder(); const recover=vi.fn();
  const r=harness({onDecoderBehind:recover});
  // StateChanged(Connected) queued a React update; before its passive effect
  // commits, the independently dispatched binary channel supplies first IDR.
  await r.decodeH264(key);
  r.beginConnectionAttempt(); // Session.tsx connected passive effect
  await r.decodeH264(delta);
  expect(decoders[0].close).toHaveBeenCalledOnce();
  expect(decoders[0].decode).toHaveBeenCalledOnce();
  expect(r.h264.size).toBe(0);
  expect(recover).not.toHaveBeenCalled();
});

it('reproduces stale queued IDR entering decoder after beginConnectionAttempt', async () => {
  const decoders=installDecoder();
  const r=harness({draining:true});
  r.applyFrame({damageX:0,damageY:0,damageW:1920,damageH:1080,rects:[key]});
  expect(r.pending.length).toBe(1);
  r.beginConnectionAttempt();
  expect(r.generation).toBe(1);
  await r.drain();
  expect(decoders).toHaveLength(1);
  expect(decoders[0].decode).toHaveBeenCalledOnce();
});

it('reproduces unrequested recovery after synchronous decode exception (unchanged path)', async () => {
  const decoders=installDecoder(); const recover=vi.fn();
  const r=harness({onDecoderBehind:recover});
  await r.decodeH264(key);
  decoders[0].decode.mockImplementationOnce(() => {throw new Error('bad chunk');});
  await r.decodeH264(delta);
  expect(r.h264.size).toBe(0);
  expect(recover).not.toHaveBeenCalled();
});
