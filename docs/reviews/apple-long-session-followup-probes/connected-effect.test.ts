// Review-only reproduction; see README.md for expected meaning.
// @vitest-environment jsdom
import { expect, it, vi } from 'vitest';
import { act, createElement, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { WebGLRenderer } from '../../../ui/src/render/WebGLRenderer';

it('batches a connected update until after a binary first key; passive boundary then removes the new decoder', async () => {
  (globalThis as any).IS_REACT_ACT_ENVIRONMENT=true;
  const decoders: any[]=[];
  vi.stubGlobal('EncodedVideoChunk',class {constructor(init:any){Object.assign(this,init);}});
  vi.stubGlobal('VideoDecoder',class {
    state='unconfigured';decodeQueueSize=0;
    configure(){this.state='configured';}
    decode=vi.fn();close=vi.fn(()=>{this.state='closed';});
    constructor(_c:any){decoders.push(this);}
  });
  const recovery=vi.fn();
  const renderer=Object.assign(Object.create(WebGLRenderer.prototype),{
    h264:new Map(),generation:1,disposed:false,continuousH264:true,
    latestVideo:null,h264Failed:false,h264Unsupported:false,h264Failures:0,
    h264Acceleration:'prefer-hardware',h264Behind:false,behindAskedAt:0,
    mediaSubmitted:0,mediaLatencyDropped:0,onDecoderBehind:recovery,
  });
  let setConnected: any;
  function ConnectedEffect(){
    const [connected,set]=useState(false);setConnected=set;
    // Identical lifecycle ordering to Session.tsx:1113–1126.
    useEffect(()=>{if(connected)renderer.beginConnectionAttempt();},[connected]);
    return null;
  }
  const root=createRoot(document.createElement('div'));
  await act(async()=>{root.render(createElement(ConnectedEffect));});
  const key={h264Context:0,h264Key:true,h264Reset:true,payload:new Uint8Array([0,0,0,1,0x65,0xaa])};
  await act(async()=>{
    // useSession sets connected; its separate Channel handler can supply a
    // first key before React commits the pending state and passive effects.
    setConnected(true);
    await renderer.decodeH264(key);
    expect(renderer.h264.size).toBe(1);
  });
  expect(decoders[0].close).toHaveBeenCalledOnce();
  expect(renderer.h264.size).toBe(0);
  await renderer.decodeH264({...key,h264Key:false,h264Reset:false});
  expect(decoders[0].decode).toHaveBeenCalledOnce();
  expect(recovery).not.toHaveBeenCalled();
  await act(async()=>root.unmount());
  vi.unstubAllGlobals();
});
