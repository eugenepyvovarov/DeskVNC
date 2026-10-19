import { useState } from "react";

export interface MacDisplayInfo {
  displayId: number;
  originalModeId: number;
  currentModeId: number;
  width: number;
  height: number;
  pixelWidth: number;
  pixelHeight: number;
  canRestore: boolean;
  modes: { id: number; width: number; height: number; pixelWidth: number; pixelHeight: number }[];
}
export type MacDisplayAction = { action: "list" | "restore" } | { action: "set"; width: number; height: number };

/**
 * Two separate Mac-side levers, honestly labelled:
 * stream size (the Apple Remote Desktop approach, over the live Screen
 * Sharing session) and the physical panel mode (SSH + CoreGraphics, advanced).
 */
export function MacDisplayControls(props: {
  info: MacDisplayInfo | null;
  notice: string | null;
  busy: boolean;
  size: { w: number; h: number } | null;
  native: { w: number; h: number } | null;
  onStreamResize: (w: number, h: number) => void;
  onPanelMode: (action: MacDisplayAction) => void;
}) {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState("");
  const modes = props.info ? Array.from(new Set(props.info.modes.filter(m => m.pixelWidth <= 4096 && m.pixelHeight <= 4096).map(m => `${m.width}x${m.height}`))) : [];
  const streamSize = props.size ? `${props.size.w}×${props.size.h}` : "…";
  const native = props.native;
  return <div className="absolute bottom-3 right-3 z-20 text-xs">
    <button className="rounded-md border border-subtle bg-raised px-3 py-2" onClick={() => setOpen(!open)}>Mac</button>
    {open && <div className="absolute bottom-full right-0 mb-2 w-80 space-y-3 rounded-lg border border-subtle bg-raised p-4 shadow-lg">
      <p className="text-secondary">Streaming at {streamSize} pixels</p>
      <div>
        <strong>Stream size</strong>
        <p className="mt-1 text-secondary">Ask the Mac to render and stream at a smaller resolution, over the live session. This is the Apple Remote Desktop approach; the layout the Mac confirms is what you get.</p>
        <div className="mt-2 flex flex-wrap gap-2">
          <button className="rounded border border-subtle px-2 py-1" onClick={() => props.onStreamResize(1920, 1080)}>1920×1080</button>
          <button className="rounded border border-subtle px-2 py-1" onClick={() => props.onStreamResize(2560, 1440)}>2560×1440</button>
          {native && <button className="rounded border border-subtle px-2 py-1" onClick={() => props.onStreamResize(native.w, native.h)}>Native ({native.w}×{native.h})</button>}
        </div>
        <p className="mt-1 text-tertiary">The Quality menu maps its presets onto these sizes for a Mac.</p>
      </div>
      <div>
        <strong>Physical panel mode (advanced)</strong>
        <p className="mt-1 text-secondary">Sets the Mac panel's own display mode over SSH with this Mac account and the trusted host key. Slower and heavier than the stream resize; never creates a private display.</p>
        <button disabled={props.busy} onClick={() => props.onPanelMode({action:"list"})} className="mt-2 rounded border border-subtle px-2 py-1 disabled:opacity-50">{props.busy ? "Waiting for macOS…" : "Read available modes"}</button>
        {props.info && <>
          <p className="mt-2">Panel: {props.info.width} × {props.info.height} points ({props.info.pixelWidth} × {props.info.pixelHeight} pixels)</p>
          <label className="mt-1 block">Mode <select aria-label="Physical Mac panel mode" className="mt-1 w-full rounded border border-subtle bg-canvas p-1" value={selected} onChange={e => setSelected(e.target.value)}>
            <option value="">Choose an available mode</option>
            {modes.map(mode => <option key={mode} value={mode}>{mode.replace("x", " × ")}</option>)}
          </select></label>
          <div className="mt-2 flex gap-2">
            <button disabled={props.busy || !selected} className="rounded border border-subtle px-2 py-1 disabled:opacity-50" onClick={() => {const [width,height]=selected.split("x").map(Number); props.onPanelMode({action:"set",width,height});}}>Apply on Mac</button>
            <button disabled={props.busy || !props.info.canRestore} className="rounded border border-subtle px-2 py-1 disabled:opacity-50" onClick={() => props.onPanelMode({action:"restore"})}>Restore original</button>
          </div>
          <p className="mt-1 text-secondary">Restoration is attempted on disconnect, but cannot be guaranteed after a crash or network loss.</p>
        </>}
      </div>
      {props.notice && <p role="status" className="break-words text-secondary">{props.notice}</p>}
    </div>}
  </div>;
}