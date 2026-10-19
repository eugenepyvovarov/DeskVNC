import { describe, expect, it } from "vitest";
import { History, findings, lossFraction, report, type Sample } from "./diagnostics";
import type { AppleMediaState } from "./appleMedia";

function sample(over: Partial<Sample> = {}): Sample {
  return { at: 0, throughput: 4e6, fps: 30, loss: 0, jitter: 10, queued: 0, decodeMs: 5, ...over };
}

function media(over: Partial<AppleMediaState> = {}): AppleMediaState {
  return {
    requestedWidth: 0, requestedHeight: 0,
    layoutWidth: 0, layoutHeight: 0,
    desktopWidth: 0, desktopHeight: 0,
    canvasWidth: 0, canvasHeight: 0,
    tiles: 0, pictures: 0, lost: 0, dropped: 0, recoveries: 0, requests: 0,
    packets: 0, bytes: 0, stalls: 0, jitterMs: 0,
    ...over,
  };
}

describe("lossFraction", () => {
  it("is zero when nothing has arrived", () => {
    expect(lossFraction(0, 0)).toBe(0);
  });
  it("is the share of packets that went missing", () => {
    expect(lossFraction(5, 95)).toBeCloseTo(0.05);
  });
  it("never exceeds one", () => {
    expect(lossFraction(10, 0)).toBe(1);
  });
});

describe("findings", () => {
  it("says nothing is wrong when nothing is", () => {
    const [first] = findings(sample());
    expect(first.severity).toBe("good");
  });

  it("does not call one lost packet a problem", () => {
    // A local network drops the odd packet and nobody notices. Calling that
    // unstable sends someone hunting a fault that is not there.
    const [first] = findings(sample({ loss: 0.002 }));
    expect(first.severity).toBe("good");
  });

  it("names heavy loss before any symptom of it", () => {
    const list = findings(sample({ loss: 0.08, fps: 2, jitter: 200 }));
    expect(list[0].severity).toBe("bad");
    expect(list[0].title).toContain("8.0%");
    expect(list[0].detail).toContain("MTU");
  });

  it("explains a growing decoder queue as this machine being behind", () => {
    const list = findings(sample({ queued: 6 }));
    const queue = list.find((f) => f.title.includes("waiting to be decoded"));
    expect(queue?.severity).toBe("warning");
    expect(queue?.detail).toContain("not the network");
  });

  it("reports stalls and local drops as notices, not faults", () => {
    const list = findings(sample(), { stalls: 2, dropped: 3 });
    expect(list.some((f) => f.title.includes("stalled 2 times"))).toBe(true);
    expect(list.some((f) => f.title.includes("3 pictures dropped"))).toBe(true);
  });

  it("orders the worst finding first", () => {
    const list = findings(sample({ loss: 0.2, jitter: 300, queued: 5 }), { stalls: 1 });
    const severities = list.map((f) => f.severity);
    expect(severities[0]).toBe("bad");
    expect(severities.indexOf("warning")).toBeLessThan(severities.indexOf("notice"));
  });
});

describe("History", () => {
  it("keeps only the newest samples", () => {
    const history = new History(3);
    for (let i = 0; i < 5; i++) history.push(sample({ at: i }));
    expect(history.length).toBe(3);
    expect(history.all()[0].at).toBe(2);
  });

  it("does not amplify a flat series into a trend", () => {
    const history = new History(4);
    for (let i = 0; i < 4; i++) history.push(sample({ throughput: 1e6 }));
    expect(history.normalized((s) => s.throughput)).toEqual([0, 0, 0, 0]);
  });

  it("scales a changing series across its own range", () => {
    const history = new History(3);
    history.push(sample({ throughput: 1e6 }));
    history.push(sample({ throughput: 2e6 }));
    history.push(sample({ throughput: 3e6 }));
    expect(history.normalized((s) => s.throughput)).toEqual([0, 0.5, 1]);
  });
});

describe("report", () => {
  it("carries the numbers a diagnosis needs", () => {
    const text = report({
      appVersion: "0.31.0",
      protocol: "apple",
      desktopName: "MB14Shtora",
      host: "192.168.1.140:5900",
      connectedFor: 120,
      requested: { w: 1800, h: 1169 },
      layout: { w: 3600, h: 2338 },
      decoded: { w: 3600, h: 2338 },
      media: media({ packets: 960, lost: 40, bytes: 5_000_000, jitterMs: 30, stalls: 1 }),
      stats: { throughput_bps: 4e6, fps: 29.5, rtt_ms: 0, rtt_source: "none" },
      decoder: { queued: 1, submitted: 100, decoded: 99, latencyMs: 12 },
      queue: { depth: 0, bytes: 0, dropped: 0 },
      findings: findings(sample()),
      history: [sample({ at: 0 }), sample({ at: 1000 })],
    });
    expect(text).toContain("Protocol: apple");
    expect(text).toContain("3600x2338");
    expect(text).toContain("4.00%");
    expect(text).toContain("not measured");
    expect(text).toContain("Last samples");
  });

  it("says plainly when nothing has been measured yet", () => {
    const text = report({
      protocol: "apple",
      desktopName: "Mac",
      host: "host",
      connectedFor: 1,
      media: null,
      stats: null,
      decoder: null,
      queue: null,
      findings: [],
      history: [],
    });
    expect(text).toContain("no transport statistics yet");
    expect(text).not.toContain("Last samples");
  });
});
