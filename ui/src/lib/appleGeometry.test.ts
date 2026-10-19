import { beforeEach, expect, it } from "vitest";
import { appleGeometryArguments, readAppleGeometry, writeAppleGeometry } from "./appleGeometry";

beforeEach(() => localStorage.clear());

it("remembers the geometry a session confirmed", () => {
  writeAppleGeometry("host-1", {
    pixelWidth: 3600,
    pixelHeight: 2338,
    pointWidth: 1800,
    pointHeight: 1169,
  });
  expect(readAppleGeometry("host-1")).toEqual({
    pixelWidth: 3600,
    pixelHeight: 2338,
    pointWidth: 1800,
    pointHeight: 1169,
  });
});

it("keeps one host's geometry away from another's", () => {
  writeAppleGeometry("host-1", {
    pixelWidth: 3600, pixelHeight: 2338, pointWidth: 1800, pointHeight: 1169,
  });
  expect(readAppleGeometry("host-2")).toBeNull();
});

it("ignores a half remembered geometry", () => {
  // The pixels and the points come from the same confirmation. Half of one
  // is no use, and a guess would resize the person's desktop.
  localStorage.setItem(
    "deskvnc.apple.geometry.host-1",
    JSON.stringify({ pixelWidth: 3600, pixelHeight: 2338 }),
  );
  expect(readAppleGeometry("host-1")).toBeNull();
});

it("ignores nonsense that is not a geometry", () => {
  localStorage.setItem("deskvnc.apple.geometry.host-1", "{oops");
  expect(readAppleGeometry("host-1")).toBeNull();
  localStorage.setItem(
    "deskvnc.apple.geometry.host-1",
    JSON.stringify({ pixelWidth: 0, pixelHeight: 0, pointWidth: 0, pointHeight: 0 }),
  );
  expect(readAppleGeometry("host-1")).toBeNull();
});

it("turns the geometry into the four numbers the connect command takes", () => {
  expect(
    appleGeometryArguments({
      pixelWidth: 3600, pixelHeight: 2338, pointWidth: 1800, pointHeight: 1169,
    }),
  ).toEqual([3600, 2338, 1800, 1169]);
  expect(appleGeometryArguments(null)).toBeNull();
});
