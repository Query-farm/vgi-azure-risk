// THE reason vgi-azure-risk exists: prove the lagged-timestamp watermark is a
// durable, no-silent-loss VGI scan cursor — the watermark-archetype analogue of the
// directory worker's delta crash-resume proof. This file imports ONLY
// @vgi-azure/graph-core + this package's own driver + bun:test (NO @query-farm/*), so
// it runs without the SDK and pins the archetype end to end.
//
// The load-bearing claim (SPEC §2b, committee must-fix #1): the persisted watermark
// is advanced through graph-core `clampWatermark`, which UNCONDITIONALLY subtracts the
// lag. The quiet-tenant test below is the regression guard that kills the original
// `min(max(timefield), now - lag)` data-loss bug.

import { test, expect } from "bun:test";
import { clampWatermark, isoToMs, msToIso } from "@vgi-azure/graph-core";
import { collectWatermark, EPOCH_ISO, type CollectionSpec } from "../src/risk-watermark.js";
import { FakeRisk } from "./fake-risk.js";

// A minimal spec — collectWatermark needs only { collection, timeField } — kept inline
// so this proof never imports schema.ts (which pulls @query-farm Arrow).
const DETECTIONS: CollectionSpec = {
  fn: "risk_detections",
  collection: "riskDetections",
  timeField: "detectedDateTime",
  description: "risk detections (event cursor)",
  scope: "IdentityRiskEvent.Read.All",
};

const base = Date.parse("2026-06-01T00:00:00.000Z");
const MIN = 60_000;
const at = (ms: number) => msToIso(base + ms);

function detection(id: string, tMs: number): Record<string, unknown> {
  return {
    id,
    detectedDateTime: at(tMs),
    riskLevel: "high",
    riskState: "atRisk",
    ipAddress: "203.0.113.7",
    userId: `user-${id}`,
  };
}

test("full scan pages through everything and returns a clamped watermark (graph-core clampWatermark, verbatim nextLink)", async () => {
  const g = new FakeRisk("riskDetections", "detectedDateTime", /*pageSize*/ 2); // 3 objs → 2 pages
  g.upsert(detection("d0", 0));
  g.upsert(detection("d1", 1 * MIN));
  g.upsert(detection("d2", 2 * MIN));

  const lagMs = 90_000; // PT1M30S
  const nowMs = base + 2.5 * MIN; // now just past the newest row
  const r = await collectWatermark(g.fetch, DETECTIONS, EPOCH_ISO, lagMs, 2, () => nowMs);

  expect(r.rows.map((x) => x.id).sort()).toEqual(["d0", "d1", "d2"]);
  expect(g.fetches).toBe(2); // two pages, @odata.nextLink followed verbatim

  const maxSeenMs = base + 2 * MIN;
  expect(r.maxSeen).toBe(msToIso(maxSeenMs));
  // The watermark equals graph-core clampWatermark EXACTLY (not a hand-rolled clamp)…
  expect(r.watermarkNext).toBe(msToIso(clampWatermark(maxSeenMs, lagMs, nowMs)));
  // …and sits BELOW the newest row — the lag is real, not decorative.
  expect(isoToMs(r.watermarkNext)).toBeLessThan(maxSeenMs);
});

test("QUIET-TENANT (§2b regression guard): watermark stays exactly SAFETY_LAG behind maxSeen, never flush at it", async () => {
  const g = new FakeRisk("riskDetections", "detectedDateTime", 100);
  g.upsert(detection("d0", 0));
  g.upsert(detection("d2", 2 * MIN)); // newest row is ancient relative to `now`

  const lagMs = 10 * MIN;
  const nowMs = base + 10 * 60 * MIN; // ~10h ahead ⇒ maxSeen ≪ now − lag (a quiet tenant)
  const r = await collectWatermark(g.fetch, DETECTIONS, EPOCH_ISO, lagMs, 100, () => nowMs);

  const maxSeenMs = base + 2 * MIN;
  // THE assertion the whole worker exists for: min(maxSeen, now) − lag == maxSeen − lag.
  expect(isoToMs(r.watermarkNext)).toBe(maxSeenMs - lagMs);
  expect(maxSeenMs - isoToMs(r.watermarkNext)).toBe(lagMs);
  // The old `min(max(t), now − lag)` form returned maxSeen here (zero lag) and dropped
  // the next late-scored row at-or-before maxSeen forever. This proves that bug is dead.
  expect(isoToMs(r.watermarkNext)).toBeLessThan(maxSeenMs);
});

test("OVERLAP + late-arrival (no silent loss): re-scan from the clamped watermark catches a row scored behind the tail", async () => {
  const g = new FakeRisk("riskDetections", "detectedDateTime", 100);
  g.upsert(detection("d0", 0));
  g.upsert(detection("d1", 1 * MIN));
  g.upsert(detection("d2", 2 * MIN));

  const lagMs = 90_000;
  const now1 = base + 2.5 * MIN;
  const r1 = await collectWatermark(g.fetch, DETECTIONS, EPOCH_ISO, lagMs, 100, () => now1);
  const W1 = r1.watermarkNext; // = t2 − lag = base + 30s (sits between t0 and t1)
  expect(isoToMs(W1)).toBe(base + 2 * MIN - lagMs);

  // A detection SCORED LATE — stamped behind the already-passed tail (t1.5) — that only
  // becomes queryable on the second scan, plus a fresh t3.
  g.upsert(detection("late", 1.5 * MIN));
  g.upsert(detection("d3", 3 * MIN));

  const now2 = base + 3.5 * MIN;
  const r2 = await collectWatermark(g.fetch, DETECTIONS, W1, lagMs, 100, () => now2);
  const ids = r2.rows.map((x) => x.id).sort();

  expect(ids).toContain("late"); // caught because W1 was clamped behind the lag — NOT dropped
  expect(ids).toContain("d3"); // the genuinely-new row
  expect(ids).toContain("d1"); // overlap re-includes already-seen rows (ge boundary; dedup-by-id)
  expect(ids).not.toContain("d0"); // t0 is below W1 ⇒ correctly outside the window
});

test("LAG-ZERO negative control (§7.3b): PT0S advances flush to maxSeen and DROPS a late row — proving the lag is load-bearing", async () => {
  const g = new FakeRisk("riskDetections", "detectedDateTime", 100);
  g.upsert(detection("d0", 0));
  g.upsert(detection("d1", 1 * MIN));
  g.upsert(detection("d2", 2 * MIN));

  const now1 = base + 2.5 * MIN;
  const r1 = await collectWatermark(g.fetch, DETECTIONS, EPOCH_ISO, /*lagMs*/ 0, 100, () => now1);
  const W1 = r1.watermarkNext;
  expect(isoToMs(W1)).toBe(base + 2 * MIN); // zero lag ⇒ watermark flush at maxSeen

  // A row scored late, stamped BELOW maxSeen, surfaced only on scan 2.
  g.upsert(detection("late", 1.5 * MIN));

  const now2 = base + 3 * MIN;
  const r2 = await collectWatermark(g.fetch, DETECTIONS, W1, 0, 100, () => now2);
  const ids = r2.rows.map((x) => x.id);

  // ge W1 (== ge t2) excludes the t1.5 late row ⇒ DATA LOSS, on purpose. PT0S is unsafe;
  // this is the negative control that proves the default 10-min lag earns its keep.
  expect(ids).not.toContain("late");
  expect(ids).toContain("d2"); // the boundary row is still re-included (ge)
});
