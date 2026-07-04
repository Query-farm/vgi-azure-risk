// Marker-row contract + per-collection schema shape. Uses @query-farm Arrow via
// src/schema.ts (that is fine here — only the archetype proof must stay SDK-free).

import { test, expect } from "bun:test";
import { RISKY_USERS, RISK_DETECTIONS, schemaFor, buildWatermarkBatch } from "../src/schema.js";
import type { RiskRow } from "../src/risk-watermark.js";

test("buildWatermarkBatch: N business rows + exactly 1 marker row carrying _watermark_next", () => {
  const schema = schemaFor(RISK_DETECTIONS);
  const rows: RiskRow[] = [
    { id: "d1", timeSeen: "2026-06-01T00:00:00.000Z", fields: { riskLevel: "high", riskState: "atRisk", userId: "u1", ipAddress: "203.0.113.7" } },
    { id: "d2", timeSeen: "2026-06-01T00:01:00.000Z", fields: { riskLevel: "medium", riskState: "dismissed", userId: "u2" } },
  ];
  const batch = buildWatermarkBatch(RISK_DETECTIONS, schema, rows, "2026-06-01T00:00:30.000Z") as { numRows: number };
  expect(batch.numRows).toBe(3); // 2 business + 1 marker
});

test("schema columns: id, time col, risk_level, risk_state, business…, then the two control columns", () => {
  expect(schemaFor(RISK_DETECTIONS).fields.map((f) => f.name)).toEqual([
    "id", "detected_date_time", "risk_level", "risk_state",
    "user_id", "user_principal_name", "risk_event_type", "detection_timing_type", "ip_address",
    "_row_kind", "_watermark_next",
  ]);
  // State collection uses the riskLastUpdatedDateTime time column instead.
  expect(schemaFor(RISKY_USERS).fields.map((f) => f.name)).toContain("risk_last_updated_date_time");
});

test("an empty scan still emits exactly the marker row (the cursor always advances)", () => {
  const schema = schemaFor(RISKY_USERS);
  const batch = buildWatermarkBatch(RISKY_USERS, schema, [], "2026-06-01T00:00:00.000Z") as { numRows: number };
  expect(batch.numRows).toBe(1);
});
