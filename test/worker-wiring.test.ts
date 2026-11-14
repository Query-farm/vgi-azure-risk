// Wiring: all three table functions register and the `azure` catalog advertises them
// with the shared azure_graph secret; plus the safety-lag duration parser (the
// load-bearing PT0S knob). Uses @query-farm via src/{functions,catalog,schema}.

import { test, expect } from "bun:test";
import { FunctionRegistry, ReadOnlyCatalogInterface } from "@query-farm/vgi";
import { makeRiskFunction, durationToMs } from "../src/functions.js";
import {
  SPECS,
  RISKY_USERS,
  RISK_DETECTIONS,
  RECONCILE_DETECTIONS_EXAMPLE,
  STALE_DETECTION_STATE_EXAMPLE,
  USER_DETECTION_ROLLUP_EXAMPLE,
  type FnExample,
} from "../src/schema.js";
import { makeCatalog, AZURE_GRAPH_SECRET } from "../src/catalog.js";
import { FakeRisk } from "./fake-risk.js";

test("all three functions register and the azure catalog advertises them", () => {
  const g = new FakeRisk("riskDetections", "detectedDateTime");
  const clientFactory = () => ({ fetchJson: g.fetch, postJson: async () => ({}) });

  const functions = SPECS.map((s) => makeRiskFunction(s, clientFactory));
  expect(functions.length).toBe(3);

  const registry = new FunctionRegistry();
  for (const f of functions) registry.register(f);

  const cat = makeCatalog(functions);
  expect(cat.name).toBe("azure");
  expect(cat.secretTypes?.[0]).toBe(AZURE_GRAPH_SECRET);
  expect(cat.secretTypes?.[0]!.name).toBe("azure_graph"); // frozen secret type across the set
  expect(cat.schemas[0]!.functions!.map((f) => (f as { meta: { name: string } }).meta.name).sort()).toEqual([
    "risk_detections",
    "risky_service_principals",
    "risky_users",
  ]);

  // Constructs the read-only catalog interface without throwing.
  new ReadOnlyCatalogInterface(cat, registry);
});

test("durationToMs honors PT0S (the §7.3b zero-lag knob) and defaults safely on garbage", () => {
  expect(durationToMs("PT10M")).toBe(600_000);
  expect(durationToMs("PT1M30S")).toBe(90_000);
  expect(durationToMs("PT2H")).toBe(7_200_000);
  expect(durationToMs("PT0S")).toBe(0); // a deliberate zero lag is honored, not coerced to default
  expect(durationToMs("")).toBe(600_000); // NULL/empty → default 10 min
  expect(durationToMs("garbage")).toBe(600_000); // unparseable → default, never a silent 0-lag
});

test("composed examples are shown on the driving function (first 5) and in the schema list", () => {
  const clientFactory = () => ({ fetchJson: async () => ({ value: [] }), postJson: async () => ({}) });
  const cat = makeCatalog(SPECS.map((s) => makeRiskFunction(s, clientFactory)));
  const schemaSql = (JSON.parse(cat.schemas[0]!.tags!["vgi.example_queries"]!) as { sql: string }[]).map((e) => e.sql);
  const drivers: [typeof RISKY_USERS, FnExample][] = [
    [RISK_DETECTIONS, RECONCILE_DETECTIONS_EXAMPLE],
    [RISK_DETECTIONS, STALE_DETECTION_STATE_EXAMPLE],
    [RISKY_USERS, USER_DETECTION_ROLLUP_EXAMPLE],
  ];
  for (const [spec, ex] of drivers) {
    expect(spec.examples.slice(0, 5)).toContain(ex);
    expect(schemaSql).toContain(ex.sql);
    expect(ex.sql).not.toMatch(/SELECT \*/);
  }
  // No exact duplicates in the schema-level list.
  expect(new Set(schemaSql).size).toBe(schemaSql.length);
});
