// The VGI table functions: risky_users, risk_detections, risky_service_principals.
// All three come from one factory over the proven collectWatermark driver. The
// GraphClient is injected so the worker wires the real MSAL-backed client and tests
// inject a fake.
//
// CONFORMANCE (graph-core-SPEC checklist): all three are TABLE functions so
// `since := value` works ([[vgi-scalar-no-named-args]]); the optional args live in
// `argDefaults` so they are NAMED (`safety_lag := 'PT5M'`, `page_size := 200`). The
// State object is fully serializable — an ISO watermark string, a plain lagMs number,
// a done flag; no socket, no RecordBatch, no Date (graph-core / Go gob-state gotcha).

import { defineTableFunction, secretsOfType, type OutputCollector } from "@query-farm/vgi";
import { Utf8, Int64 } from "@query-farm/apache-arrow";
import { collectWatermark, EPOCH_ISO } from "./risk-watermark.js";
import { schemaFor, buildWatermarkBatch, type RiskCollectionSpec } from "./schema.js";
import type { GraphClient } from "@vgi-azure/graph-core";

export type ClientFactory = (secret: Record<string, unknown>) => GraphClient;

interface Args {
  /** A previously persisted `_watermark_next` (ISO-8601), or "" for a full sync from epoch. */
  since: string;
  /** ISO-8601 duration safety-lag override (default PT10M). Load-bearing (§2b). */
  safety_lag: string;
  /** Maps to Graph `$top`; graph-core clamps to <=1000. */
  page_size: number;
}
interface State {
  done: boolean;
  /** ISO watermark this scan filters `ge` on (immutable scan origin). */ since: string;
  /** Serializable number, NOT a Date. */ lagMs: number;
  top: number;
}

/** Parse an ISO-8601 duration to ms. Supports the forms this worker uses:
 *  PT#H / PT#M / PT#S (and combinations) plus a plain #-of-days `P#D`. Defaults to
 *  the 10-minute safety lag on anything unparseable rather than silently 0-lagging
 *  (0 lag is the data-loss case, SPEC §2b/§7.3b). */
export function durationToMs(iso: string): number {
  const DEFAULT = 10 * 60 * 1000;
  if (!iso) return DEFAULT;
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(iso.trim());
  if (!m) return DEFAULT;
  const [, d, h, min, s] = m;
  const ms =
    (d ? Number(d) * 86_400_000 : 0) +
    (h ? Number(h) * 3_600_000 : 0) +
    (min ? Number(min) * 60_000 : 0) +
    (s ? Number(s) * 1000 : 0);
  // A well-formed PT0S is a deliberate zero lag (the §7.3b negative control); honor it.
  return m[0] === iso.trim() && /\d/.test(iso) ? ms : DEFAULT;
}

export function makeRiskFunction(
  spec: RiskCollectionSpec,
  clientFactory: ClientFactory,
  now: () => number = Date.now,
) {
  const schema = schemaFor(spec);
  return defineTableFunction<Args, State>({
    name: spec.fn,
    description: spec.description,
    args: { since: new Utf8(), safety_lag: new Utf8(), page_size: new Int64() },
    // Optional args → argDefaults, so they are addressable by name (since := …).
    argDefaults: { since: "", safety_lag: "PT10M", page_size: 500 },
    argDocs: {
      since:
        "A previously persisted watermark (the `_watermark_next` value from a prior scan's marker row), an ISO-8601 instant. The scan returns rows whose time field is `>=` this value. Empty (the default) performs a full sync from epoch.",
      safety_lag:
        "ISO-8601 duration (e.g. `PT10M`, `PT1H`, `P1D`) subtracted from the high-water mark before it is committed, so late-scored risk in the lag window is re-read on the next scan rather than lost. Defaults to `PT10M`; anything unparseable falls back to the 10-minute default.",
      page_size:
        "Maps to the Microsoft Graph `$top` page size; clamped to the range 1..1000 (defaults to 500). Controls request paging only, not the total number of rows returned.",
    },
    examples: spec.examples,
    tags: {
      "vgi.category": "identity-protection-risk",
      "vgi.title": spec.title,
      "vgi.keywords": JSON.stringify(spec.keywords),
      "vgi.doc_llm": spec.docLlm,
      "vgi.doc_md": spec.docMd,
      "vgi.result_columns_schema": JSON.stringify(spec.resultColumns),
    },
    onBind: () => ({ outputSchema: schema }),
    initialState: (p) => ({
      done: false,
      since: p.args.since ? p.args.since : EPOCH_ISO, // NULL/empty → full sync from epoch (§2d)
      lagMs: durationToMs(p.args.safety_lag),
      top: Number(p.args.page_size),
    }),
    process: async (p, state: State, out: OutputCollector) => {
      if (state.done) {
        out.finish();
        return;
      }
      const secret = secretsOfType(p.secrets, "azure_graph")[0];
      if (!secret) throw new Error(`${spec.fn}: attach an 'azure_graph' secret (TYPE azure_graph)`);
      const client = clientFactory(secret as Record<string, unknown>);

      const { rows, watermarkNext } = await collectWatermark(
        client.fetchJson,
        spec,
        state.since,
        state.lagMs,
        state.top,
        now,
      );
      out.emit(buildWatermarkBatch(spec, schema, rows, watermarkNext));
      state.done = true; // next process() call hits the done branch and finishes.
    },
  });
}
