// The Identity-Protection lagged-watermark driver — pure logic over graph-core, no
// SDK / no network. One driver serves risky_users, risk_detections, and
// risky_service_principals: a risk row is generic (id + time field + risk fields),
// so the same code walks every collection. This is the module the quiet-tenant
// watermark-proof exercises.
//
// Unlike the directory delta driver, these collections have NO /delta endpoint and
// NO @removed tombstone (SPEC §2, §2a). The only incremental lever is an OData
// `$filter` on a timestamp field, so the durable cursor is a TIMESTAMP WATERMARK the
// worker computes itself via graph-core's clampWatermark — at-least-once with a
// re-scan overlap, never the clean exactly-once window a delta token gives.
//
// CRITICAL (committee must-fix #1, SPEC §2b): the persisted watermark is advanced
// through graph-core's clampWatermark EXACTLY. We do NOT hand-roll
// `min(max(timefield), now - lag)` — that form applies zero lag on a quiet tenant
// (maxSeen << now-lag) and silently drops late-scored risk forever.

import {
  paginate,
  clampWatermark,
  isoToMs,
  msToIso,
  foldMaxSeen,
  type FetchJson,
} from "@vgi-azure/graph-core";

const GRAPH = "https://graph.microsoft.com/v1.0";

/** The epoch watermark used for a full sync (`since` NULL/empty). */
export const EPOCH_ISO = "1970-01-01T00:00:00Z";

export type Collection = "riskyUsers" | "riskDetections" | "riskyServicePrincipals";

/** The two cursor sub-types (SPEC §2a): STATE collections mutate a row in place and
 *  bump `riskLastUpdatedDateTime`; EVENT collections append a row whose
 *  `detectedDateTime` never moves. Both advance an order-independent max-seen
 *  watermark, so neither needs `$orderby`. */
export interface CollectionSpec {
  /** SQL table-function name. */ fn: string;
  collection: Collection;
  /** The OData time field the watermark filters + folds on. */ timeField: string;
  description: string;
  /** Graph application permission required (least-privilege, SPEC §3). */ scope: string;
}

export interface RiskRow {
  id: string;
  /** The row's own value of the collection's time field, as an ISO string (null if
   *  absent). Folded into max-seen; NEVER persisted per-row as the cursor (§2b). */
  timeSeen: string | null;
  /** Business fields (non-`@odata` keys) straight off the Graph object. */
  fields: Record<string, unknown>;
}

export interface WatermarkResult {
  rows: RiskRow[];
  /** The watermark to persist as `since` for the next scan: clampWatermark(maxSeen,
   *  lag, now) — always `lag` behind maxSeen (§2b). ISO string, fully serializable. */
  watermarkNext: string;
  /** Non-authoritative high-water of the time field actually seen this scan (for
   *  telemetry / assertions). NOT the committed cursor. */
  maxSeen: string;
}

/** Graph caps `$top` at 1000 (often 500 in practice); clamp defensively (SPEC §4). */
export function clampTop(pageSize: number): number {
  if (!Number.isFinite(pageSize) || pageSize <= 0) return 500;
  return Math.min(1000, Math.max(1, Math.floor(pageSize)));
}

/**
 * Build the initial filtered URL for a scan. The boundary is **`ge`** (not `gt`) so
 * the trailing lag window re-includes the boundary row; idempotent dedup-by-id makes
 * the re-include free (SPEC §2b). NO `$orderby` — Identity Protection has
 * limited/unsupported ordering on these collections and the clampWatermark advance is
 * order-independent by construction (SPEC §2a).
 */
export function watermarkStartUrl(spec: CollectionSpec, sinceIso: string, top: number): string {
  const filter = `${spec.timeField} ge ${sinceIso}`;
  return (
    `${GRAPH}/identityProtection/${spec.collection}` +
    `?$filter=${encodeURIComponent(filter)}` +
    `&$top=${clampTop(top)}`
  );
}

/** Map one raw Graph risk object to a generic risk row. There is NO tombstone here:
 *  dismissal/remediation is a `riskState` FIELD CHANGE on the same row, never a delete
 *  (SPEC §2c) — so unlike the directory driver there is no `isRemoved` branch. */
export function toRow(obj: Record<string, unknown>, timeField: string): RiskRow {
  const id = String(obj.id ?? "");
  const t = obj[timeField];
  const timeSeen = typeof t === "string" && t.length > 0 ? t : null;
  const fields: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) if (!k.startsWith("@")) fields[k] = v;
  return { id, timeSeen, fields };
}

/**
 * Drain a lagged-watermark scan to completion from `sinceIso` (an ISO watermark, or
 * EPOCH for a full sync). Pages via `@odata.nextLink` VERBATIM (graph-core paginate),
 * folds every row's time field into a running max-seen (order-independent), then
 * computes the watermark to persist as clampWatermark(maxSeen, lagMs, now).
 *
 * The loss-safety contract lives in the CALLER: persist `watermarkNext` only after
 * the rows are durably applied (no eager ack, SPEC §2c). On crash the caller still
 * holds the old `since`; re-running re-reads the overlapping lag window, absorbed
 * idempotently by upsert-by-id (at-least-once capture, exactly-once effect).
 *
 * `now` is injected so tests are deterministic; the worker passes `Date.now`.
 */
export async function collectWatermark(
  fetchJson: FetchJson,
  spec: CollectionSpec,
  sinceIso: string,
  lagMs: number,
  top: number,
  now: () => number = Date.now,
): Promise<WatermarkResult> {
  const rows: RiskRow[] = [];
  let maxSeenMs = isoToMs(sinceIso); // never advance below where we started
  const startUrl = watermarkStartUrl(spec, sinceIso, top);

  for await (const page of paginate<Record<string, unknown>>(fetchJson, startUrl)) {
    const times: number[] = [];
    for (const obj of page.value) {
      const row = toRow(obj, spec.timeField);
      rows.push(row);
      if (row.timeSeen !== null) times.push(isoToMs(row.timeSeen));
    }
    maxSeenMs = foldMaxSeen(maxSeenMs, times);
  }

  // FINAL, order-independent advance. clampWatermark UNCONDITIONALLY subtracts the
  // lag (SPEC §2b committee must-fix #1) — so on a quiet tenant the watermark still
  // sits `lag` behind maxSeen and the next late-scored update is re-read, not lost.
  const watermarkNextMs = clampWatermark(maxSeenMs, lagMs, now());
  return { rows, watermarkNext: msToIso(watermarkNextMs), maxSeen: msToIso(maxSeenMs) };
}
