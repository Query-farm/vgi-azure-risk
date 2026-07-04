// Arrow output schemas + row→batch mapping for the three Identity-Protection
// collections. One CollectionSpec drives everything (schema, filter time field,
// business columns, required Graph scope), so risky_users / risk_detections /
// risky_service_principals are data, not duplicated code.
//
// PII masking note (SPEC §4a, graph-core decision H): risk rows are PII-bearing —
// `ip_address`, location, and userPrincipalName/userDisplayName. The worker emits the
// RAW verdict; masking is a `vgi-pii -> vgi-mask` view declared by the CONSUMER, using
// format-preserving encryption (FPE) on any join key (userId/ipAddress) so the
// mandatory risk_detections.userId <-> risky_users.id reconciliation join (§2c) and
// the vgi-azure-signins join (§1) still match on masked keys; location free-text may
// be fully redacted.

import { Schema, Field, Utf8 } from "@query-farm/apache-arrow";
import { batchFromColumns } from "@query-farm/vgi";
import { ROW_KIND, MARKER, WATERMARK_NEXT } from "@vgi-azure/graph-core";
import { EPOCH_ISO, type CollectionSpec, type RiskRow } from "./risk-watermark.js";

export interface BusinessCol {
  /** SQL column name. */ col: string;
  /** Graph field name in the object. */ field: string;
}

/** Per-collection column set. `id`, `risk_level`, `risk_state`, `ip_address` and the
 *  collection's time column (`risk_last_updated_date_time` / `detected_date_time`)
 *  are surfaced explicitly per the SPEC; the rest ride the generic mapper. */
export interface RiskCollectionSpec extends CollectionSpec {
  /** The SQL column name for this collection's time field. */ timeCol: string;
  business: BusinessCol[];
}

// --- STATE collections (cursor B, riskLastUpdatedDateTime): riskyUsers / riskySPs.
// One row per principal that MUTATES IN PLACE; risk state is a field change, never a
// tombstone (SPEC §2c). These are the SOURCE OF TRUTH for current riskState and the
// MANDATORY reconciliation target for risk_detections (§2c).

export const RISKY_USERS: RiskCollectionSpec = {
  fn: "risky_users",
  collection: "riskyUsers",
  timeField: "riskLastUpdatedDateTime",
  timeCol: "risk_last_updated_date_time",
  scope: "IdentityRiskyUser.Read.All",
  description:
    "Entra ID Protection risky users (current per-user risk STATE) via Microsoft Graph, " +
    "lagged-watermark on riskLastUpdatedDateTime. SOURCE OF TRUTH for current riskState: any " +
    "risk_detections row MUST be reconciled against the matching risky_users row (join userId <-> id) " +
    "before acting — a detection's riskState can be stale (§2c). Absence from a page NEVER means " +
    "'cleared'; dismissal is a riskState field change, not a delete.",
  business: [
    { col: "user_principal_name", field: "userPrincipalName" },
    { col: "user_display_name", field: "userDisplayName" },
    { col: "risk_detail", field: "riskDetail" },
    { col: "ip_address", field: "ipAddress" },
  ],
};

export const RISKY_SERVICE_PRINCIPALS: RiskCollectionSpec = {
  fn: "risky_service_principals",
  collection: "riskyServicePrincipals",
  timeField: "riskLastUpdatedDateTime",
  timeCol: "risk_last_updated_date_time",
  // The user scope does NOT subsume this collection — it 403s under IdentityRiskyUser.Read.All
  // (SPEC §3 committee §6.2 fix). IdentityRiskyServicePrincipal.Read.All is REQUIRED, not optional.
  scope: "IdentityRiskyServicePrincipal.Read.All",
  description:
    "Entra ID Protection risky service principals (current per-SP risk STATE) via Microsoft Graph, " +
    "lagged-watermark on riskLastUpdatedDateTime. REQUIRES IdentityRiskyServicePrincipal.Read.All " +
    "(the user-risk scope 403s here). Source of truth for current SP riskState; dismissal is a field " +
    "change, not a delete.",
  business: [
    { col: "app_id", field: "appId" },
    { col: "display_name", field: "displayName" },
    { col: "risk_detail", field: "riskDetail" },
    { col: "ip_address", field: "ipAddress" },
  ],
};

// --- EVENT collection (cursor A, detectedDateTime): riskDetections.
// Append-mostly; a detection is IMMUTABLE EVIDENCE created once. Its riskState later
// transitions WITHOUT moving detectedDateTime (§2c state-transition leak) — which is
// exactly why the risky_users reconciliation join above is MANDATORY.

export const RISK_DETECTIONS: RiskCollectionSpec = {
  fn: "risk_detections",
  collection: "riskDetections",
  timeField: "detectedDateTime",
  timeCol: "detected_date_time",
  scope: "IdentityRiskEvent.Read.All",
  description:
    "Entra ID Protection risk detections (immutable detection EVENTS) via Microsoft Graph, " +
    "lagged-watermark on detectedDateTime. A detection's riskState transitions in place without " +
    "moving detectedDateTime, so this cursor never re-surfaces a verdict change — consumers MUST " +
    "join userId <-> risky_users.id and read the CURRENT verdict there (§2c), never act on the " +
    "detection's own (possibly stale) riskState.",
  business: [
    { col: "user_id", field: "userId" },
    { col: "user_principal_name", field: "userPrincipalName" },
    { col: "risk_event_type", field: "riskEventType" },
    { col: "detection_timing_type", field: "detectionTimingType" },
    { col: "ip_address", field: "ipAddress" },
  ],
};

export const SPECS: readonly RiskCollectionSpec[] = [RISKY_USERS, RISK_DETECTIONS, RISKY_SERVICE_PRINCIPALS];

/**
 * Column order per collection:
 *   id, <time_col>, risk_level, risk_state, <business…>, _row_kind, _watermark_next
 * `risk_level`/`risk_state` mirror riskLevel/riskState; `risk_state` is the cheap
 * change-tracking column the SPEC surfaces (`_risk_state` in §4 → here `risk_state`).
 * The two control columns close every row per the strict marker contract.
 */
export function schemaFor(spec: RiskCollectionSpec): Schema {
  return new Schema([
    new Field("id", new Utf8(), true),
    new Field(spec.timeCol, new Utf8(), true),
    new Field("risk_level", new Utf8(), true),
    new Field("risk_state", new Utf8(), true),
    ...spec.business.map((b) => new Field(b.col, new Utf8(), true)),
    new Field(ROW_KIND, new Utf8(), true),
    new Field(WATERMARK_NEXT, new Utf8(), true),
  ]);
}

function allBusinessCols(spec: RiskCollectionSpec): string[] {
  return ["id", spec.timeCol, "risk_level", "risk_state", ...spec.business.map((b) => b.col)];
}

/**
 * Build one Arrow batch: the business rows (with `_row_kind` NULL, `_watermark_next`
 * NULL — consumers read data via `WHERE _row_kind IS NULL`) followed by exactly ONE
 * strict marker row (ALL business columns null, `_row_kind='marker'`,
 * `_watermark_next` = the clamped ISO watermark to persist). This is the graph-core
 * §D marker contract; N+1 rows in one batch keep the cursor atomic with its data.
 *
 * There is NO authoritative per-row watermark stamp on these lagged rows — the
 * committed watermark is only knowable AFTER the last page (clampWatermark over the
 * whole scan, §2b), so it lives solely on the marker row.
 */
export function buildWatermarkBatch(
  spec: RiskCollectionSpec,
  schema: Schema,
  rows: RiskRow[],
  watermarkNext: string,
) {
  const cols: Record<string, unknown[]> = {};
  for (const name of allBusinessCols(spec)) cols[name] = [];
  cols[ROW_KIND] = [];
  cols[WATERMARK_NEXT] = [];

  for (const r of rows) {
    cols.id!.push(r.id);
    cols[spec.timeCol]!.push(r.timeSeen);
    cols.risk_level!.push(str(r.fields.riskLevel));
    cols.risk_state!.push(str(r.fields.riskState));
    for (const b of spec.business) cols[b.col]!.push(str(r.fields[b.field]));
    cols[ROW_KIND]!.push(null); // business row
    cols[WATERMARK_NEXT]!.push(null); // never authoritative per-row (§2b)
  }

  // The single strict marker row: all business cols null, cursor on _watermark_next.
  for (const name of allBusinessCols(spec)) cols[name]!.push(null);
  cols[ROW_KIND]!.push(MARKER);
  cols[WATERMARK_NEXT]!.push(watermarkNext);

  return batchFromColumns(cols as Record<string, unknown[]>, schema);
}

function str(v: unknown): string | null {
  return v == null ? null : String(v);
}

export { EPOCH_ISO };
