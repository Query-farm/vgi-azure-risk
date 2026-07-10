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

export interface FnExample {
  sql: string;
  description: string;
}

/** One entry of a static vgi.result_columns_schema — {name, type, description}. */
export interface ResultColumn {
  name: string;
  /** A real DuckDB type (VARCHAR / …). */ type: string;
  description: string;
}

/** Per-collection column set. `id`, `risk_level`, `risk_state`, `ip_address` and the
 *  collection's time column (`risk_last_updated_date_time` / `detected_date_time`)
 *  are surfaced explicitly per the SPEC; the rest ride the generic mapper. */
export interface RiskCollectionSpec extends CollectionSpec {
  /** The SQL column name for this collection's time field. */ timeCol: string;
  business: BusinessCol[];
  /** vgi.title — human display name (multi-word so it doesn't equal the machine name). */
  title: string;
  /** vgi.keywords — search terms / synonyms. */
  keywords: string[];
  /** vgi.doc_llm — LLM-oriented "what is it / when to use it" prose. */
  docLlm: string;
  /** vgi.doc_md — richer human Markdown narrative. */
  docMd: string;
  /** vgi.result_columns_schema — the static result columns as {name,type,description}. */
  resultColumns: ResultColumn[];
  /** Per-function examples surfaced via the function descriptor. */
  examples: FnExample[];
}

// The two control/cursor columns are common to every collection's output; only the
// time column and the business columns differ. This shared tail keeps every
// result_columns_schema aligned with schemaFor()'s field order.
const RESULT_COLUMNS_TAIL: ResultColumn[] = [
  {
    name: "_row_kind",
    type: "VARCHAR",
    description: "NULL for data rows; 'marker' for the single trailing cursor row.",
  },
  {
    name: "_watermark_next",
    type: "VARCHAR",
    description:
      "On the marker row, the ISO-8601 instant to persist and replay as the next scan's `since`; NULL on data rows. There is no authoritative per-row watermark.",
  },
];

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
  title: "Entra Risky Users Feed",
  keywords: [
    "entra id protection",
    "azure ad",
    "risky users",
    "user risk",
    "risk state",
    "risk level",
    "identity protection",
    "compromised",
    "watermark",
    "identity",
    "security",
  ],
  docLlm:
    "Current per-user risk STATE from Microsoft Entra ID Protection via Microsoft Graph. Reach for it " +
    "to answer 'which users are risky right now and how bad', reading risk_level (low/medium/high/hidden) " +
    "and risk_state (atRisk/confirmedCompromised/dismissed/remediated). This is the SOURCE OF TRUTH for " +
    "the current verdict — any risk_detections row MUST be reconciled against the matching risky_users " +
    "row (join risk_detections.user_id <-> risky_users.id) before acting, because a detection's own " +
    "risk_state can be stale. Incremental via a lagged TIMESTAMP watermark on risk_last_updated_date_time: " +
    "pass since := <prior _watermark_next>, or omit since for a full sync from epoch. Read data rows with " +
    "WHERE _row_kind IS NULL and persist the marker row's _watermark_next as the next cursor. Requires an " +
    "app-only azure_graph secret with IdentityRiskyUser.Read.All and an Entra ID P2 license.",
  docMd:
    "## risky_users\n\n" +
    "Current per-user risk state from Microsoft Entra ID Protection, backed by Graph " +
    "`identityProtection/riskyUsers` with a lagged-watermark cursor on `risk_last_updated_date_time`.\n\n" +
    "Read data rows with `WHERE _row_kind IS NULL`; persist the marker row's `_watermark_next` and replay " +
    "it as `since` on the next scan. This table is the source of truth for the current verdict — reconcile " +
    "any `risk_detections` row against it (join `user_id` <-> `id`). See the examples for full, runnable queries.",
  resultColumns: [
    {
      name: "id",
      type: "VARCHAR",
      description:
        "The risky user's object id (GUID); join key to risk_detections.user_id. NULL on the marker row.",
    },
    {
      name: "risk_last_updated_date_time",
      type: "VARCHAR",
      description:
        "ISO-8601 instant the user's risk was last updated (the watermark field). NULL on the marker row.",
    },
    {
      name: "risk_level",
      type: "VARCHAR",
      description: "Current aggregate risk level (low/medium/high/hidden/none). NULL on the marker row.",
    },
    {
      name: "risk_state",
      type: "VARCHAR",
      description:
        "Current risk state (atRisk/confirmedCompromised/dismissed/remediated/confirmedSafe). NULL on the marker row.",
    },
    { name: "user_principal_name", type: "VARCHAR", description: "The user's UPN (sign-in name). PII." },
    { name: "user_display_name", type: "VARCHAR", description: "The user's display name. PII." },
    {
      name: "risk_detail",
      type: "VARCHAR",
      description: "Latest risk detail / remediation reason (e.g. adminConfirmedUserCompromised).",
    },
    { name: "ip_address", type: "VARCHAR", description: "IP address associated with the risk. PII." },
    ...RESULT_COLUMNS_TAIL,
  ],
  examples: [
    {
      sql: "SELECT id, user_principal_name, risk_level, risk_state FROM azure.main.risky_users() WHERE _row_kind IS NULL AND risk_state = 'atRisk'",
      description: "Full sync of users currently at risk (data rows only)",
    },
    {
      sql: "SELECT id, user_principal_name, risk_detail FROM azure.main.risky_users(since := '<_watermark_next>') WHERE _row_kind IS NULL",
      description: "Incremental sync replaying a previously saved watermark",
    },
    {
      sql: "SELECT _watermark_next FROM azure.main.risky_users() WHERE _row_kind = 'marker'",
      description: "Read the watermark to persist for the next sync",
    },
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
  title: "Entra Risky Service Principals Feed",
  keywords: [
    "entra id protection",
    "azure ad",
    "risky service principals",
    "service principal",
    "workload identity",
    "app risk",
    "risk state",
    "identity protection",
    "watermark",
    "security",
  ],
  docLlm:
    "Current per-service-principal (workload identity) risk STATE from Microsoft Entra ID Protection via " +
    "Microsoft Graph. Reach for it to answer 'which app/service-principal identities are risky right now', " +
    "reading risk_level and risk_state on each SP. Source of truth for the current SP verdict; dismissal is " +
    "a risk_state field change, not a delete, so absence from a page never means 'cleared'. Incremental via " +
    "a lagged TIMESTAMP watermark on risk_last_updated_date_time: pass since := <prior _watermark_next>, or " +
    "omit since for a full sync from epoch. Read data rows with WHERE _row_kind IS NULL and persist the " +
    "marker row's _watermark_next. REQUIRES its own scope IdentityRiskyServicePrincipal.Read.All (the " +
    "user-risk scope 403s here) plus an app-only azure_graph secret and an Entra ID P2 license.",
  docMd:
    "## risky_service_principals\n\n" +
    "Current per-service-principal risk state from Microsoft Entra ID Protection, backed by Graph " +
    "`identityProtection/riskyServicePrincipals` with a lagged-watermark cursor on " +
    "`risk_last_updated_date_time`.\n\n" +
    "Read data rows with `WHERE _row_kind IS NULL`; persist the marker row's `_watermark_next` as the next " +
    "`since`. Requires `IdentityRiskyServicePrincipal.Read.All` — the user-risk scope does not subsume it. " +
    "See the examples for full, runnable queries.",
  resultColumns: [
    {
      name: "id",
      type: "VARCHAR",
      description: "The risky service principal's object id (GUID). NULL on the marker row.",
    },
    {
      name: "risk_last_updated_date_time",
      type: "VARCHAR",
      description:
        "ISO-8601 instant the SP's risk was last updated (the watermark field). NULL on the marker row.",
    },
    {
      name: "risk_level",
      type: "VARCHAR",
      description: "Current aggregate risk level (low/medium/high/hidden/none). NULL on the marker row.",
    },
    {
      name: "risk_state",
      type: "VARCHAR",
      description:
        "Current risk state (atRisk/confirmedCompromised/dismissed/remediated). NULL on the marker row.",
    },
    { name: "app_id", type: "VARCHAR", description: "The service principal's application (client) id." },
    { name: "display_name", type: "VARCHAR", description: "The service principal's display name." },
    { name: "risk_detail", type: "VARCHAR", description: "Latest risk detail / remediation reason." },
    { name: "ip_address", type: "VARCHAR", description: "IP address associated with the risk, if any. PII." },
    ...RESULT_COLUMNS_TAIL,
  ],
  examples: [
    {
      sql: "SELECT id, app_id, display_name, risk_level, risk_state FROM azure.main.risky_service_principals() WHERE _row_kind IS NULL",
      description: "Full sync of all risky service principals (data rows only)",
    },
    {
      sql: "SELECT id, app_id, display_name FROM azure.main.risky_service_principals() WHERE _row_kind IS NULL AND risk_level = 'high'",
      description: "High-risk service principals only",
    },
    {
      sql: "SELECT _watermark_next FROM azure.main.risky_service_principals() WHERE _row_kind = 'marker'",
      description: "Read the watermark to persist for the next sync",
    },
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
  title: "Entra Risk Detections Feed",
  keywords: [
    "entra id protection",
    "azure ad",
    "risk detections",
    "risk events",
    "sign-in risk",
    "unfamiliar features",
    "anonymized ip",
    "identity protection",
    "watermark",
    "security",
  ],
  docLlm:
    "Immutable detection EVENTS from Microsoft Entra ID Protection via Microsoft Graph — each row is one " +
    "risk detection (e.g. unfamiliarFeatures, anonymizedIPAddress) created once and never moved. Reach for " +
    "it to answer 'what risk events fired, of what type, for which user, from where'. IMPORTANT: a " +
    "detection's own risk_state transitions in place WITHOUT moving detected_date_time, so this cursor " +
    "never re-surfaces a verdict change — consumers MUST join user_id <-> risky_users.id and read the " +
    "CURRENT verdict there, never act on the detection's own (possibly stale) risk_state. Incremental via a " +
    "lagged TIMESTAMP watermark on detected_date_time: pass since := <prior _watermark_next>, or omit since " +
    "for a full sync from epoch. Read data rows with WHERE _row_kind IS NULL and persist the marker row's " +
    "_watermark_next. Requires an app-only azure_graph secret with IdentityRiskEvent.Read.All and Entra ID P2.",
  docMd:
    "## risk_detections\n\n" +
    "Immutable risk detection events from Microsoft Entra ID Protection, backed by Graph " +
    "`identityProtection/riskDetections` with a lagged-watermark cursor on `detected_date_time`.\n\n" +
    "Read data rows with `WHERE _row_kind IS NULL`; persist the marker row's `_watermark_next` as the next " +
    "`since`. A detection's `risk_state` can be stale — reconcile against `risky_users` (join `user_id` " +
    "<-> `id`) for the current verdict. See the examples for full, runnable queries.",
  resultColumns: [
    {
      name: "id",
      type: "VARCHAR",
      description: "The risk detection's id (immutable event id). NULL on the marker row.",
    },
    {
      name: "detected_date_time",
      type: "VARCHAR",
      description:
        "ISO-8601 instant the detection was created (the watermark field; never moves once set). NULL on the marker row.",
    },
    {
      name: "risk_level",
      type: "VARCHAR",
      description: "Risk level at detection time (low/medium/high/hidden). NULL on the marker row.",
    },
    {
      name: "risk_state",
      type: "VARCHAR",
      description:
        "The detection's own (possibly stale) risk state; reconcile against risky_users for the current verdict. NULL on the marker row.",
    },
    {
      name: "user_id",
      type: "VARCHAR",
      description: "The affected user's object id; join key to risky_users.id.",
    },
    { name: "user_principal_name", type: "VARCHAR", description: "The affected user's UPN. PII." },
    {
      name: "risk_event_type",
      type: "VARCHAR",
      description: "The detection type (e.g. unfamiliarFeatures, anonymizedIPAddress, maliciousIPAddress).",
    },
    {
      name: "detection_timing_type",
      type: "VARCHAR",
      description: "Detection timing: realtime or offline.",
    },
    { name: "ip_address", type: "VARCHAR", description: "IP address the detection fired from. PII." },
    ...RESULT_COLUMNS_TAIL,
  ],
  examples: [
    {
      sql: "SELECT id, user_id, risk_event_type, detected_date_time FROM azure.main.risk_detections() WHERE _row_kind IS NULL",
      description: "Full sync of all risk detections (data rows only)",
    },
    {
      sql: "SELECT d.id, d.risk_event_type, u.risk_state AS current_verdict FROM azure.main.risk_detections() d JOIN azure.main.risky_users() u ON d.user_id = u.id WHERE d._row_kind IS NULL AND u._row_kind IS NULL",
      description: "Reconcile detections against the current per-user verdict (mandatory §2c join)",
    },
    {
      sql: "SELECT _watermark_next FROM azure.main.risk_detections() WHERE _row_kind = 'marker'",
      description: "Read the watermark to persist for the next sync",
    },
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
