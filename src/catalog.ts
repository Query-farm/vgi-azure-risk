// The `azure` catalog descriptor + the shared azure_graph secret type. Risk is a thin
// catalog over graph-core, so it REUSES the exact app-only client-credentials secret
// shape frozen by vgi-azure-directory (§3) — same secret, one CREATE SECRET across the set.

import { Schema, Field, Utf8 } from "@query-farm/apache-arrow";
import type { CatalogDescriptor, SecretTypeDescriptor, ViewDescriptor, VgiFunction } from "@query-farm/vgi";

const REPO = "https://github.com/Query-farm/vgi-azure-risk";
const ISSUES = `${REPO}/issues`;

export const AZURE_GRAPH_SECRET: SecretTypeDescriptor = {
  name: "azure_graph",
  description: "Microsoft Entra app-only (client-credentials) credentials for Microsoft Graph",
  schema: new Schema([
    new Field("tenant_id", new Utf8(), true),
    new Field("client_id", new Utf8(), true),
    new Field("client_secret", new Utf8(), true, new Map([["redact", "true"]])),
  ]),
};

/** Catalog-level tags: docs, discovery, provenance, and the agent-test suite. */
const CATALOG_TAGS: Record<string, string> = {
  "vgi.title": "Microsoft Entra ID Protection Risk",
  "vgi.doc_llm":
    "Microsoft Entra ID Protection risk feed as SQL table functions over Microsoft Graph. Reach for it to " +
    "sync who and what is risky in the tenant: risky_users (current per-user risk STATE), " +
    "risky_service_principals (current per-workload-identity risk STATE), and risk_detections (immutable " +
    "detection EVENTS). Each is incremental via a lagged `TIMESTAMP` watermark — pass since := <prior " +
    "_watermark_next>, or omit since for a full sync from epoch; read data rows with WHERE _row_kind IS " +
    "NULL and persist the marker row's _watermark_next. The STATE tables are the source of truth for the " +
    "current verdict: any risk_detections row MUST be reconciled against risky_users (join user_id <-> id) " +
    "because a detection's own risk_state can be stale. Requires an app-only azure_graph secret " +
    "(tenant_id, client_id, client_secret) with IdentityRiskyUser.Read.All + IdentityRiskEvent.Read.All + " +
    "IdentityRiskyServicePrincipal.Read.All (the SP scope is not subsumed by the user scope), and an " +
    "Entra ID P2 license (Identity Protection 403s without P2).",
  "vgi.doc_md":
    "## Microsoft Entra ID Protection Risk\n\n" +
    "Incremental access to the Microsoft Entra ID Protection risk feed via Microsoft Graph, exposed as " +
    "three DuckDB table functions.\n\n" +
    "- **`risky_users`** — current per-user risk state (source of truth for the verdict).\n" +
    "- **`risky_service_principals`** — current per-service-principal (workload identity) risk state.\n" +
    "- **`risk_detections`** — immutable risk detection events.\n\n" +
    "Each function returns data rows plus a single marker row (`_row_kind = 'marker'`) whose " +
    "`_watermark_next` column holds the ISO-8601 instant to persist and replay as the next scan's `since`. " +
    "Call with no arguments for a full sync from epoch; pass `since := '<_watermark_next>'` for an " +
    "incremental sync. Reconcile `risk_detections` against `risky_users` (join `user_id` <-> `id`) for the " +
    "current verdict. Requires an app-only `azure_graph` secret, the three `Identity*.Read.All` Graph " +
    "permissions, and an Entra ID P2 license.",
  "vgi.keywords": JSON.stringify([
    "azure",
    "entra id",
    "azure ad",
    "microsoft graph",
    "identity protection",
    "risk",
    "risky users",
    "risk detections",
    "risky service principals",
    "watermark",
    "identity",
    "security",
  ]),
  "vgi.author": "Query Farm LLC",
  "vgi.copyright": "Copyright 2026 Query Farm LLC",
  "vgi.license": "MIT",
  "vgi.support_contact": ISSUES,
  "vgi.support_policy_url": ISSUES,
  // Guaranteed-runnable, catalog-qualified examples (VGI509/VGI906). A LIVE sync needs an
  // attached azure_graph secret and a network call to Microsoft Graph, so these are
  // credential-free `LIMIT 0` schema/bind probes: they verify each function binds and
  // expose its exact result columns without fetching (onBind runs; process() — where the
  // secret + network live — is never reached). Drop the `LIMIT 0` and attach an
  // azure_graph secret to pull real rows — the data-returning queries live in each
  // function's `examples` and the schema `example_queries`.
  "vgi.executable_examples": JSON.stringify([
    {
      name: "risky_users_bind_probe",
      description:
        "Bind risky_users and expose its result columns (credential-free; drop LIMIT 0 and attach an azure_graph secret to sync real data)",
      sql: "SELECT id, user_principal_name, risk_level, risk_state FROM azure.main.risky_users() LIMIT 0",
    },
    {
      name: "risk_detections_bind_probe",
      description:
        "Bind risk_detections and expose its result columns (credential-free; attach an azure_graph secret to sync real data)",
      sql: "SELECT id, user_id, risk_event_type, detected_date_time FROM azure.main.risk_detections() LIMIT 0",
    },
    {
      name: "risky_service_principals_bind_probe",
      description:
        "Bind risky_service_principals and expose its result columns (credential-free; attach an azure_graph secret to sync real data)",
      sql: "SELECT id, app_id, display_name, risk_level, risk_state FROM azure.main.risky_service_principals() LIMIT 0",
    },
  ]),
  // The agent-suitability suite (VGI520/VGI920), catalog only. `reference_sql` is the
  // canonical fully-qualified solution (grader-only) — it drives static coverage (VGI520)
  // so every object is exercised, and authenticated reference grading; `success_criteria`
  // is the LLM-judge rubric used when the sim runs unauthenticated (a live risk scan needs
  // an azure_graph secret and returns tenant-specific, non-deterministic data, so an
  // exact-compare reference can only be graded with real credentials). Neither reference_sql
  // nor success_criteria is ever shown to the analyst.
  "vgi.agent_test_tasks": JSON.stringify([
    {
      name: "list_at_risk_users",
      prompt: "List the users in the Entra tenant who are currently at risk, with their risk level.",
      reference_sql:
        "SELECT user_principal_name, risk_level FROM azure.main.risky_users() WHERE _row_kind IS NULL AND risk_state = 'atRisk' ORDER BY user_principal_name",
      success_criteria:
        "The answer queries risky_users(), filters to data rows (_row_kind IS NULL) with risk_state = 'atRisk', and returns user_principal_name and risk_level.",
    },
    {
      name: "reconcile_detection_verdict",
      prompt: "For each recent risk detection, what is the affected user's current risk verdict?",
      reference_sql:
        "SELECT d.id, d.risk_event_type, u.risk_state AS current_verdict FROM azure.main.risk_detections() d JOIN azure.main.risky_users() u ON d.user_id = u.id WHERE d._row_kind IS NULL AND u._row_kind IS NULL",
      success_criteria:
        "The answer joins risk_detections() to risky_users() on user_id = id (both filtered to _row_kind IS NULL) and reads risk_state from risky_users rather than from the detection, explaining that the detection's own risk_state can be stale.",
    },
    {
      name: "high_risk_service_principals",
      prompt: "Which service principals (workload identities) in the tenant are currently high risk?",
      reference_sql:
        "SELECT display_name, app_id FROM azure.main.risky_service_principals() WHERE _row_kind IS NULL AND risk_level = 'high' ORDER BY display_name",
      success_criteria:
        "The answer queries risky_service_principals(), filters to data rows (_row_kind IS NULL) with risk_level = 'high', and returns the service principal display_name and app_id.",
    },
    {
      name: "save_watermark",
      prompt: "After syncing risky users, how do I get the cursor to use for the next incremental sync?",
      reference_sql: "SELECT _watermark_next FROM azure.main.risky_users() WHERE _row_kind = 'marker'",
      success_criteria:
        "The answer selects _watermark_next from the marker row (_row_kind = 'marker') of risky_users() and explains it should be replayed via the since argument.",
    },
    {
      name: "browse_collections",
      prompt: "What risk feeds does this worker expose, and which table function serves each?",
      reference_sql: "SELECT collection, table_function FROM azure.main.risk_collections ORDER BY collection",
      success_criteria:
        "The answer reads risk_collections and lists the risk feeds (risky users, risky service principals, risk detections) alongside the table function that serves each.",
    },
  ]),
};

/** Schema-level tags: docs, discovery, the category registry, and shown examples. */
const SCHEMA_TAGS: Record<string, string> = {
  "vgi.title": "Entra ID Protection Risk",
  "vgi.doc_llm":
    "The Microsoft Entra ID Protection risk table functions. risky_users and risky_service_principals are " +
    "current-STATE feeds (one mutable row per principal, watermarked on risk_last_updated_date_time); " +
    "risk_detections is an immutable EVENT feed (watermarked on detected_date_time). Each scan returns data " +
    "rows followed by one marker row whose _watermark_next is the ISO-8601 cursor to persist for the next " +
    "scan. Omit since for a full sync from epoch. The STATE feeds are the source of truth: reconcile " +
    "risk_detections against risky_users (join user_id <-> id) for the current verdict.",
  "vgi.doc_md":
    "## Entra ID Protection risk functions\n\n" +
    "| Function | Kind | Watermark field | Returns |\n" +
    "| --- | --- | --- | --- |\n" +
    "| `risky_users` | State | `risk_last_updated_date_time` | current user risk + watermark |\n" +
    "| `risky_service_principals` | State | `risk_last_updated_date_time` | current SP risk + watermark |\n" +
    "| `risk_detections` | Event | `detected_date_time` | risk detection events + watermark |\n\n" +
    "All three share the same shape: read data rows with `WHERE _row_kind IS NULL`, and take the next " +
    "cursor from the single marker row's `_watermark_next`. Each requires an app-only `azure_graph` secret " +
    "and an Entra ID P2 license.",
  "vgi.keywords": JSON.stringify([
    "entra id protection",
    "azure ad",
    "risk",
    "risky users",
    "risk detections",
    "risky service principals",
    "watermark",
    "identity",
    "security",
  ]),
  domain: "security",
  // Ordered navigation registry; each `name` is referenced by an object's vgi.category.
  "vgi.categories": JSON.stringify([
    {
      name: "discovery",
      title: "Discovery",
      description:
        "Browsable, credential-free entry points for finding your way around the risk catalog.",
    },
    {
      name: "identity-protection-risk",
      title: "Identity Protection Risk Feeds",
      description:
        "Microsoft Entra ID Protection risk feeds (risky users, risky service principals, risk detections) via Microsoft Graph lagged-watermark cursors.",
    },
  ]),
  "vgi.example_queries": JSON.stringify([
    {
      description: "Users currently at risk",
      sql: "SELECT id, user_principal_name, risk_level FROM azure.main.risky_users() WHERE _row_kind IS NULL AND risk_state = 'atRisk'",
    },
    {
      description: "Incremental sync of risk detections from a saved watermark",
      sql: "SELECT id, user_id, risk_event_type FROM azure.main.risk_detections(since := '<_watermark_next>') WHERE _row_kind IS NULL",
    },
    {
      description: "Reconcile detections against the current per-user verdict (mandatory §2c join)",
      sql: "SELECT d.id, d.risk_event_type, u.risk_state AS current_verdict FROM azure.main.risk_detections() d JOIN azure.main.risky_users() u ON d.user_id = u.id WHERE d._row_kind IS NULL AND u._row_kind IS NULL",
    },
    {
      description: "High-risk service principals",
      sql: "SELECT id, app_id, display_name FROM azure.main.risky_service_principals() WHERE _row_kind IS NULL AND risk_level = 'high'",
    },
  ]),
};

// A browsable, credential-free discovery view: the three risk feeds, the table function
// that serves each, its cursor/watermark field, and a one-line description. Its definition
// is a self-contained VALUES relation evaluated entirely by DuckDB (no worker call, no
// secret), so an agent can `SELECT * FROM azure.main.risk_collections` to learn the surface
// before it ever needs Microsoft Graph credentials. This is the worker's browsable entry
// point (VGI146): every other object here is a credential-gated table function.
const RISK_COLLECTIONS_VIEW: ViewDescriptor = {
  name: "risk_collections",
  definition:
    "SELECT collection, kind, table_function, watermark_field, description FROM (VALUES " +
    "('risky_users', 'state', 'risky_users', 'risk_last_updated_date_time', 'Current per-user risk state; source of truth for the verdict'), " +
    "('risky_service_principals', 'state', 'risky_service_principals', 'risk_last_updated_date_time', 'Current per-service-principal (workload identity) risk state'), " +
    "('risk_detections', 'event', 'risk_detections', 'detected_date_time', 'Immutable risk detection events (reconcile against risky_users for the current verdict)')" +
    ") AS t(collection, kind, table_function, watermark_field, description)",
  comment:
    "The Entra ID Protection risk feeds this catalog exposes and the lagged-watermark table function that serves each. Browsable without credentials.",
  columnComments: {
    collection: "The risk feed slug (risky_users / risky_service_principals / risk_detections).",
    kind: "Feed kind: 'state' (current mutable verdict per principal) or 'event' (immutable detection).",
    table_function: "The catalog table function that syncs this feed as a lagged-watermark cursor.",
    watermark_field: "The row time field the incremental watermark cursor advances on.",
    description: "A one-line description of the feed.",
  },
  tags: {
    "vgi.title": "Risk Feed Index",
    "vgi.category": "discovery",
    domain: "security",
    "vgi.doc_llm":
      "A static, credential-free catalog of the Entra ID Protection risk feeds this worker exposes: one row " +
      "per feed (risky_users, risky_service_principals, risk_detections) giving its kind (state vs event), " +
      "the table function that syncs it as a lagged-watermark cursor, and the watermark field it advances " +
      "on. Query it to discover the worker's surface before attaching an azure_graph secret.",
    "vgi.doc_md":
      "## risk_collections\n\n" +
      "A browsable, credential-free index of the Entra ID Protection risk feeds this catalog exposes. One " +
      "row per feed, naming the lagged-watermark table function that syncs it and its watermark field. " +
      "Start here, then call the named function (with an `azure_graph` secret attached) to sync that feed.",
    "vgi.keywords": JSON.stringify([
      "risk",
      "collections",
      "catalog",
      "discovery",
      "risky users",
      "risky service principals",
      "risk detections",
      "table functions",
    ]),
    "vgi.example_queries": JSON.stringify([
      {
        description: "List every risk feed and the table function that serves it",
        sql: "SELECT collection, table_function FROM azure.main.risk_collections ORDER BY collection",
      },
      {
        description: "Find the state feeds and their watermark field",
        sql: "SELECT collection, watermark_field FROM azure.main.risk_collections WHERE kind = 'state'",
      },
    ]),
  },
};

// Required Graph APPLICATION permissions (admin-consented), least-privilege (SPEC §3):
//   IdentityRiskyUser.Read.All             -> risky_users            (user-risk STATE)
//   IdentityRiskEvent.Read.All             -> risk_detections        (detection EVENTS)
//   IdentityRiskyServicePrincipal.Read.All -> risky_service_principals (SP-risk STATE)
// The committee §6.2 fix: the SP collections 403 under IdentityRiskyUser.Read.All — the
// user-risk scope does NOT subsume them, so IdentityRiskyServicePrincipal.Read.All is
// REQUIRED, not optional. Licensing gate: Identity Protection requires Entra ID P2; without
// P2 Graph 403s even with correct consent (no P2, no data).
export function makeCatalog(functions: VgiFunction[]): CatalogDescriptor {
  return {
    name: "azure",
    defaultSchema: "main",
    comment:
      "Microsoft Entra ID Protection risk feed (risky users / risk detections / risky service " +
      "principals) via Microsoft Graph lagged-watermark — vgi-azure-risk. Perms: " +
      "IdentityRiskyUser.Read.All + IdentityRiskEvent.Read.All + IdentityRiskyServicePrincipal.Read.All " +
      "(the SP scope is REQUIRED, not subsumed by the user scope). Requires Entra ID P2. " +
      "risk_detections consumers MUST reconcile against risky_users for the current verdict (§2c).",
    sourceUrl: REPO,
    tags: CATALOG_TAGS,
    secretTypes: [AZURE_GRAPH_SECRET],
    schemas: [
      {
        name: "main",
        comment:
          "Microsoft Entra ID Protection risk objects (risky users, risky service principals, risk detections) as lagged-watermark Graph feeds.",
        tags: SCHEMA_TAGS,
        views: [RISK_COLLECTIONS_VIEW],
        functions,
      },
    ],
  };
}
