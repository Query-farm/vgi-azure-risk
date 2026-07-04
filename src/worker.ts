// vgi-azure-risk stdio worker entry. DuckDB spawns this and ATTACHes it:
//   ATTACH 'risk' AS risk (TYPE vgi, LOCATION '/path/to/worker.ts');
//   CREATE SECRET g (TYPE azure_graph, TENANT_ID '…', CLIENT_ID '…', CLIENT_SECRET '…');
//   SELECT * FROM risk.risky_users() WHERE _row_kind IS NULL;              -- full sync
//   SELECT * FROM risk.risk_detections(since := '<_watermark_next>');      -- incremental
//
// Cursor: a lagged TIMESTAMP WATERMARK (SPEC §2) — `since` in / `_watermark_next` out —
// advanced through graph-core clampWatermark with a `ge` boundary + dedup-by-id. No delta
// token, no tombstone, no 410 resync (§2d). AUDIENCE is 'graph': every collection lives on
// graph.microsoft.com, but the token cache is still keyed by (tenant, client, AUDIENCE) so it
// composes with future ARM / Log-Analytics workers sharing this graph-core cache (§3).

import { Worker, ReadOnlyCatalogInterface, FunctionRegistry } from "@query-farm/vgi";
import { TokenCache, makeGraphClient, type Fetch } from "@vgi-azure/graph-core";
import { makeMsalMinter } from "@vgi-azure/node-auth";
import { makeRiskFunction } from "./functions.js";
import { SPECS } from "./schema.js";
import { makeCatalog } from "./catalog.js";

const cache = new TokenCache(makeMsalMinter());

const clientFactory = (secret: Record<string, unknown>) =>
  makeGraphClient({
    fetch: globalThis.fetch as unknown as Fetch,
    cache,
    cred: {
      tenantId: String(secret.tenant_id ?? ""),
      clientId: String(secret.client_id ?? ""),
      clientSecret: secret.client_secret != null ? String(secret.client_secret) : undefined,
    },
    audience: "graph", // Identity Protection is a Graph-only surface.
  });

const functions = SPECS.map((spec) => makeRiskFunction(spec, clientFactory));

const registry = new FunctionRegistry();
for (const f of functions) registry.register(f);

const catalogInterface = new ReadOnlyCatalogInterface(makeCatalog(functions), registry);

new Worker({ functions, catalogInterface }).run();
