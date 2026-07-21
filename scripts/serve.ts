// Serve the vgi-azure-risk worker over HTTP with the standardized VGI landing surface.
//
//   GET  /                                     → the shared vendored VGI landing.html
//   GET  /describe.json                        → the worker's catalog introspection
//   GET  /describe/{catalog}/{schema}/{t}.json → lazy per-object columns
//   GET  /health                               → JSON health endpoint (needs NO azure creds)
//   POST /                                     → the VGI RPC transport (what DuckDB attaches to)
//
// Run it:  PORT=8000 bun run scripts/serve.ts   (default port 8787)
// Attach:  ATTACH 'risk' AS risk (TYPE vgi, LOCATION 'http://localhost:8000');
//          CREATE SECRET g (TYPE azure_graph, TENANT_ID '…', CLIENT_ID '…', CLIENT_SECRET '…');
//          SELECT * FROM risk.risky_users() WHERE _row_kind IS NULL;
//
// Everything below the worker's own identity — protocol assembly, state-token
// signing, CORS, the landing surface, Bun.serve — lives in the SDK's
// serveVgiWorker. Set VGI_SIGNING_KEY (64 hex chars) for any real deployment;
// without it the SDK generates an ephemeral key and warns.
//
// The wiring here mirrors src/worker.ts (the stdio entry): the same real
// MSAL-backed Graph client is wired into the same risk table functions, same
// registry + catalog. The three functions stay credential-gated at QUERY time
// (each needs a live app-only azure_graph secret), so /health and catalog
// introspection work with no azure credentials present. Adding a function means
// updating BOTH entries.

import { serveVgiWorker } from "@query-farm/vgi/serve";
import { ReadOnlyCatalogInterface, FunctionRegistry } from "@query-farm/vgi";
import { TokenCache, makeGraphClient, type Fetch } from "@vgi-azure/graph-core";
import { makeMsalMinter } from "@vgi-azure/node-auth";
import { makeRiskFunction } from "../src/functions.js";
import { SPECS } from "../src/schema.js";
import { makeCatalog } from "../src/catalog.js";

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

serveVgiWorker({
  name: "risk",
  doc: "Microsoft Entra ID Protection risk feed: risky_users, risky_service_principals, and risk_detections as incremental DuckDB table functions over Microsoft Graph.",
  version: "0.1.0",
  repositoryUrl: "https://github.com/Query-farm/vgi-azure-risk",
  serverId: "vgi-azure-risk",
  registry,
  catalogInterface,
});
