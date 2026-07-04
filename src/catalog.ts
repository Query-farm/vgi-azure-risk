// The `azure` catalog descriptor + the shared azure_graph secret type. Risk is a thin
// catalog over graph-core, so it REUSES the exact app-only client-credentials secret
// shape frozen by vgi-azure-directory (§3) — same secret, one CREATE SECRET across the set.

import { Schema, Field, Utf8 } from "@query-farm/apache-arrow";
import type { CatalogDescriptor, SecretTypeDescriptor, VgiFunction } from "@query-farm/vgi";

export const AZURE_GRAPH_SECRET: SecretTypeDescriptor = {
  name: "azure_graph",
  description: "Microsoft Entra app-only (client-credentials) credentials for Microsoft Graph",
  schema: new Schema([
    new Field("tenant_id", new Utf8(), true),
    new Field("client_id", new Utf8(), true),
    new Field("client_secret", new Utf8(), true, new Map([["redact", "true"]])),
  ]),
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
    sourceUrl: "https://query.farm",
    secretTypes: [AZURE_GRAPH_SECRET],
    schemas: [{ name: "main", functions }],
  };
}
