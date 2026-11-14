# vgi-azure-risk

A [VGI](https://query.farm) worker (**Microsoft Entra ID Protection Risk**) for DuckDB. The Microsoft Entra ID Protection risk feed via Microsoft Graph, as three incremental DuckDB table functions: `risky_users` (current per-user risk state), `risky_service_principals` (current per-workload-identity risk state) and `risk_detections` (immutable detection events). Each returns data rows plus a single marker row (`_row_kind = 'marker'`) whose `_watermark_next` is the instant to persist and pass back as `since`; call with no arguments for a full sync. The state tables are the source of truth for the current verdict, so reconcile `risk_detections` against `risky_users` (join `user_id` to `id`).

## Quick start

Every [GitHub release](https://github.com/Query-farm/vgi-azure-risk/releases) ships a prebuilt worker binary. The `vgi` extension downloads the one for your platform, checks its SHA-256 and caches it, so there is nothing to install besides DuckDB:

```sql
INSTALL vgi FROM community;
LOAD vgi;

ATTACH 'azure' AS azure (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-azure-risk@v0.4.0');

-- Bind risky_users and expose its result columns (credential-free; drop LIMIT 0 and
-- attach an azure_graph secret to sync real data)
SELECT id, user_principal_name, risk_level, risk_state FROM azure.main.risky_users() LIMIT 0;

-- Bind risk_detections and expose its result columns (credential-free; attach an
-- azure_graph secret to sync real data)
SELECT id, user_id, risk_event_type, detected_date_time FROM azure.main.risk_detections() LIMIT 0;
```

The examples are credential-free `LIMIT 0` bind probes: they check that each function binds and show its result columns without calling Azure. To pull real rows, create an `azure_graph` secret (see [Credentials](#credentials)) and drop the `LIMIT 0`.

All the Query Farm Azure workers use the catalog name `azure`. To attach more than one in the same session, give each its own alias (for example `ATTACH 'azure' AS azure_risk (...)`) and qualify queries with that alias instead of `azure`.

Prebuilt binaries cover macOS (Apple silicon), Linux (x86-64 and arm64). `github-auto://` needs an explicit release tag; change `@v0.4.0` to move to a newer release.

### Other ways to run it

- **Docker** (the image bundles the worker; needs a container runtime):

  ```sql
  ATTACH 'azure' AS azure (TYPE vgi, LOCATION 'docker://ghcr.io/query-farm/vgi-azure-risk:0.4.0');
  ```

- **Manual download.** Download the archive for your platform from the [releases page](https://github.com/Query-farm/vgi-azure-risk/releases), verify it against its `.sha256` file (a cosign `.cosign.bundle` is published alongside), unpack it, and set `LOCATION` to the path of the extracted worker executable.

### Build from source

To build and test the worker yourself, see [Development](#development).

## Credentials

Live queries authenticate with an `azure_graph` secret holding app-only Microsoft Entra client credentials for a service principal: `TENANT_ID`, `CLIENT_ID` and `CLIENT_SECRET` (the client secret is redacted when secrets are listed). The worker registers the `azure_graph` secret type when it is attached, so create the secret after the `ATTACH`:

```sql
ATTACH 'azure' AS azure (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-azure-risk@v0.4.0');
CREATE SECRET azure_sp (TYPE azure_graph, TENANT_ID '<tenant-guid>', CLIENT_ID '<app-guid>', CLIENT_SECRET '<secret>');
```

For this worker the service principal needs the Microsoft Graph application permissions `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` and `IdentityRiskyServicePrincipal.Read.All` (the service-principal scope is not covered by the user scope), and the tenant needs an Entra ID P2 license (Identity Protection returns 403 without it).

With the secret in place, the feeds combine in plain SQL. This triage list joins the current per-user verdict in `risky_users` to the detection events in `risk_detections`, giving every user who is currently at risk or confirmed compromised with their number of detections, the latest detection time and the distinct detection types:

```sql
SELECT u.user_principal_name, u.risk_level, u.risk_state,
       count(d.id) AS detections,
       max(d.detected_date_time) AS last_detected,
       list(DISTINCT d.risk_event_type ORDER BY d.risk_event_type) FILTER (WHERE d.id IS NOT NULL) AS event_types
FROM azure.main.risky_users() u
LEFT JOIN azure.main.risk_detections() d ON d.user_id = u.id AND d._row_kind IS NULL
WHERE u._row_kind IS NULL AND u.risk_state IN ('atRisk', 'confirmedCompromised')
GROUP BY u.user_principal_name, u.risk_level, u.risk_state
ORDER BY detections DESC, u.user_principal_name;
```

## Development

Requires [Bun](https://bun.sh). `bun install` also fetches the shared `@vgi-azure/graph-core` package from GitHub.

```bash
bun install && bun test
bun run typecheck
```

To attach a local checkout, point `LOCATION` at the launch wrapper:

```sql
ATTACH 'azure' AS azure (TYPE vgi, LOCATION '/path/to/vgi-azure-risk/bin/vgi-azure-risk-worker');
```

## License

MIT. See [LICENSE](LICENSE).

## Notebooks

[Explore the executed watermark notebook](notebooks/README.md): compare late-event capture and duplicate observations using two synthetic snapshots through the real risk function.
