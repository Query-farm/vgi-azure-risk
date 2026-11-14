/** A fixed synthetic snapshot injected into the existing risk-function factory. */
import { createRequire } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { pinnedCheckout } from "./pinned_checkout.ts";

const [repository, revision, snapshot] = process.argv.slice(2);
if (
  repository !== "Query-farm/vgi-azure-risk" ||
  !revision ||
  !["initial", "later"].includes(snapshot ?? "")
) {
  throw new Error(
    "Usage: bun run fixture_worker.ts Query-farm/vgi-azure-risk FULL_SHA initial|later",
  );
}
const checkout = await pinnedCheckout(repository, revision);
const source = (path: string) =>
  import(pathToFileURL(join(checkout, path)).href);
const require = createRequire(join(checkout, "package.json"));
const { Worker, FunctionRegistry, ReadOnlyCatalogInterface } = await import(
  pathToFileURL(require.resolve("@query-farm/vgi")).href
);
const { makeRiskFunction } = await source("src/functions.ts");
const { RISK_DETECTIONS } = await source("src/schema.ts");
const { makeCatalog } = await source("src/catalog.ts");
const { FakeRisk } = await source("test/fake-risk.ts");

const graph = new FakeRisk("riskDetections", "detectedDateTime", 2);
const detection = (id: string, minute: number) => ({
  id,
  detectedDateTime: `2026-06-01T12:${String(minute).padStart(2, "0")}:00.000Z`,
  riskLevel: "medium",
  riskState: "atRisk",
  riskEventType: "unfamiliarFeatures",
  userId: `synthetic-${id}`,
  userPrincipalName: `${id}@example.invalid`,
  ipAddress: "203.0.113.7",
});
graph.upsert(detection("event-a", 0));
graph.upsert(detection("event-b", 4));
graph.upsert(detection("event-c", 8));
if (snapshot === "later") {
  graph.upsert(detection("late-event", 3));
  graph.upsert(detection("new-event", 12));
}
const clock = Date.parse(
  snapshot === "initial" ? "2026-06-01T12:20:00Z" : "2026-06-01T12:30:00Z",
);
const fetchJson = async (address: string) => {
  const url = new URL(address);
  if (
    url.origin !== "https://graph.microsoft.com" ||
    url.pathname !== "/v1.0/identityProtection/riskDetections"
  ) {
    throw new Error("The synthetic fixture supports only riskDetections.");
  }
  return graph.fetch(address);
};
const functions = [
  makeRiskFunction(
    RISK_DETECTIONS,
    () => ({ fetchJson }),
    () => clock,
  ),
];
const registry = new FunctionRegistry();
for (const fn of functions) registry.register(fn);
const catalogInterface = new ReadOnlyCatalogInterface(
  makeCatalog(functions),
  registry,
);
await new Worker({ functions, catalogInterface }).run();
