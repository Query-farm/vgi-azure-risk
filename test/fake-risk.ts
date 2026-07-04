// A stateful fake of Microsoft Graph's Identity-Protection collections — enough to
// prove the lagged-watermark cursor contract with NO network and NO SDK. It models
// exactly the levers this feed actually has (SPEC §2a): a `$filter=<timeField> ge
// <iso>` slice, `@odata.nextLink` paging, and — deliberately — NO `/delta`, NO
// `@removed` tombstone, and NO `@odata.deltaLink` on the final page (a watermark
// worker computes its own cursor, §2d). Both cursor sub-types are covered by
// parametrizing the collection path + time field: EVENT (riskDetections /
// detectedDateTime) and STATE (riskyUsers|riskyServicePrincipals /
// riskLastUpdatedDateTime, which mutate a row in place via `upsert`).
//
// Imports ONLY @vgi-azure/graph-core, so the archetype-proof test runs SDK-free.

import { type FetchJson } from "@vgi-azure/graph-core";

const GRAPH = "https://graph.microsoft.com/v1.0";

export interface FakeRiskObj {
  id: string;
  [k: string]: unknown;
}

function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64url");
}
function unb64(s: string): string {
  return Buffer.from(s, "base64url").toString("utf8");
}

export class FakeRisk {
  private objs: FakeRiskObj[] = [];
  /** Number of HTTP round-trips served — asserts nextLink is followed verbatim. */
  public fetches = 0;

  constructor(
    private readonly collection: string,
    private readonly timeField: string,
    private readonly pageSize: number = 100,
  ) {}

  /** Add or replace an object. STATE collections mutate a row in place (same id,
   *  bumped time field); EVENT collections append. There is deliberately NO remove:
   *  dismissal is a riskState field change, never a delete (SPEC §2c). */
  upsert(o: FakeRiskObj): void {
    const i = this.objs.findIndex((x) => x.id === o.id);
    if (i >= 0) this.objs[i] = { ...o };
    else this.objs.push({ ...o });
  }

  fetch: FetchJson = async (url) => {
    this.fetches++;
    const u = new URL(url);
    const filter = u.searchParams.get("$filter") ?? "";
    // Parse the "<timeField> ge <iso>" watermark filter (`ge`, not `gt` — SPEC §2b).
    const m = / ge (.+)$/.exec(filter);
    const wm = m ? m[1]! : "1970-01-01T00:00:00.000Z";
    const sk = u.searchParams.get("$skiptoken");
    const offset = sk ? Number(unb64(sk)) : 0;

    // `ge` boundary: re-include the boundary row so the lag overlap is free under
    // idempotent dedup-by-id. ISO-8601 UTC strings compare lexicographically in time.
    const matched = this.objs
      .filter((o) => String(o[this.timeField] ?? "") >= wm)
      .sort((a, b) => String(a[this.timeField]).localeCompare(String(b[this.timeField])));

    const slice = matched.slice(offset, offset + this.pageSize);
    const nextOffset = offset + this.pageSize;
    const filterParam = `$filter=${encodeURIComponent(filter || `${this.timeField} ge ${wm}`)}`;

    if (nextOffset < matched.length) {
      const skiptoken = b64(String(nextOffset));
      return {
        value: slice,
        // nextLink is opaque + followed VERBATIM; it carries the same filter forward.
        "@odata.nextLink": `${GRAPH}/identityProtection/${this.collection}?${filterParam}&$skiptoken=${skiptoken}`,
      };
    }
    // Final page: NO deltaLink. A watermark worker derives its own cursor (§2d).
    return { value: slice };
  };
}
