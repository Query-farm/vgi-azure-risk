# Executable SQL examples

| Notebook | Question |
| --- | --- |
| [Recover late detections with a lagged watermark](01_late_events_and_watermarks.ipynb) | How does overlap affect late-event capture and duplicate observations? |

The example scans two explicitly synthetic snapshots through the actual pinned
VGI risk function, resumes from its returned watermark, deduplicates event IDs
and compares the result with a full reference scan. Two charts show the event-time
boundary and reconcile appended observations with unique stored events. A zero-lag
experiment exposes the late event that falls before the resumed cursor.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/getting-started/installation/),
[Bun](https://bun.sh/) and Git, then copy or download the complete `notebooks/`
folder. Bun 1.3.14 was used for the saved executions.

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

No worker source checkout, root environment, tenant or credentials are required.
Internet access is needed to install packages, fetch the pinned Git revision and
download the community VGI extension. Haybarn 2.0.0rc11 and notebook dependencies
are locked separately. The visible SQL uses two literal launchers:

```text
bun run fixture_worker.ts Query-farm/vgi-azure-risk 74be06875655bcc88680825b159abcf778ac192c initial
bun run fixture_worker.ts Query-farm/vgi-azure-risk 74be06875655bcc88680825b159abcf778ac192c later
```

The shared helper verifies the public commit and installs its frozen Bun lock,
using an install lock and a Bun-version-specific cache under
`~/.cache/vgi-notebook-workers` (or `XDG_CACHE_HOME`). Setup logs go to stderr;
stdout remains the Arrow protocol. To upgrade, change both visible Git pins and
rerun the default and experiment before replacing outputs.

## Synthetic source and limits

`fixture_worker.ts` uses the source's tested
`makeRiskFunction(spec, clientFactory, now)` injection interface. It imports the
original risk-detection function, schema/catalog and `test/fake-risk.ts`. The
worker performs pagination, watermark calculation, row conversion and VGI
transport. The helper supplies two invented snapshots, two-object pages and fixed
UTC clocks: 2026-06-01 12:20 for `initial`, and 12:30 for `later`.

Only `risk_detections` is exposed by the fixture harness. Graph-shaped URLs are
handled by the fake client and never fetched from Azure. Dummy secrets satisfy
the real function's interface; authentication and live tenant behavior are not
tested. All identifiers, `example.invalid` addresses and the documentation-range
IP address are synthetic. This workflow measures event capture; it does not infer
a user's current risk verdict. A bounded lag cannot capture arbitrarily old late
arrivals, and this small in-memory example is not a durable production sink.

For an interactive notebook editor, select `notebooks/.venv/bin/python`, or
register the environment:

```sh
uv run --frozen python -m ipykernel install --user --name vgi-azure-risk-notebooks --display-name "Python (risk notebooks)"
```

The runner uses a temporary kernel specification and the notebook folder as its
working directory. It saves the default only after every cell succeeds.

## Zero-lag experiment

```sh
uv run --frozen python execute.py --parameters '{"SAFETY_LAG_MINUTES": 0}' --output-dir validation/zero-lag
```

The default is 10 minutes, with accepted integer values from 0 to 20. The
experiment changes only the lag; both source snapshots and clocks stay fixed.
Compare the missed-event marker, repeated observations and reference gap. Reset
`SAFETY_LAG_MINUTES = 10` for the default. Overrides require a separate output
folder, and experiment copies include the helpers, launcher, assets, runner and
locked environment files. Charts and logs are ignored; successful outputs remain
embedded in the main notebook. See [STANDARD.md](STANDARD.md) for presentation
conventions.

## SQL credential isolation

The notebook creates Haybarn with a fresh temporary `secret_directory` and
`allow_persistent_secrets=False` before attaching workers. It fully drains and
checks an empty secret inventory, then creates only explicitly `TEMPORARY`
public fixture secrets and verifies their `persistent=false`, `storage=memory`
metadata. Cleanup removes the temporary directory after closing the connection.
Existing user SQL secrets are neither read, modified nor deleted.
