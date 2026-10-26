# Local onboarding and hunting demo

This demo can run without another member's server or credentials. It creates
its own authenticated HTTPS Elasticsearch and A2 HTTP service, ingests synthetic
SSH events through B3/B1, then runs C2 through its existing development MCP
servers. It never calls an LLM. C3 can be tested with the optional snapshot
flags below; final C1 and A3 are outside this demo.

## Prepare

Use Linux UID 1000, matching the pinned images, with Docker access, OpenSSL,
`uv`, Git and Group B's Python 3.11 environment. Run from the repository root.
At most two test containers run together, each capped at 1.5 GiB. Existing
containers, clusters and developer `.env` files are not reused.

```bash
docker pull docker.elastic.co/elasticsearch/elasticsearch:8.19.23
docker pull docker.elastic.co/logstash/logstash:8.19.23
git fetch origin feature/A2/pull-push-ingestion

demo_workspace=$(mktemp -d /tmp/smtd-demo.XXXXXX)
uv venv --python group_B/.venv/bin/python "$demo_workspace/hunt-venv"
uv pip install --python "$demo_workspace/hunt-venv/bin/python" \
  -r group_C/threat_hunting/requirements.txt
```

The separate C2 environment preserves both groups' dependency pins. C2's code
is read from the current committed Git tree into a temporary directory; source
edits must be committed before they are included in the demo.

## Run

```bash
group_B/.venv/bin/python group_B/scripts/check_onboarding_hunt_demo.py \
  --hunt-python "$demo_workspace/hunt-venv/bin/python" \
  --output-dir "$demo_workspace/evidence"
```

The evidence directory must be new; existing output is never overwritten.
The pinned A2 commit is `8b86c10eb5ee5248f087aa6c8273c8fadb82758c`.
The runner provisions temporary credentials/certificates, aligns A2/B3/C2 on
`security-events-c2test*`, uses C2's existing development mapping there, waits
for A2's actual container HTTP listener, and cleans up its own services.

## Presentation sequence

1. Explain that 35 raw SSH lines contain a planted 30-failure burst followed
   by a successful login, plus four benign events on another host.
2. Show the B3 `verified` result and zero new submissions on replay in
   `evidence/summary.json`. These events passed through actual A2 and B1.
3. Show `evidence/attack/result.json`: `SUPPORTED`, two claims, 31 unique cited
   attack events, both claims self-checked. The harness fetches every citation
   from Elasticsearch independently and compares the evidence set to ground truth.
4. Show `benign`, `missing-host`, and `empty-window` results: `NOT_SUPPORTED`,
   `INCONCLUSIVE`, and `INSUFFICIENT_DATA`. Missing data must not become support.
5. Show `attack/trace.jsonl` and `attack/mcp-audit.jsonl`: the actual MCP requests,
   query hashes and evidence trail. Explain that ES tools are read-only and the
   analytics server receives no ES credentials.
6. Show `attack-repeat`: identical request hashes, claims, evidence and verdict.

The output retains synthetic evidence after containers and credentials are
removed. These JSON files can be inspected locally or shared with the team.
Use [the recorded results](tests/ONBOARDING_HUNT_RESULTS.md) if Docker is not
available during the presentation, clearly labeling it as a recorded run.

## Troubleshooting

- Group B's configuration and A2's `A2_INDEX_PREFIX` must name the same index
  namespace. HTTP acknowledgement alone does not prove indexing.
- Monitoring API/host port readiness is insufficient; the harness checks the
  listener inside the container. Do not remove this gate to speed startup.
- A C2 import error usually means the wrong `--hunt-python` interpreter or
  missing pinned dependencies. Keep the virtual-environment path intact.
- A C1 replacement must implement C2's documented tool names/result shapes;
  the current development stand-in is not proof that the replacement works.
- Normal completion/failures clean up temporary resources. After a hard kill,
  inspect only resources labeled `smtd.b3.integration`; do not remove unrelated
  services or run shared `docker compose down -v`.

## Remaining team integration

Repeat on another team member's local environment without exchanging credentials;
replace the C1 development stand-in;
connect C3's verifier/report; agree on A3's envelope/source IDs and yearless
firewall policy. None of those agreements is implied by this local demo.

## Test the proposed C2/C3 contracts

The optional snapshot flags test unmerged Group C code without installing it
in this branch. Preserve the older recorded demo as historical evidence.

```bash
git fetch origin feature/c2-review-fixes
git fetch origin refs/pull/23/head
uv pip install --python "$demo_workspace/hunt-venv/bin/python" Jinja2==3.1.6
group_B/.venv/bin/python group_B/scripts/check_onboarding_hunt_demo.py \
  --hunt-python "$demo_workspace/hunt-venv/bin/python" \
  --c2-ref a8b4a58bb9febab48b57279b09865368859dc887 \
  --c3-ref e98599eb3b5309c4655124cc25265fe6a9d9f230 \
  --output-dir "$demo_workspace/c2-c3-evidence"
```

C2 comes entirely from the selected C2 tree; only C3's evidence package is
added from its selected commit. Each hunt is passed to C3 through its real
bundle/report CLI, using a separate MCP connection for verification and query
replay. The harness rejects offline fallback. Reports are JSON, Markdown and
HTML; PDF rendering and the final C1 server are outside this test.

See [the C2/C3 findings](tests/C2_C3_INTEGRATION_RESULTS.md) before presenting
the positive scenario: C3 currently rejects one correlation claim.


## Delivered C1 with updated C2/C3 and C4

Use these pinned snapshots for the 2026-10-26 unified test. This selects
`es_mcp_server.server` for both C2 and C3, requires the expected C3 verdicts
and complete identical query replay, then compares the two attack outputs
using C4. It uses synthetic SSH data in a dedicated local index and no LLM.
The C1 package is the delivered server plus the compatibility changes in #22.

```bash
git fetch origin refs/pull/22/head refs/pull/23/head refs/pull/25/head
group_B/.venv/bin/python group_B/scripts/check_onboarding_hunt_demo.py \
  --hunt-python "$demo_workspace/hunt-venv/bin/python" \
  --c2-ref 676c21b73c46e4a2632d0d855a922497cc0b9c15 \
  --c3-ref 5d8ced350259c3727d9c1bddabf292194518797e \
  --es-mcp-module es_mcp_server.server \
  --require-c3-agreement \
  --c4-ref ae8b316730fdabcbe90929b6869c1a8f8bf0eef4 \
  --output-dir "$demo_workspace/unified-evidence"
```

Use the separate C2 environment prepared above, including Jinja2 3.1.6.
The selected commits must exist locally; outputs never overwrite a previous
run. Older results above remain historical evidence of earlier snapshots.

[Unified recorded results](tests/UNIFIED_C1_C4_RESULTS.md) show the expected
C3 verdicts and complete query replay with these exact snapshots.

## Latest bounded A3 and DeepSeek chain

The newer path adds `--a3-stream` to run B3 raw envelopes through the actual
A3 UDP receiver before A2. Use the current C2 agent branch:

```bash
git fetch origin feature/c2-agentic-hunt refs/pull/23/head refs/pull/25/head
group_B/.venv/bin/python group_B/scripts/check_onboarding_hunt_demo.py \
  --hunt-python "$demo_workspace/hunt-venv/bin/python" \
  --c2-ref fd9995af15804a7e2fe33b13d90f39911ef6ee36 \
  --c3-ref 5d8ced350259c3727d9c1bddabf292194518797e \
  --es-mcp-module es_mcp_server.server --require-c3-agreement \
  --c4-ref ae8b316730fdabcbe90929b6869c1a8f8bf0eef4 \
  --a3-stream --output-dir "$demo_workspace/a3-rules-evidence"
```

For live agent checks, add `--llm-env /absolute/path/to/private-provider.env`
and use another new output directory. The file contains `LLM_PROVIDER`,
`LLM_BASE_URL`, `LLM_API_KEY` and `HUNT_MODEL`. DeepSeek was tested through its
OpenAI-compatible API using `deepseek-flash`. Provider credentials are passed
only to C2, never written to evidence or sent to C3's MCP processes.

The live variant runs attack, benign and repeated attack cases. It sets an
8-call LLM budget, two investigator steps and a 45-second provider timeout.
Every actual completed LLM call is retained in the synthetic run audit. C3
still re-verifies the resulting claims independently. C4 records differences
instead of failing just because the LLM chose a different query.

The rules variant also checks raw Apache (including a malformed request),
unknown JSON/CSV through B2, the original normalized A3 path with duplicate
replay, and rejection of unapproved raw pipelines. Existing A3 parsers and
sender scripts remain usable. See [the transport contract](B3_A3_CONTRACT.md).

## Current C4 compatibility

To use the expanded comparator, select
`--c4-ref 5e76ccf6262fc756a0b5c5fce3d11eb09fac97c4` after fetching
`feature/c4-repeatability`. Historical pins above remain reproducible.
The harness handles both APIs and records the actual number of checks.
Comparison completion does not imply all fields match: inspect `all_match`
and `differing_fields` in the summary. Add `--require-c4-match` when every
C4 field, including execution metadata, must match for the run to pass.
See [the compatibility results](tests/C4_COMPATIBILITY_RESULTS.md).


The corrected local C4 implementation is pinned at
`315cb6c784d32fdeabfa41546c285d329f556d3e`; use that value for `--c4-ref`
after fetching this integration branch. It handles valid zero-claim results
and excludes phase execution timings while preserving meaningful differences.
Both rules and live modes now enforce seeded scenario verdicts and exact
attack citations. See [the corrected recheck](tests/C4_CORRECTIONS_RESULTS.md).
