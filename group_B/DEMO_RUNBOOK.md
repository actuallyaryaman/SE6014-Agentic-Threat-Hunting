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
