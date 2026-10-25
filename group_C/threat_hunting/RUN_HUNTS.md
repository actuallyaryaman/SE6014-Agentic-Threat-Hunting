# Running the four reference hunts (Group C)

These commands run C2's hunt through C1's MCP server against data that is already in Elasticsearch, then check each result independently with C3. They cover only Group C: the Elastic stack, ingestion and the team data are set up by the other groups.

**Assumed in place**
- Elasticsearch reachable over HTTPS, and its CA certificate file.
- A **read-only API key** with `read` and `view_index_metadata` on the hunt indices (INTERFACES.md §3.2).
- Group B's SSH demo data indexed: on 2026-10-25, 30 failed logins and then a successful one from `203.0.113.99` on host `DEMO-SSH`, plus benign events on `BENIGN-SSH` (`group_B/DEMO_RUNBOOK.md`).
- Python 3.11 or later, Git, and a checkout of this repository.

Run the blocks in order, in one terminal.

## 1. Settings
Change the values to your environment. `HUNT_INDEX` is the index pattern that holds the team data.
```bash
export REPO="$HOME/SE6014-Agentic-Threat-Hunting" ES_URL="https://localhost:9200" ES_CA_CERT="$HOME/se6014-certs/http_ca.crt" HUNT_INDEX="security-events-*"
```
Enter the read-only key without it showing on screen or in the shell history:
```bash
read -rsp "Read-only API key: " ES_API_KEY && export ES_API_KEY && echo
```

## 2. Configure the agent and check access
This writes `group_C/threat_hunting/.env` (owner-only, git-ignored). C1's server and C3 read it.
```bash
cd "$REPO/group_C/threat_hunting" && (umask 077 && printf 'ES_URL=%s\nES_API_KEY=%s\nES_CA_CERT=%s\nHUNT_INDEX=%s\nHUNT_INDEX_PREFIX=security-events-\n' "$ES_URL" "$ES_API_KEY" "$ES_CA_CERT" "$HUNT_INDEX" > .env)
```
This should print a document count:
```bash
curl -s --cacert "$ES_CA_CERT" -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/$HUNT_INDEX/_count" && echo
```

## 3. Python environment and offline tests
```bash
cd "$REPO/group_C/threat_hunting" && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt Jinja2==3.1.6
```
```bash
cd "$REPO/group_C/threat_hunting" && .venv/bin/python -m pytest -q -m "not es"
```

## 4. The four hunts (C2 agent through C1's MCP server)
Case 1, attack:
```bash
cd "$REPO/group_C/threat_hunting" && HUNT_ES_MCP_CMD="python -m es_mcp_server.server" HUNT_FORCE_RULES=1 .venv/bin/python -m threat_hunting.run "An external IP brute-forced SSH on DEMO-SSH and then logged in successfully on 2026-10-25." --run-id c-attack
```
Case 2, benign host:
```bash
cd "$REPO/group_C/threat_hunting" && HUNT_ES_MCP_CMD="python -m es_mcp_server.server" HUNT_FORCE_RULES=1 .venv/bin/python -m threat_hunting.run "An external IP brute-forced SSH on BENIGN-SSH and then logged in successfully on 2026-10-25." --run-id c-benign
```
Case 3, a host with no logs:
```bash
cd "$REPO/group_C/threat_hunting" && HUNT_ES_MCP_CMD="python -m es_mcp_server.server" HUNT_FORCE_RULES=1 .venv/bin/python -m threat_hunting.run "An external IP brute-forced SSH on NO-SUCH-HOST and then logged in successfully on 2026-10-25." --run-id c-missing-host
```
Case 4, a date with no data:
```bash
cd "$REPO/group_C/threat_hunting" && HUNT_ES_MCP_CMD="python -m es_mcp_server.server" HUNT_FORCE_RULES=1 .venv/bin/python -m threat_hunting.run "An external IP brute-forced SSH on DEMO-SSH and then logged in successfully on 2030-01-01." --run-id c-empty-window
```
Summary:
```bash
cd "$REPO/group_C/threat_hunting" && for r in attack benign missing-host empty-window; do .venv/bin/python -c "import json; d=json.load(open('runs/c-$r/result.json')); v=d['verdict']; print(f\"{'$r':13s} {v['label']:17s} {v['confidence']:6s} claims={len(d['claims'])} events={len({e for c in d['claims'] for e in c['event_ids']})} es={d['manifest']['mcp_servers']['es']}\")"; done
```

## 5. Independent check by C3
C3's code is in PR #23 until it is merged; this fetches it into a separate folder next to the checkout.
```bash
git -C "$REPO" fetch origin pull/23/head:refs/remotes/pr/23 && (test -d "$REPO/../se6014-c3" || git -C "$REPO" worktree add --detach "$REPO/../se6014-c3" pr/23)
```
```bash
cd "$REPO/../se6014-c3" && export C3_MCP_COMMAND="$REPO/group_C/threat_hunting/.venv/bin/python" C3_MCP_ARGS="-m es_mcp_server.server" C3_MCP_CWD="$REPO/group_C/threat_hunting" C3_MCP_ANALYTICS_COMMAND="$REPO/group_C/threat_hunting/.venv/bin/python" C3_MCP_ANALYTICS_ARGS="-m analytics_server.server" && for r in attack benign missing-host empty-window; do H="$REPO/group_C/threat_hunting"; mkdir -p "$H/runs/c-$r/c3" && "$C3_MCP_COMMAND" -m group_C.threat_hunting.evidence.cli from-run --plan "$H/runs/c-$r/plan.json" --result "$H/runs/c-$r/result.json" --audit "$H/audit/c-$r.jsonl" --out "$H/runs/c-$r/c3/bundle.json" >/dev/null && "$C3_MCP_COMMAND" -m group_C.threat_hunting.evidence.cli report --bundle "$H/runs/c-$r/c3/bundle.json" --verify mcp --out-dir "$H/runs/c-$r/c3" --formats json,md,html | grep "^Claims" | sed "s/^/$r: /" && grep -hE '^\| \*\*Verdict|C2.s draft verdict' "$H/runs/c-$r/c3"/*.md; done
```

## Expected results
Measured on 2026-10-25 on the team stack (Elastic 8.19.23 over HTTPS), with C3 at `5d8ced3`:

| Case | C2 verdict | Claims / cited events | C3 verdict | C3 review |
|---|---|---|---|---|
| 1. attack | `SUPPORTED`, high | 2 / 31 | Confirmed | agrees |
| 2. benign host | `NOT_SUPPORTED`, medium | 0 / 0 | Refuted | agrees |
| 3. host with no logs | `INCONCLUSIVE`, low | 0 / 0 | Inconclusive | agrees |
| 4. date with no data | `INSUFFICIENT_DATA`, low | 0 / 0 | Inconclusive | agrees |

Every query C3 replayed through C1's server returned identical results. Case 1 requires analyst review (every `SUPPORTED` verdict does).

## Outputs
- C2: `runs/c-<case>/result.json`, `plan.json` and `trace.jsonl` (INTERFACES.md §4.1).
- C1's audit logs: `audit/c-<case>.jsonl`, plus `audit/c-<case>-analytics.jsonl` from C2's analytics server.
- C3's reports (JSON, Markdown, HTML): `runs/c-<case>/c3/`.

All of these are under `group_C/threat_hunting` and git-ignored.

The `.env` written in step 2 takes precedence over the `.env.test` that `dev/setup_test_es.py` writes for C2's own end-to-end tests; remove one of them when you switch between the two.

**Caveat.** If `HUNT_INDEX` also holds data from other days, case 2 can come out `INCONCLUSIVE` instead of `NOT_SUPPORTED`, because the agent currently sets the hunt window from the newest event in the whole index. Point `HUNT_INDEX` at the demo data's index to avoid this until the window fix lands.
