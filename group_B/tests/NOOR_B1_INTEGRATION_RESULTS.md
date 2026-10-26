# Noor B1 integration verification — 2026-10-26

PR #29 was updated with main `7b57f61`, then Noor's PR #30 head `fbe387f`
was merged preserving her original commits. The three overlapping files were
reconciled: both syslog pipelines and the B1 test file.

B1 keeps its legacy current-year/UTC fallback for callers without labels.
Supplied year labels override the year; optional timezone labels are applied
and output is normalized to UTC. Invalid supplied years fail parsing rather
than silently falling back. ISO timestamps retain their original meaning.
B3 still requires confirmed year/timezone during onboarding; `b3.raw.v1`
rejects missing labels in Elasticsearch. Replay timestamp/metadata checks remain.

Fresh checks:

- Group B plus C4: 302 passed, 23 opt-in live tests skipped, 11 subtests passed.
- Entire combined B1 suite against authenticated HTTPS Elasticsearch 8.19.23:
  24 tests passed, including Noor's four tests and the strict B3 timezone test.
- Real A3/A2/Elasticsearch/C1/pinned C2/C3/C4 rules integration: 31 checkpoints
  passed. 112 raw records and three legacy normalized documents; raw replay
  submissions zero. Year-2024 leap day and Singapore-to-UTC year boundary pass.
- C3 query replay: 66/66 identical. Rules C4: 24/24 matching fields.
- No live LLM calls were made. Dat's separate C2 agent-scope fix remains pending;
  the earlier failed DeepSeek attempts remain failed and are not superseded.

The complete summary and tested source hashes are in
[NOOR_B1_INTEGRATION_RESULTS.json](NOOR_B1_INTEGRATION_RESULTS.json).
It records the pre-commit merge worktree honestly; hashes pin the executed files.
Full synthetic evidence, executed wrapper and live B1 test log are retained in
ignored `group_B/agentic_ingestion/runtime/noor-integration-20261026/`.
All owned test services, data, credentials and certificates were removed.

Reproduce the rules command in [YEAR_POLICY_E2E_RESULTS.md](YEAR_POLICY_E2E_RESULTS.md)
against this branch. B1's complete live suite can also be run using
`ES_URL`, `ES_API_KEY` and `ES_CA_CERT` configured for your local ES:

```bash
python -m unittest discover -s group_B/B1/Tests -v
```

No credentials need to be exchanged. Noor's GitHub PR remains open; this local
history integration does not merge it into GitHub main.
