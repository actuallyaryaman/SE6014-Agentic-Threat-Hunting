# C2 sample runs and how C3 uses them

`runs/` and `audit/` hold two complete runs written by C2's agent (`result.json` schema 0.2, PR #22, `run-samples-v0.2.zip`), copied here without changes. The earlier schema 0.1 runs are kept in `c2_runs_v01/` to show that older output still loads:

| Run | Hypothesis | C2 verdict |
|---|---|---|
| `share-ssh-bruteforce` | an external IP brute-forced SSH and logged in on 2026-10-01 | SUPPORTED, high (2 claims) |
| `share-lsass-lateral` | LSASS credential dumping on WS-01, then lateral movement | SUPPORTED, high (14 claims) |

The data is synthetic (documentation IP ranges 203.0.113.0/24 and 198.51.100.0/24). Do not edit these files.
The tests check that they stay byte-identical.

## What the tests do

We only have C2's run folders, not its Elasticsearch data. `../recorded_gateway.py` stands in for a log store that has
not changed. Re-run queries return what the audit log recorded, and cited events are rebuilt from the evidence
excerpts and the facts that C2's claims quote. This is enough to show that C3 reads the real file formats and catches
planted errors. It does not prove anything against a live Elasticsearch.

`../tamper.py` copies a run, changes one thing in `result.json` and states what C3 must conclude:

| Case | Run | Planted error | C3 must say |
|---|---|---|---|
| `inflated_count` | ssh | C-001 says 50 failed logins, data says 30 | C-001 contradicted: verdict Inconclusive |
| `wrong_user` | ssh | C-002 says the login was as `root`, event says `admin` | C-002 contradicted: Inconclusive |
| `fake_event_id` | ssh | C-002 cites an event that does not exist | C-002 unsupported: Inconclusive |
| `invented_host` | ssh | C-002 says the login was on WS-09; the event is from WS-02 (quoted facts untouched) | C-002 contradicted: Inconclusive |
| `invented_user` | ssh | C-002 says the login was as `svc_backup`; the event says `admin` (quoted facts untouched) | C-002 contradicted: Inconclusive |
| `invented_claim` | ssh | C-003 "copied /etc/shadow", no evidence | C-003 unsupported, rest verified |
| `forged_aggregate` | lsass | C-013 says 40 error responses (text and replay agree, 27 is true) | C-013 contradicted by replay |
| `unknown_ioc` | lsass | C-008 names an IP the threat-intel feed does not list | C-008 contradicted by replay |
| `invented_narrative` | lsass | C2's verdict reasons name 198.51.100.23 and FS-09, which are in no evidence | all claims verified; flag `narrative_unsupported_entity`, analyst review |
| `two_indicators_wrong` | lsass | 2 of 3 LSASS indicators quote wrong values | both contradicted, T1003.001 below min_support: Inconclusive |

Write the tampered copies to disk to inspect them:

```bash
python -m tests.group_C.c3.tamper --out group_C/experiments/c2_tampered_runs
python -m group_C.threat_hunting.evidence.cli from-run \
    --plan group_C/experiments/c2_tampered_runs/wrong_user/runs/share-ssh-bruteforce/plan.json \
    --result group_C/experiments/c2_tampered_runs/wrong_user/runs/share-ssh-bruteforce/result.json \
    --audit group_C/experiments/c2_tampered_runs/wrong_user/audit/share-ssh-bruteforce.jsonl --out /tmp/bundle.json
```

## What the untouched runs show

* All 16 claims (2 and 14) are verified and all queries replay identically (14 and 47 queries), so C3 agrees with C2's evidence.
* Both runs are confirmed with `high` confidence and the review outcome is `agrees`. Each has two independent verified
  steps and full coverage, as DESIGN §4.1 asks. With the optional `C3_MIN_LOG_SOURCES=2` rule they drop to `medium`,
  because each run has events from one log source only (`auth` for the first, `sysmon` for the second).
* Both runs now carry C2's own prompt-injection finding (a planted user-agent string). C3 shows it as the flag `c2_prompt_injection` and requires analyst review. No claim or verdict changes.
