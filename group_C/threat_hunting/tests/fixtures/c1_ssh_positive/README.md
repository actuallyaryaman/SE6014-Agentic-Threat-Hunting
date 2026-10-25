# C1 positive SSH hunt fixture

This separate ECS-normalized fixture contains 25 failed SSH logins, followed by
one successful login. It preserves the existing 20-failure policy and does not
use or modify `security-events-c1test` or `hunt-20261025-064437`.

| Property | Value |
|---|---|
| Dedicated index | `security-events-c1-ssh-positive-v1` |
| Dataset / action | `linux.auth` / `ssh_login` |
| Source | `203.0.113.51` (documentation address) |
| Target host / IP | `C1-SSH-POSITIVE` / `10.77.0.10:22` |
| User | `admin` |
| Failures | 2026-10-02 06:00 through 06:24 UTC, one per minute |
| Success | 2026-10-02 06:25 UTC |
| Document and ECS event IDs | `c1-ssh-positive-01` through `c1-ssh-positive-26` |

`events.ndjson` is the fixed fixture; `index.json` supplies explicit mappings.
The runner creates only the dedicated index and uses bulk **create** operations.
It refuses ingestion if the index exists, disables inherited ingest pipelines
for these already normalized events, and never deletes indices. If ingestion
partially fails, it leaves the dedicated index for diagnosis. Do not rerun
ingestion to overwrite it; inspect it first.

Queries from this runner use the exact dedicated index. Other hunts using the
broad `security-events-*` pattern will discover this index too; use exact index
scopes for isolated tests. Nothing changes the old six-event index or report.

## Local PowerShell commands

Run from the repository root. These commands target only the isolated local
Elasticsearch 8.19.23 endpoint. Docker commands are not required.

```powershell
Set-Location .\group_C\threat_hunting
$env:ES_URL = 'http://127.0.0.1:9200'
$env:ES_CA_CERT = ''
# ES_API_KEY must already be set in this PowerShell session. Do not print it.
if (-not $env:ES_API_KEY) { throw 'Set the local read-only ES_API_KEY first.' }

.\.venv\Scripts\python.exe -m dev.validate_c1_ssh_positive check-fixture
if ($LASTEXITCODE -ne 0) { throw 'Fixture validation failed.' }

# Prompt securely for the isolated local container administrator credentials.
$cred = Get-Credential -UserName elastic -Message 'Isolated local Elasticsearch test-data creation'
if ($null -eq $cred) { throw 'Credential entry cancelled.' }
$previousAdminUser = $env:ES_ADMIN_USER
$previousAdminPassword = $env:ES_ADMIN_PASSWORD
$previousWriteKey = $env:ES_WRITE_API_KEY
try {
    # Only the short-lived ingestion subprocess receives these credentials.
    Remove-Item Env:ES_WRITE_API_KEY -ErrorAction SilentlyContinue
    $env:ES_ADMIN_USER = $cred.UserName
    $env:ES_ADMIN_PASSWORD = $cred.GetNetworkCredential().Password
    .\.venv\Scripts\python.exe -m dev.validate_c1_ssh_positive ingest
    if ($LASTEXITCODE -ne 0) { throw 'Ingestion stopped; inspect the dedicated index before retrying.' }
} finally {
    $env:ES_ADMIN_USER = $previousAdminUser
    $env:ES_ADMIN_PASSWORD = $previousAdminPassword
    $env:ES_WRITE_API_KEY = $previousWriteKey
    $cred = $null
}

# Verification and the hunt use the read-only ES_API_KEY, not admin credentials.
.\.venv\Scripts\python.exe -m dev.validate_c1_ssh_positive verify
if ($LASTEXITCODE -ne 0) { throw 'Read-only index verification failed.' }
.\.venv\Scripts\python.exe -m dev.validate_c1_ssh_positive hunt
if ($LASTEXITCODE -ne 0) { throw 'Hunt/evidence verification failed; inspect the printed run paths.' }
```

The read-only API key needs `read` and `view_index_metadata` on this dedicated
index, or an existing `security-events-*` grant. A key limited to
`security-events-c1test` cannot query the new index. Provision the correct local
key separately; this runner does not create or change credentials.

## Checks and expected results

`verify` checks all 26 document IDs and full `_source` objects against the
fixture, confirms 25 failures and one success, and verifies IP/date mappings.
`hunt` repeats those checks, scopes C2 to the exact index, chooses the dedicated
`es_mcp_server.server`, and forces the existing deterministic rules planner.
All 25 failures precede the success; the normal first-failure and subsequent
success searches should therefore execute without changing detection policy.

It expects `SUPPORTED` findings for T1110 and T1078, but treats any unexpected
verdict as a verification failure and retains the original saved result. It
does not rewrite verdicts. For each claim it checks evidence handles against
the server audit, replays aggregate claims through MCP, and retrieves the cited
documents through `get_event`. It expects all 26 fixture IDs to be cited and
retrievable, including the successful login. The old negative report is hashed
before/after each command when present.

Outputs have fresh UTC run IDs under `runs/c1-ssh-positive-<timestamp>/`:

- `plan.json`, `result.json`, `trace.jsonl`: unmodified C2 outputs.
- `c1-verification.json`: written only after all evidence checks pass.
- Server audits are under `audit/<run_id>.jsonl`; independent MCP checks
  have their own `<run_id>-verification` trace and audit.

No live success is claimed until these commands pass on your machine. Runtime
errors print only an exception class to avoid exposing credentials. Check local
connectivity/key privileges if verification fails before a run is created;
otherwise inspect the saved report, per-step status and audit results. A
`NOT_SUPPORTED` or incomplete result must be diagnosed, not forced positive.
