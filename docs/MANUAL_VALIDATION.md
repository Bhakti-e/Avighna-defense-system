# Development validation — unreleased

Manual results: PENDING. Automated passes are not manual acceptance or release approval.
Do not enable the legacy scanner, telemetry pipeline, shell, or firewall modules.

## Fresh offline setup (Windows x64 / Python 3.11)

Use a fresh checkout of the proposed development commit, preserving Git history.
From its root, in PowerShell:

```powershell
py -3.11 -m venv .venv-offline
.\.venv-offline\Scripts\python -m pip install --require-hashes -r requirements-offline.lock
.\.venv-offline\Scripts\python scripts/setup_local_key.py
.\.venv-offline\Scripts\python -X utf8 -B -m pytest -q
$env:OFFLINE_MODE="true"
.\.venv-offline\Scripts\python -X utf8 -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

In another terminal:

```powershell
cd frontend
npm ci
$env:NEXT_PUBLIC_API_URL="http://127.0.0.1:8000"
$env:NEXT_PUBLIC_WS_URL="ws://127.0.0.1:8000"
npm run build
npm run start -- --hostname 127.0.0.1
```

Open http://localhost:3000 and create a preview account. Use only local test data.
A key rotation requires API restart and sign-in again. Never include keys or tokens in failure reports.

## Checklist

| # | Steps | Expected result / current limitation |
|---|---|---|
| 1 | Follow fresh setup; open http://127.0.0.1:8000/health. | API says offline; collection, enforcement and shell false. Manual run pending. |
| 2 | Open dashboard; inspect inventory and intelligence widgets. | Offline banner visible. Inventory comes from SQLite; demo intelligence still has only a global warning. Per-widget separation is incomplete (Stage 5). |
| 3 | Open http://127.0.0.1:8000/discovery/scan without approving any scope. | HTTP 503; no scan. Approved-scope configuration is not implemented; positive discovery test requires an explicitly authorized lab later. |
| 4 | Review tests/offline/test_visibility.py: repeated simulated discovery and traffic for a device with an old heartbeat. Run that test file locally. | Network timestamp advances; heartbeat/event timestamps do not. This is automated evidence only; end-to-end testing needs an authorized agent/device and enabled safe ingestion later. |
| 5 | Review loss/stale/offline/recovery test and API fields last_agent_heartbeat, agent_status. | Healthy <=60s, stale >60 through180s, offline >180s; missing/future heartbeat unknown. Dedicated dashboard states and real-device recovery validation remain pending. |
| 6 | Inspect SensorHealth alerts created by the isolated tests. | Stored evaluation timestamp, heartbeat, source, rule and limitations; no compromise verdict or automatic action. Live analyst UI review pending. |
| 7 | Open Reports; do not enable legacy generation to test it. | Generation stays blocked. Real-evidence/time-range PDF correctness is NOT implemented or manually validated (Stage 4). |
| 8 | POST /investigation/execute or /actions/quarantine locally without credentials, using only an empty JSON body. | HTTP 503 and no action. This tests disabling only; consistent 401/403 role authorization remains Stage 3 work. Do not send real commands/targets. |
| 9 | Do not attempt real containment. | Preview, approval, confirmation, failure and rollback are NOT implemented/validated. Requires an isolated lab or mock enforcement point in Stage 7. |
| 10 | Observe startup in Task Manager and review /health. | No scanner/capture/shell/firewall worker should start. Runtime guards are covered by offline tests; independent manual observation is pending. |

Report each item as PASS / FAIL / BLOCKED / NOT RUN. Include:
commit hash (git rev-parse HEAD), item number, setup/command, expected result,
actual result, time, and a redacted screenshot or relevant error.
Do not report blocked/planned items as passed.

## Stage 2 semantics and limitations

The three observation timestamps are independent; existing last_seen is retained only
for legacy compatibility. Migration leaves ambiguous old timestamps unknown.
Migration is additive and tested for SQLite only. Stop the API and back up the local
database before running a changed schema; restore that backup with the earlier code
to roll back. Never commit the database or backup.

Loss/recovery events reuse the alerts table with a unique episode key. Loss does not
change threat risk, prove tampering, or trigger containment. Network status means
recently observed / not recently observed / unknown, not proof of reachability failure.
Reconciliation occurs on inventory reads and heartbeat updates, not an autonomous
monitor. Concurrent multi-worker operation and real-agent ingestion remain unverified.
The legacy ingestion route remains disabled; the changed helper is tested in isolation.

## Push and release gates

Work stays on a development branch. Before each commit review staged paths, diff,
secret checks and tests. Show exact remote, branch, commits and files and obtain
explicit push approval. Never force-push or rewrite history.
No tags, GitHub Releases, binaries, packages, public deployments or announcements.
After the user's manual results, prepare a candidate summary with tested hash,
automated/manual results, limitations, platforms, dependency/security checks and
proposed notes/assets. Each release action needs separate explicit approval.
