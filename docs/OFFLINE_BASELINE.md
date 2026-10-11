# Stage 1 offline baseline

Target: Windows x64, CPython 3.11. The locked environment covers the offline API
and tests, not the optional ML/capture/forensics stack in requirements.txt.
These versions reproduce this baseline; this is not a production security audit.

## Setup (PowerShell, from C:\Projects\domeMCA)

```powershell
py -3.11 -m venv .venv-offline
.\.venv-offline\Scripts\python -m pip install --require-hashes -r requirements-offline.lock
.\.venv-offline\Scripts\python -m pip check
.\.venv-offline\Scripts\python -B -m pytest -q
Set-Location frontend
npm ci
$env:NEXT_PUBLIC_API_URL = "http://127.0.0.1:8000"
$env:NEXT_PUBLIC_WS_URL = "ws://127.0.0.1:8000"
npm run build
```

The existing package-lock.json pins frontend dependencies. Installing dependencies
requires Internet access; the backend tests themselves do not require a server,
scanner, network access, model files, or a real device. pytest.ini explicitly
selects tests/offline and the preserved health regression tests. The older
tests/*.py scripts perform live actions and are NOT part of this offline suite.

## Local preview

From the project root:
```powershell
# One-time setup; does not display the generated key.
.\.venv-offline\Scripts\python scripts/setup_local_key.py
$env:OFFLINE_MODE = "true"
.\.venv-offline\Scripts\python -X utf8 -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

In another terminal, from frontend:
```powershell
npm run start -- --hostname 127.0.0.1
```

Use http://localhost:3000 and create a local preview account if needed.
The offline database defaults to avighna_offline.db, separate from the original
database. To use a dedicated temporary SQLite file, set
AVIGHNA_OFFLINE_DATABASE_URL=sqlite:///C:/absolute/path/preview.sqlite.
Offline mode ignores the live DATABASE_URL and does not load .env.
Only local SQLite storage is permitted.

No background workers, scanners, model loading/training, telemetry response,
shell endpoints, or firewall actions are started/imported by this app.
Effectful routes return HTTP 503 without executing the requested action.
Online mode currently refuses startup: an environment flag alone is not an
approved network scope or permission to enable the old action routes.

The existing dashboard is a preview, not evidence of live protection. UI polish,
mock-intelligence removal, API authorization, report truthfulness, and separation
of agent/network timestamps remain later stages. Never expose this preview to a
network or treat its empty inventory as an "all clear" result.

## Lock regeneration (same Python/platform)

```powershell
.\.venv-offline\Scripts\python -m pip install pip==24.0 pip-tools==7.4.1
.\.venv-offline\Scripts\python -m piptools compile --generate-hashes --resolver=backtracking --output-file=requirements-offline.lock requirements-offline.in
```

Review changes to the lock and rerun tests before adopting new versions.

## Verified baseline (11 October 2026, MSI / Windows / Python 3.11)

- Offline pytest suite: 22 passed, 7 dependency deprecation warnings; exit 0.
- Hash-locked install and pip check: passed; no broken requirements.
- Frontend npm run build: exit 0, all 17 pages generated. Browserslist data warning remains.
- git diff --check: exit 0; Git reported line-ending normalization warnings.
- Local API /health: offline mode; collection, enforcement and shell all disabled.
- Local frontend: HTTP 200 with offline-preview notice present.
- Windows startup needs Python -X utf8 because existing state.py prints emoji.

These checks do not validate live detectors, ML accuracy, containment, or report truthfulness.
At that checkpoint changes were local and uncommitted; Stage 2 was not yet implemented.
See MANUAL_VALIDATION.md for the subsequent Stage 2 behavior and pending manual gates.
Stage 0 source backup: C:\\Projects\\domeMCA-baseline-20261010-232703.
Stage 0 Git reference: safety/stage01-20261010-232703 (original HEAD).
