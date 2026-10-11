# Local authentication: development only

The historical hardcoded JWT signing key is exposed. It must never be reused.
The API now refuses startup without a valid SECRET_KEY, before initializing its database.
No default is provided. Use a cryptographically random key of at least 32 characters.

From the repository root, after installing the offline requirements:

```powershell
.\.venv-offline\Scripts\python scripts/setup_local_key.py
$env:OFFLINE_MODE = "true"
.\.venv-offline\Scripts\python -X utf8 -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

The setup script writes only to ignored .env.auth and never prints the key.
It refuses to overwrite an existing file unless --rotate is supplied.
The SECRET_KEY process environment variable takes precedence over that file.
AVIGHNA_SECRET_FILE can select a different private file; ensure it is ignored.
The general .env file is not loaded by offline mode. .env.example has placeholders only.

## Rotation and session invalidation

Stop every API process using the old key, then run:

```powershell
.\.venv-offline\Scripts\python scripts/setup_local_key.py --rotate
```

Remove any stale SECRET_KEY process/service override, or update it privately.
Restart every affected API instance with the replacement key. Tokens signed with
the old key then fail signature verification; users must log out and sign in again.
The current frontend checks token presence before validation, so a stale login screen
state may require logout or clearing this site's local storage manually.

Rotation on this laptop does not rotate unknown deployments or other machines.
An operator must rotate every other instance that used the exposed key and restart it.
Do not paste keys into chat, commands stored in history, logs, tests, or tracked files.
Do not rewrite Git history without explicit approval.
