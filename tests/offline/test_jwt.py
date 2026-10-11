"""JWT regression tests use ephemeral keys, never the machine's local key."""
import ast
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]

def run_import(tmp_path, key=None, extra_code=""):
    env = dict(os.environ, OFFLINE_MODE="true",
               AVIGHNA_SECRET_FILE=str(tmp_path / "missing.env"),
               AVIGHNA_OFFLINE_DATABASE_URL="sqlite:///" + (tmp_path / "isolated.db").as_posix())
    env.pop("SECRET_KEY", None)
    if key is not None:
        env["SECRET_KEY"] = key
    return subprocess.run([sys.executable, "-X", "utf8", "-B", "-c",
                           "from backend.main import app\n" + extra_code],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=45)

@pytest.mark.parametrize("key", [None, "", "short", "<GENERATE_A_RANDOM_LOCAL_KEY>"])
def test_missing_or_invalid_key_refuses_startup_before_database(tmp_path, key):
    result = run_import(tmp_path, key)
    assert result.returncode != 0
    assert "SECRET_KEY is missing or unsafe" in result.stderr
    assert not (tmp_path / "isolated.db").exists()

def test_random_key_allows_startup_and_signing(tmp_path):
    result = run_import(tmp_path, secrets.token_urlsafe(48), """
from backend.auth import create_access_token, SECRET_KEY, ALGORITHM
from jose import jwt
token = create_access_token({"sub": "test-only"})
assert jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"] == "test-only"
""")
    assert result.returncode == 0, "Application startup or signing failed"

def test_local_secret_file_and_environment_precedence(tmp_path, monkeypatch):
    from backend.secret_config import load_secret_key
    file_key, env_key = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    path = tmp_path / "secret.env"
    path.write_text("SECRET_KEY=" + file_key, encoding="utf-8")
    monkeypatch.setenv("AVIGHNA_SECRET_FILE", str(path))
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert load_secret_key() == file_key
    monkeypatch.setenv("SECRET_KEY", env_key)
    assert load_secret_key() == env_key

def test_exposed_historical_key_tokens_rejected_after_rotation(tmp_path):
    # Read the exposed key only into child-process memory; never echo or persist it.
    result = run_import(tmp_path, secrets.token_urlsafe(48), """
import ast
import subprocess
from jose import jwt
from fastapi import HTTPException
from unittest.mock import MagicMock
from backend.auth import get_current_user
source = subprocess.check_output(
    ["git", "show", "73b1286e66a2ea6a8875dfc6fba7dec2cb5a03eb:backend/auth.py"], text=True)
assignment = next(n for n in ast.parse(source).body
                  if isinstance(n, ast.Assign) and any(
                      isinstance(t, ast.Name) and t.id == "SECRET_KEY" for t in n.targets))
retired = ast.literal_eval(assignment.value.args[1])
token = jwt.encode({"sub": "test-only"}, retired, algorithm="HS256")
db = MagicMock()
try:
    get_current_user(token=token, db=db)
except HTTPException as error:
    assert error.status_code == 401
else:
    raise AssertionError("Retired signing key accepted")
db.query.assert_not_called()
""")
    assert result.returncode == 0, "Historical-key rejection regression failed"

def test_no_literal_signing_key_fallback_in_auth_source():
    tree = ast.parse((ROOT / "backend/auth.py").read_text(encoding="utf-8"))
    assignment = next(n for n in tree.body if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "SECRET_KEY" for t in n.targets))
    assert isinstance(assignment.value, ast.Call)
    assert isinstance(assignment.value.func, ast.Name)
    assert assignment.value.func.id == "load_secret_key"
    assert not assignment.value.args
