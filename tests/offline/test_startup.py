"""Offline application integration checks; external IO fails immediately."""
import secrets
import importlib
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def application(tmp_path_factory):
    # Windows platform detection invokes `ver`; cache it before the IO guard.
    import platform
    platform.uname()
    root = tmp_path_factory.mktemp("avighna-offline")
    database_file = root / "test.sqlite"
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected network/process operation in offline mode")
    # A bad live DATABASE_URL must be ignored. All test storage is temporary.
    with patch.dict("os.environ", {
        "OFFLINE_MODE": "true",
        "SECRET_KEY": secrets.token_urlsafe(48),
        "AVIGHNA_OFFLINE_DATABASE_URL": "sqlite:///" + database_file.as_posix(),
        "DATABASE_URL": "postgresql://invalid:invalid@forbidden.invalid/unused",
    }), patch.object(subprocess, "Popen", forbidden), \
         patch.object(subprocess, "run", forbidden), \
         patch.object(socket, "create_connection", forbidden), \
         patch.object(socket, "gethostbyname", forbidden), \
         patch.object(httpx.HTTPTransport, "handle_request", forbidden):
        from backend.main import app
        from backend.database import engine
        async def loopback_app(scope, receive, send):
            scope = dict(scope, client=("127.0.0.1", 12345))
            await app(scope, receive, send)
        with TestClient(loopback_app) as client:
            from backend.database import SessionLocal
            from backend.models import User
            from backend.auth import create_access_token
            with SessionLocal() as db:
                db.add(User(username="offline_admin", email="admin@example.com",
                            hashed_password="!login-disabled-test-fixture", role="admin", is_active=True))
                db.commit()
            client.headers["Authorization"] = "Bearer " + create_access_token({"sub": "offline_admin"})
            yield client, database_file
        engine.dispose()


def test_startup_uses_temporary_sqlite(application):
    client, db_path = application
    assert db_path.exists()
    assert db_path.parent.name.startswith("avighna-offline")
    assert client.get("/devices/").json() == []
    assert client.get("/alerts/").json() == {"count": 0, "alerts": []}


def test_health_explicitly_reports_offline(application):
    client, _ = application
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-AVIGHNA-Mode"] == "offline"
    data = response.json()
    assert data["mode"] == "offline"
    assert not any(data[key] for key in (
        "collection_enabled", "enforcement_enabled", "shell_enabled"
    ))


@pytest.mark.parametrize("method,path", [
    ("GET", "/discovery/scan"),
    ("POST", "/network/scan/now"),
    ("POST", "/manual-devices/register"),
    ("POST", "/telemetry/ingest"),
    ("POST", "/actions/quarantine"),
    ("POST", "/actions/unquarantine"),
    ("POST", "/actions/shutdown"),
    ("POST", "/investigation/execute"),
    ("POST", "/simulate/simulate"),
    ("POST", "/reports/generate"),
    ("GET", "/reports-db/pdf/isolation/test"),
])
def test_effectful_routes_disabled(application, method, path):
    client, _ = application
    response = client.request(method, path, json={"command": "ping 127.0.0.1"})
    assert response.status_code == 503
    assert "No action was attempted" in response.json()["detail"]


def test_no_sensor_or_model_modules_imported(application):
    forbidden = {
        "backend.background_tasks", "backend.router_discovery",
        "backend.scanning.scapy_monitor", "backend.core.ml_detection",
        "backend.core.forensics", "backend.utils.quarantine",
        "backend.routers.investigation", "backend.routers.telemetry_db",
    }
    assert not forbidden.intersection(sys.modules)


def test_inventory_reads_existing_database_without_discovery(application):
    client, _ = application
    from backend.database import SessionLocal
    from backend.models import Device
    with SessionLocal() as db:
        db.add(Device(device_id="offline-fixture", hostname="Test fixture",
                      ip_address="192.0.2.10", source="test", status="OFFLINE",
                      first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1)))
        db.commit()
    response = client.get("/devices/")
    assert response.status_code == 200
    assert response.json()[0]["device_id"] == "offline-fixture"
    assert response.json()[0]["source"] == "test"


def test_existing_auth_flow_against_temporary_database(application):
    client, _ = application
    response = client.post("/auth/signup", json={
        "username": "offline_tester", "email": "offline@example.com",
        "password": "Offline-test-only-92", "full_name": "Offline test",
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.get("/auth/me", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 200
    assert response.json()["username"] == "offline_tester"
    response = client.post("/auth/login", data={
        "username": "offline_tester", "password": "Offline-test-only-92",
    })
    assert response.status_code == 200


def test_non_loopback_client_is_rejected(application):
    from backend.main import app
    async def remote_client_app(scope, receive, send):
        await app(dict(scope, client=("192.0.2.20", 12345)), receive, send)
    with TestClient(remote_client_app) as client:
        response = client.get("/health")
    assert response.status_code == 403
    assert response.json()["detail"] == "Offline preview is local-only."


def test_read_routes_return_valid_shapes(application):
    client, _ = application
    assert isinstance(client.get("/reports/list").json()["reports"], list)
    assert "devices" in client.get("/stats/dashboard").json()


@pytest.mark.parametrize("path", [
    "/devices/", "/alerts/", "/stats/dashboard", "/stats/network-activity",
    "/stats/threat-trends", "/reports/list", "/reports/download/1",
    "/reports-db/incidents", "/reports-db/isolation/details",
    "/reports-db/observation/details", "/auth/me", "/openapi.json", "/discovery/status",
])
def test_sensitive_routes_require_authentication(application, path):
    client, _ = application
    response = client.get(path, headers={"Authorization": ""})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"

def permission_token(role, active=True):
    from backend.database import SessionLocal
    from backend.models import User
    from backend.auth import create_access_token
    import uuid
    username = "permission_" + uuid.uuid4().hex[:12]
    with SessionLocal() as db:
        db.add(User(username=username, email=username + "@example.com",
                    hashed_password="!disabled-test-fixture", role=role, is_active=active))
        db.commit()
    return {"Authorization": "Bearer " + create_access_token({"sub": username, "role": "admin"})}

@pytest.mark.parametrize("role", ["user", "viewer", "analyst"])
def test_readers_cannot_invoke_disabled_actions(application, role):
    client, _ = application
    headers = permission_token(role)
    assert client.get("/devices/", headers=headers).status_code == 200
    assert client.post("/actions/quarantine", headers=headers, json={}).status_code == 403

@pytest.mark.parametrize("command", ["ping 127.0.0.1 & whoami", "nmap; whoami",
                                     "$(whoami)", "powershell", "ping | whoami"])
def test_console_never_executes_metacharacters_or_commands(application, command):
    client, _ = application
    assert client.post("/investigation/execute", json={"command": command}).status_code == 503
    assert client.post("/investigation/execute", json={"command": command},
                       headers={"Authorization": ""}).status_code == 401

@pytest.mark.parametrize("role,active", [("unknown-role", True), ("admin", False)])
def test_unknown_roles_and_disabled_accounts_rejected(application, role, active):
    client, _ = application
    assert client.get("/devices/", headers=permission_token(role, active)).status_code == 403

def test_expired_and_malformed_tokens_rejected(application):
    from backend.auth import create_access_token
    from datetime import timedelta
    client, _ = application
    token = create_access_token({"sub": "offline_admin"}, timedelta(seconds=-1))
    for bad in (token, "invalid-token"):
        assert client.get("/devices/", headers={"Authorization": "Bearer " + bad}).status_code == 401

def test_signup_cannot_assign_admin_role(application):
    client, _ = application
    response = client.post("/auth/signup", json={
        "username": "ordinary_signup", "email": "ordinary@example.com",
        "password": "Only-a-test-password-92", "role": "admin"})
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "user"

def test_investigation_module_contains_no_subprocess_or_shell_runner():
    import ast
    tree = ast.parse((Path(__file__).resolve().parents[2] /
                      "backend/routers/investigation.py").read_text(encoding="utf8"))
    forbidden = {"subprocess", "os", "platform"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not forbidden.intersection(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden


def test_health_reflects_collector_lease_without_starting_collection(application):
    from backend.database import SessionLocal
    from backend.models import DiscoverySession
    from datetime import timedelta
    client, _ = application
    with SessionLocal() as db:
        row = DiscoverySession(id=1, session_id="fixture", scope="192.168.50.0/24",
            profile="TestNetwork", status="running", interval_seconds=60,
            approved_at=datetime.utcnow(), lease_expires=datetime.utcnow() + timedelta(seconds=60),
            last_success=datetime.utcnow(), observed_count=2)
        db.add(row)
        db.commit()
        try:
            assert client.get("/health").json()["mode"] == "discovery"
            assert client.get("/discovery/status").json()["observed_count"] == 2
            row.lease_expires = datetime.utcnow() - timedelta(seconds=1)
            db.commit()
            assert client.get("/health").json()["mode"] == "offline"
            assert client.get("/discovery/status").json()["state"] == "stale"
        finally:
            db.delete(row)
            db.commit()

LOCAL_HEADERS = {"Authorization": "", "Origin": "http://localhost:3000",
                 "Host": "127.0.0.1:8000", "X-AVIGHNA-Local-View": "1"}

@pytest.mark.parametrize("path", ["/devices/", "/alerts/", "/discovery/status", "/stats/dashboard"])
def test_local_dashboard_reads_without_account(application, path):
    client, _ = application
    assert client.get(path, headers=LOCAL_HEADERS).status_code == 200

@pytest.mark.parametrize("change", [
    {"Origin": "https://foreign.example"}, {"Origin": ""},
    {"Host": "foreign.example:8000"}, {"X-AVIGHNA-Local-View": ""},
])
def test_local_view_rejects_foreign_site_or_rebinding(application, change):
    client, _ = application
    assert client.get("/devices/", headers={**LOCAL_HEADERS, **change}).status_code == 401

@pytest.mark.parametrize("path", ["/actions/quarantine", "/investigation/execute", "/network/scan/now"])
def test_local_view_does_not_authorize_actions(application, path):
    client, _ = application
    assert client.post(path, headers=LOCAL_HEADERS, json={}).status_code == 401

def test_local_view_does_not_expose_account(application):
    client, _ = application
    assert client.get("/auth/me", headers=LOCAL_HEADERS).status_code == 401

def test_remote_client_cannot_use_local_view(application):
    from backend.main import app
    async def remote(scope, receive, send):
        await app(dict(scope, client=("192.0.2.20", 12345)), receive, send)
    with TestClient(remote) as client:
        assert client.get("/devices/", headers=LOCAL_HEADERS).status_code == 403
