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
