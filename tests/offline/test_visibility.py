"""Visibility regressions: temporary SQLite, simulated observations, no network."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

@pytest.fixture
def visibility_db(tmp_path):
    from backend.database import Base
    from backend import models
    engine = create_engine("sqlite:///" + (tmp_path / "visibility.sqlite").as_posix())
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        yield db, factory
    engine.dispose()

@pytest.mark.parametrize("age,status", [
    (0, "ACTIVE"), (60, "ACTIVE"), (61, "STALE"), (180, "STALE"),
    (181, "LOST"), (-1, "UNKNOWN"),
])
def test_heartbeat_boundaries(age, status):
    from backend.db_utils import compute_telemetry_health
    now = datetime(2026, 1, 1, 12)
    assert compute_telemetry_health(now - timedelta(seconds=age), now)[1] == status

def test_missing_heartbeat_is_unknown_even_with_network_presence(visibility_db):
    from backend.models import Device
    from backend.db_utils import compute_telemetry_health
    db, _ = visibility_db
    device = Device(device_id="network-only", last_network_seen=datetime.utcnow())
    db.add(device)
    db.commit()
    assert compute_telemetry_health(device.last_agent_heartbeat) == (None, "UNKNOWN")

def test_timezone_aware_heartbeat():
    from backend.db_utils import compute_telemetry_health
    now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    assert compute_telemetry_health(now, now) == (100.0, "ACTIVE")

def test_repeated_discovery_and_packets_cannot_refresh_agent(visibility_db):
    from backend.models import Device
    from backend.device_manager import DeviceManager
    from backend.db_utils import compute_telemetry_health
    db, factory = visibility_db
    old = datetime.utcnow() - timedelta(minutes=10)
    mac = "00:11:22:33:44:55"
    db.add(Device(device_id=mac, last_agent_heartbeat=old, last_endpoint_event=old))
    db.commit()
    manager = DeviceManager()
    manager.local_ip = "127.0.0.1"
    with patch("backend.device_manager.SessionLocal", factory), \
         patch.object(manager, "_lookup_vendor", return_value="Unknown"):
        for _ in range(3):
            assert manager.register_device("192.0.2.10", mac, source="nmap") is not None
            manager.update_device_from_traffic("192.0.2.10", mac)
    db.expire_all()
    device = db.query(Device).one()
    assert device.last_network_seen > old
    assert device.last_agent_heartbeat == old
    assert device.last_endpoint_event == old
    assert compute_telemetry_health(device.last_agent_heartbeat)[1] == "LOST"

def test_heartbeat_and_endpoint_event_have_separate_writers(visibility_db):
    from backend.models import Device
    from backend.db_utils import update_device_last_seen, create_telemetry_record
    db, _ = visibility_db
    db.add(Device(device_id="agent"))
    db.commit()
    update_device_last_seen(db, "agent")
    device = db.query(Device).one()
    heartbeat = device.last_agent_heartbeat
    assert heartbeat is not None
    assert device.last_endpoint_event is None
    assert device.last_network_seen is None
    create_telemetry_record(db, "agent", {"connections": 1})
    assert device.last_endpoint_event is not None
    assert device.last_agent_heartbeat == heartbeat
    assert device.last_network_seen is None

def test_legacy_sqlite_migration_preserves_data_and_unknown_heartbeat(tmp_path):
    from backend.visibility_migration import migrate_visibility_columns
    engine = create_engine("sqlite:///" + (tmp_path / "legacy.sqlite").as_posix())
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE devices (id INTEGER PRIMARY KEY, device_id TEXT, last_seen DATETIME)")
        conn.exec_driver_sql("INSERT INTO devices VALUES (1, 'legacy', '2026-01-01 00:00:00')")
    migrate_visibility_columns(engine)
    migrate_visibility_columns(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT * FROM devices")).mappings().one()
        assert row["device_id"] == "legacy"
        assert row["last_seen"] == "2026-01-01 00:00:00"
        assert row["last_agent_heartbeat"] is None
        assert row["last_network_seen"] is None
        assert row["last_endpoint_event"] is None
    engine.dispose()


def test_loss_offline_recovery_are_deduplicated_and_not_threat_verdicts(visibility_db):
    from backend.models import Device, Alert
    from backend.db_utils import evaluate_visibility, update_device_last_seen
    db, factory = visibility_db
    now = datetime.utcnow()
    db.add(Device(device_id="gap", last_agent_heartbeat=now - timedelta(seconds=61),
                  risk_score=75, risk_level="RED", status="UNDER_OBSERVATION"))
    db.commit()
    evaluate_visibility(db, now)
    evaluate_visibility(db, now + timedelta(seconds=130))
    evaluate_visibility(db, now + timedelta(seconds=140))
    assert db.query(Alert).count() == 1
    loss = db.query(Alert).one()
    assert loss.details_json["kind"] == "visibility_lost"
    assert loss.response_action == "NONE"
    assert loss.risk_level == "UNKNOWN"
    assert loss.details_json["last_agent_heartbeat"].endswith("Z")
    # A new session must preserve episode deduplication.
    with factory() as other:
        evaluate_visibility(other, now + timedelta(seconds=150))
        assert other.query(Alert).count() == 1
    db.expire_all()
    update_device_last_seen(db, "gap")
    update_device_last_seen(db, "gap")
    assert db.query(Alert).count() == 2
    assert {a.details_json["kind"] for a in db.query(Alert)} == {
        "visibility_lost", "visibility_recovered"}
    device = db.query(Device).one()
    assert (device.risk_score, device.risk_level, device.status) == (
        75, "RED", "UNDER_OBSERVATION")

def test_unknown_agent_has_no_invented_loss_event(visibility_db):
    from backend.models import Device, Alert
    from backend.db_utils import evaluate_visibility
    db, _ = visibility_db
    db.add(Device(device_id="unknown", last_network_seen=datetime.utcnow()))
    db.commit()
    evaluate_visibility(db)
    assert db.query(Alert).count() == 0

def test_inventory_api_exposes_independent_health_and_events(visibility_db):
    from backend.models import Device, Alert
    from backend.routers.devices_db import list_devices
    db, factory = visibility_db
    now = datetime.utcnow()
    db.add(Device(device_id="api-fixture", last_network_seen=now,
                  last_agent_heartbeat=now - timedelta(minutes=5)))
    db.commit()
    with patch("backend.device_manager.SessionLocal", factory):
        first = list_devices(include_offline=True, db=db)[0]
        list_devices(include_offline=True, db=db)
    assert first["agent_status"] == "OFFLINE"
    assert first["network_status"] == "RECENTLY_OBSERVED"
    assert first["telemetry_health_score"] == 0
    assert first["last_network_seen"] != first["last_agent_heartbeat"]
    assert db.query(Alert).count() == 1

def test_legacy_alert_migration_preserves_rows_and_adds_unique_event_key(tmp_path):
    from backend.visibility_migration import migrate_visibility_columns
    from sqlalchemy.exc import IntegrityError
    engine = create_engine("sqlite:///" + (tmp_path / "legacy-alert.sqlite").as_posix())
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE devices (id INTEGER PRIMARY KEY)")
        conn.exec_driver_sql("CREATE TABLE alerts (id INTEGER PRIMARY KEY, reason TEXT)")
        conn.exec_driver_sql("INSERT INTO alerts VALUES (1, 'original evidence')")
    migrate_visibility_columns(engine)
    migrate_visibility_columns(engine)
    with engine.begin() as conn:
        assert conn.execute(text("SELECT reason FROM alerts WHERE id=1")).scalar() == "original evidence"
        conn.exec_driver_sql("INSERT INTO alerts (id, visibility_event_key) VALUES (2, 'episode')")
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.exec_driver_sql("INSERT INTO alerts (id, visibility_event_key) VALUES (3, 'episode')")
    engine.dispose()
