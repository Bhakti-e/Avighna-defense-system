"""Collector tests use fake adapter/Nmap data and temporary SQLite only."""
from datetime import datetime, timedelta
from unittest.mock import Mock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.network_scanner import (
    NetworkScanner, validate_scope, validate_attachment, parse_hosts,
    parse_windows_snapshot, record_observations, nmap_hosts,
)

SCOPE = "192.168.50.0/24"
SNAPSHOT = {"profile": "AuthorizedLab", "interface": "Wi-Fi", "ip": "192.168.50.20",
            "prefix": 24, "gateway": "192.168.50.1", "mac": "02:11:22:33:44:20", "hostname": "LabCollector"}
ROW = {"ip": "192.168.50.10", "mac": "02:11:22:33:44:10", "hostname": None, "vendor": None}


@pytest.fixture
def db(tmp_path):
    from backend.database import Base
    from backend import models
    engine = create_engine("sqlite:///" + (tmp_path / "discovery.sqlite").as_posix())
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as session:
        yield session
    engine.dispose()


@pytest.mark.parametrize("scope", ["0.0.0.0/0", "8.8.8.0/24", "127.0.0.0/24",
                                  "192.168.0.0/16", "192.168.50.1/24",
                                  "192.168.50.0/24;whoami", "::1/128", "169.254.1.0/24"])
def test_invalid_scope_rejected(scope):
    with pytest.raises(ValueError):
        validate_scope(scope)


@pytest.mark.parametrize("change", [
    {"profile": "DifferentNetwork"}, {"gateway": "192.168.50.2"},
    {"ip": "192.168.60.20"}, {"prefix": 16}, {"interface": "Ethernet"}, {"mac": None},
])
def test_attachment_mismatch_rejected(change):
    with pytest.raises(ValueError):
        validate_attachment({**SNAPSHOT, **change}, SCOPE, "AuthorizedLab", "192.168.50.1")


def test_windows_adapter_parsing_excludes_other_interfaces():
    config = """Ethernet adapter Ethernet 2:
   IPv4 Address. . . . . : 192.168.56.1
Wireless LAN adapter Wi-Fi:
   IPv4 Address. . . . . : 192.168.50.20
   Subnet Mask . . . . . : 255.255.255.0
   Default Gateway . . . : fe80::1%20
                          192.168.50.1
Ethernet adapter Bluetooth:
   Media State . . . . : Media disconnected
"""
    snapshot = parse_windows_snapshot("AuthorizedLab", config,
        '"Wi-Fi","Adapter","02-11-22-33-44-20","transport"\n', "LabCollector")
    assert snapshot == SNAPSHOT


def xml(ip="192.168.50.10", exit="success"):
    return f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><address addr="02:11:22:33:44:10" addrtype="mac"/></host><runstats><finished exit="{exit}"/></runstats></nmaprun>'


def test_parser_preserves_unknown_name():
    assert parse_hosts(xml(), SCOPE) == [ROW]


@pytest.mark.parametrize("output", [xml("8.8.8.8"), xml(exit="error"), "<nmaprun/>", "<bad"])
def test_untrusted_or_failed_scan_rejected(output):
    with pytest.raises(Exception):
        parse_hosts(output, SCOPE)


def test_nmap_command_is_host_discovery_only(monkeypatch):
    run = Mock(return_value=Mock(stdout=xml()))
    monkeypatch.setattr("backend.network_scanner.shutil.which", lambda name: "nmap.exe")
    monkeypatch.setattr("backend.network_scanner.subprocess.run", run)
    assert nmap_hosts(SCOPE) == [ROW]
    args, kwargs = run.call_args
    assert args[0] == ["nmap.exe", "-sn", "-PR", "--max-retries", "1",
                       "--host-timeout", "15s", "-oX", "-", SCOPE]
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 90


def test_store_deduplicates_without_touching_agent_or_risk(db):
    from backend.models import Device
    old = datetime.utcnow() - timedelta(hours=1)
    device = Device(device_id="existing-agent", mac_address=ROW["mac"],
                    last_agent_heartbeat=old, last_endpoint_event=old,
                    risk_score=75, risk_level="RED", status="UNDER_OBSERVATION")
    db.add(device)
    db.commit()
    for _ in range(2):
        record_observations(db, [ROW], SCOPE, datetime.utcnow())
        db.commit()
    assert db.query(Device).count() == 1
    assert device.last_network_seen > old
    assert device.last_agent_heartbeat == device.last_endpoint_event == old
    assert (device.risk_score, device.risk_level, device.status) == (75, "RED", "UNDER_OBSERVATION")


def test_new_device_and_reused_ip_do_not_get_security_verdict(db):
    from backend.models import Device
    record_observations(db, [ROW], SCOPE, datetime.utcnow())
    record_observations(db, [{**ROW, "mac": "02:11:22:33:44:11"}], SCOPE, datetime.utcnow())
    db.commit()
    assert db.query(Device).count() == 2
    for device in db.query(Device):
        assert device.risk_score is None
        assert device.risk_level == "UNKNOWN"
        assert device.last_agent_heartbeat is None
        assert device.last_endpoint_event is None


def scanner(discover=None, snapshot=None):
    return NetworkScanner(SCOPE, "AuthorizedLab", "192.168.50.1",
                          snapshot=snapshot or (lambda: dict(SNAPSHOT)),
                          discover=discover or (lambda _: [dict(ROW)]))


def test_success_audited_and_local_laptop_included(db):
    from backend.models import Device, DiscoveryRun
    from backend.routers.discovery import collection_status
    worker = scanner()
    worker.start_session(db)
    assert worker.scan_once(db)
    assert db.query(Device).count() == 2
    audit = db.query(DiscoveryRun).one()
    assert audit.status == "success" and audit.observed_count == 2
    assert len(audit.observations) == 2
    assert collection_status(db)["active"]
    worker.finish(db)
    assert not collection_status(db)["active"]


def test_failure_is_not_empty_success_and_stops(db):
    from backend.models import Device, DiscoveryRun
    from backend.routers.discovery import collection_status
    worker = scanner(discover=Mock(side_effect=RuntimeError("fixture failure")))
    worker.start_session(db)
    with pytest.raises(RuntimeError):
        worker.scan_once(db)
    assert db.query(Device).count() == 0
    assert db.query(DiscoveryRun).one().status == "error"
    assert collection_status(db)["state"] == "error"
    assert not collection_status(db)["active"]


def test_network_change_during_scan_discards_results(db):
    from backend.models import Device
    snapshots = iter([SNAPSHOT, SNAPSHOT, {**SNAPSHOT, "profile": "Other"}])
    worker = scanner(snapshot=lambda: next(snapshots))
    worker.start_session(db)
    with pytest.raises(ValueError):
        worker.scan_once(db)
    assert db.query(Device).count() == 0


def test_expired_session_never_reports_live(db):
    from backend.models import DiscoverySession
    from backend.routers.discovery import collection_status
    worker = scanner()
    worker.start_session(db)
    db.get(DiscoverySession, 1).lease_expires = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    result = collection_status(db)
    assert not result["active"] and result["state"] == "stale"


def test_stop_and_duplicate_session_prevent_scan(db):
    from backend.models import DiscoverySession
    discover = Mock(return_value=[ROW])
    worker = scanner(discover=discover)
    worker.start_session(db)
    with pytest.raises(ValueError):
        scanner().start_session(db)
    db.get(DiscoverySession, 1).stop_requested = True
    db.commit()
    assert not worker.scan_once(db)
    discover.assert_not_called()
