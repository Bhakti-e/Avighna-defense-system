"""Explicitly approved Windows Wi-Fi discovery. No import/startup side effects.

Run locally with --approve-scope, --profile and --gateway. No firewall, packet
capture, port enumeration, threat verdicts or endpoint-heartbeat writes.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SNAPSHOT_COMMAND = "(Get-NetConnectionProfile -InterfaceAlias 'Wi-Fi' -ErrorAction Stop).Name | ConvertTo-Json -Compress"


def validate_scope(scope):
    net = ipaddress.ip_network(scope, strict=True)
    if net.version != 4 or not 24 <= net.prefixlen <= 30 or not any(net.subnet_of(p) for p in PRIVATE):
        raise ValueError("Approve one RFC1918 IPv4 subnet between /24 and /30.")
    return net


def normalize_mac(mac):
    value = (mac or "").upper().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", value):
        return None
    if value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        return None
    return value


def validate_attachment(snapshot, scope, profile, gateway):
    net = validate_scope(scope)
    if not profile or snapshot.get("interface") != "Wi-Fi" or snapshot.get("profile") != profile:
        raise ValueError("Approved Wi-Fi profile is not connected. Collection stopped.")
    address = ipaddress.ip_address(snapshot["ip"])
    attached = ipaddress.ip_network(str(address) + "/" + str(snapshot["prefix"]), strict=False)
    if attached != net or snapshot.get("gateway") != gateway or ipaddress.ip_address(gateway) not in net:
        raise ValueError("Wi-Fi subnet or gateway changed. Collection stopped.")
    if address not in net or not normalize_mac(snapshot.get("mac")):
        raise ValueError("Wi-Fi adapter identity could not be verified.")
    return snapshot


def parse_windows_snapshot(profile, config, mac_csv, hostname):
    import csv
    import io
    block = re.search(r"(?m)^[^\r\n]*adapter Wi-Fi:[ \t]*\r?\n([\s\S]*?)(?=^[^\s]|\Z)", config)
    if block is None:
        raise ValueError("Connected Wi-Fi adapter not found in Windows configuration.")
    text = block.group(1)
    ipv4 = re.search(r"IPv4 Address[^:\r\n]*:\s*([\d.]+)", text)
    mask = re.search(r"Subnet Mask[^:\r\n]*:\s*([\d.]+)", text)
    gateway = re.search(r"Default Gateway[\s\S]*?(\d+\.\d+\.\d+\.\d+)", text)
    if not all((ipv4, mask, gateway)) or not isinstance(profile, str):
        raise ValueError("Cannot verify Wi-Fi profile, IPv4 subnet and gateway.")
    rows = list(csv.reader(io.StringIO(mac_csv)))
    mac = next((row[2] for row in rows if len(row) >= 3 and row[0] == "Wi-Fi"), None)
    return {"profile": profile, "interface": "Wi-Fi", "ip": ipv4.group(1),
            "prefix": ipaddress.ip_network("0.0.0.0/" + mask.group(1)).prefixlen,
            "gateway": gateway.group(1), "mac": normalize_mac(mac), "hostname": hostname}


def windows_snapshot():
    if os.name != "nt":
        raise RuntimeError("This collector currently supports Windows Wi-Fi only.")
    def read(args, timeout):
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, check=True, shell=False).stdout
    profile = json.loads(read(["powershell.exe", "-NoProfile", "-NonInteractive",
                               "-Command", SNAPSHOT_COMMAND], 60))
    return parse_windows_snapshot(profile, read(["ipconfig"], 15),
                                  read(["getmac", "/v", "/fo", "csv"], 15), socket.gethostname())


def parse_hosts(xml_text, scope):
    net = validate_scope(scope)
    root = ET.fromstring(xml_text)
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Discovery did not complete successfully.")
    rows = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ipv4 = host.find("address[@addrtype='ipv4']")
        if ipv4 is None:
            continue
        ip = ipaddress.ip_address(ipv4.get("addr"))
        if ip not in net or ip in (net.network_address, net.broadcast_address):
            raise ValueError("Discovery returned an address outside the approved host range.")
        mac = host.find("address[@addrtype='mac']")
        hostname = host.find("hostnames/hostname")
        name = hostname.get("name") if hostname is not None else None
        rows[str(ip)] = {
            "ip": str(ip), "mac": normalize_mac(mac.get("addr")) if mac is not None else None,
            "hostname": name[:255] if name and name != str(ip) else None,
            "vendor": mac.get("vendor", "")[:255] or None if mac is not None else None,
        }
    return list(rows.values())


def nmap_hosts(scope):
    validate_scope(scope)
    executable = shutil.which("nmap")
    if not executable:
        executable = next((str(p) for p in (
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
            Path(r"C:\Program Files\Nmap\nmap.exe"),
        ) if p.is_file()), None)
    if not executable:
        raise RuntimeError("Nmap is not installed. No discovery was attempted.")
    result = subprocess.run(
        [executable, "-sn", "-PR", "--max-retries", "1", "--host-timeout", "15s", "-oX", "-", scope],
        capture_output=True, text=True, timeout=90, check=True, shell=False,
    )
    return parse_hosts(result.stdout, scope)


def record_observations(db, rows, scope, observed_at):
    """Update the existing Device inventory; never write endpoint clocks/risk."""
    from .models import Device
    for row in rows:
        mac = row["mac"]
        identity = "network:" + scope + ":" + (mac or "ip:" + row["ip"])
        device = db.query(Device).filter(Device.device_id == identity).first()
        if device is None and mac:
            # Reuse an existing endpoint identity only on an exact MAC match.
            matches = db.query(Device).filter(Device.mac_address == mac).all()
            device = matches[0] if len(matches) == 1 else None
        if device is None:
            device = Device(device_id=identity, first_seen=observed_at, last_seen=observed_at,
                            source="nmap", status="UNASSESSED", risk_level="UNKNOWN")
            db.add(device)
            db.flush()
            device.risk_score = None
        device.ip_address = row["ip"]
        device.mac_address = mac
        if row.get("hostname"):
            device.hostname = row["hostname"]
        if row.get("vendor"):
            device.vendor = row["vendor"]
        device.last_network_seen = observed_at


class NetworkScanner:
    def __init__(self, scope, profile, gateway, interval=60, snapshot=windows_snapshot, discover=nmap_hosts):
        self.scope = str(validate_scope(scope))
        if not profile or not gateway or not 60 <= interval <= 3600:
            raise ValueError("Profile, gateway and an interval of 60..3600 seconds are required.")
        self.profile, self.gateway, self.interval = profile, gateway, interval
        self.snapshot, self.discover = snapshot, discover
        self.session_id = uuid.uuid4().hex

    def attachment(self):
        return validate_attachment(self.snapshot(), self.scope, self.profile, self.gateway)

    def start_session(self, db):
        from sqlalchemy import text
        from .models import DiscoverySession
        self.attachment()  # Fail before any discovery or session activation.
        db.execute(text("BEGIN IMMEDIATE"))
        current = db.get(DiscoverySession, 1)
        now = datetime.utcnow()
        if current and current.lease_expires and current.lease_expires > now and not current.stop_requested:
            db.rollback()
            raise ValueError("A collector session is already active.")
        if current is None:
            current = DiscoverySession(id=1)
            db.add(current)
        current.session_id, current.scope, current.profile = self.session_id, self.scope, self.profile
        current.status, current.interval_seconds = "starting", self.interval
        current.approved_at, current.last_success = now, None
        current.lease_expires = now + timedelta(seconds=420 + self.interval)
        current.stop_requested, current.observed_count, current.error = False, 0, None
        db.commit()

    def scan_once(self, db):
        from .models import DiscoverySession, DiscoveryRun
        db.expire_all()
        session = db.get(DiscoverySession, 1)
        if not session or session.session_id != self.session_id or session.stop_requested:
            return False
        session.status = "scanning"
        session.lease_expires = datetime.utcnow() + timedelta(seconds=420 + self.interval)
        run = DiscoveryRun(session_id=self.session_id, scope=self.scope,
                           started_at=datetime.utcnow(), status="running")
        db.add(run)
        db.commit()
        try:
            before = self.attachment()
            rows = self.discover(self.scope)
            after = self.attachment()
            if before != after:
                raise ValueError("Network attachment changed during discovery; results discarded.")
            # Include the collector laptop using its adapter facts, not fabricated discovery data.
            rows = [r for r in rows if r["ip"] != after["ip"]]
            rows.append({"ip": after["ip"], "mac": normalize_mac(after["mac"]),
                         "hostname": after.get("hostname") or socket.gethostname(), "vendor": None})
            db.refresh(session)
            if session.stop_requested or session.session_id != self.session_id:
                run.status, run.finished_at = "cancelled", datetime.utcnow()
                db.commit()
                return False
            now = datetime.utcnow()
            record_observations(db, rows, self.scope, now)
            run.status, run.finished_at = "success", now
            run.observed_count, run.observations = len(rows), rows
            session.status, session.last_success = "running", now
            session.observed_count, session.error = len(rows), None
            session.lease_expires = now + timedelta(seconds=420 + self.interval)
            db.commit()
            return True
        except Exception as error:
            db.rollback()
            # Failed attempts remain auditable, never reported as a successful empty scan.
            session = db.get(DiscoverySession, 1)
            run = db.get(DiscoveryRun, run.id)
            message = str(error)[:500] if isinstance(error, ValueError) else type(error).__name__ + ": discovery failed; inspect local collector."
            run.status, run.finished_at, run.error = "error", datetime.utcnow(), message
            if session.session_id == self.session_id:
                session.status, session.error, session.lease_expires = "error", message, None
            db.commit()
            raise

    def finish(self, db):
        from .models import DiscoverySession
        db.expire_all()
        session = db.get(DiscoverySession, 1)
        if session and session.session_id == self.session_id:
            if session.status != "error":
                session.status = "stopped"
            session.lease_expires = None
            db.commit()


def main():
    parser = argparse.ArgumentParser(description="Explicitly approved local Wi-Fi host discovery; Ctrl+C stops.")
    parser.add_argument("--approve-scope")
    parser.add_argument("--profile")
    parser.add_argument("--gateway")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()
    if not args.stop and not all((args.approve_scope, args.profile, args.gateway)):
        parser.error("--approve-scope, --profile and --gateway explicitly authorize this session.")
    from .database import init_db, SessionLocal
    from .models import DiscoverySession
    init_db()
    with SessionLocal() as db:
        if args.stop:
            session = db.get(DiscoverySession, 1)
            if session:
                session.stop_requested, session.status, session.lease_expires = True, "stopping", None
                db.commit()
            print("Stop requested. An in-flight bounded scan may finish; its results will be discarded.", flush=True)
            return
        scanner = NetworkScanner(args.approve_scope, args.profile, args.gateway, args.interval)
        scanner.start_session(db)
        print("APPROVED host discovery: " + scanner.scope + "; every " + str(scanner.interval) +
              " seconds after completion. No enforcement. Ctrl+C or --stop ends collection.", flush=True)
        try:
            while scanner.scan_once(db):
                print("Discovery stored successfully at " + datetime.utcnow().isoformat() + "Z", flush=True)
                if args.once:
                    break
                for _ in range(scanner.interval):
                    time.sleep(1)
                    db.expire_all()
                    if db.get(DiscoverySession, 1).stop_requested:
                        return
        finally:
            scanner.finish(db)


if __name__ == "__main__":
    main()
