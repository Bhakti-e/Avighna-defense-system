# Approved local Wi-Fi discovery (prototype, unreleased)

This increment replaces the legacy network_scanner's in-memory inventory and
unverified rogue/block flags. It writes real host observations into the existing
Device table. The old discovery router's broad port-8000 probing is replaced
with an authenticated, read-only status endpoint. There is one inventory.

## Start and stop

Start the API and dashboard using docs/MANUAL_VALIDATION.md. API startup never
starts collection. OFFLINE_MODE=true retains the safe SQLite/API configuration;
the runtime health mode becomes discovery only while an explicitly launched
collector has an active lease. Do not set OFFLINE_MODE=false to enable legacy code.

In a separate local PowerShell window, from C:\Projects\domeMCA, inspect your
own Wi-Fi configuration and explicitly approve only that network:

```powershell
.\.venv-offline\Scripts\python -X utf8 -B -m backend.network_scanner --approve-scope "YOUR_PRIVATE_CIDR" --profile "YOUR_WIFI_PROFILE_NAME" --gateway "YOUR_GATEWAY_IP" --interval 60
```

Replace the placeholders with your authorized network values. Supports Windows,
an adapter named Wi-Fi, English ipconfig output, an exact RFC1918 IPv4 subnet
between /24 and /30, and installed Nmap/Npcap. Unsupported or ambiguous adapter
information fails closed. No credentials, real SSIDs or network inventories belong
in Git. The existing local database is ignored.

The local command is explicit session approval. It repeats after each completed
scan and the configured interval, not on API/browser startup. Keep its terminal
open; Ctrl+C stops it. From another local terminal:

```powershell
.\.venv-offline\Scripts\python -X utf8 -B -m backend.network_scanner --stop
```

An in-flight bounded Nmap request can finish after stop; its results are discarded.
No startup task/service is installed. Restarting the computer requires a new
explicit collector launch. A network mismatch or scan failure stops collection.

## What the dashboard means

- LIVE NETWORK DISCOVERY: collector lease active and at least one scan completed.
- Starting/scanning: approved collection is in progress.
- Offline/stopped/error/stale: no verified active collection; inspect the message.
- Count: hosts observed in the last successful scan, including this laptop.
- Stored identities: retained history; not all are currently connected.
- Agent UNKNOWN: no heartbeat recorded. Discovery never supplies a heartbeat.
- Security NOT ASSESSED: discovery provides no threat verdict.
- Vendor is a MAC database annotation, not a verified device name or owner.

Profile, subnet and gateway are checked before and after each scan; mismatched
results are discarded. This is an operational scope guard, not cryptographic
network authentication. Same-named networks or spoofing cannot be ruled out.
There is a bounded race if the network changes after the pre-scan check.

Nmap uses host discovery (-sn -PR), not port enumeration, scripts, OS fingerprinting,
capture or enforcement. Names/MACs can be absent. Private MAC rotation can produce
multiple identities. IP-only observations cannot establish stable identity.
Sleeping hosts and Wi-Fi client isolation can hide devices. Compare against
the router client list; do not promise every connected device is discovered.

## Data and rollback

DiscoverySession stores session approval time, scope, status and lease.
DiscoveryRun stores each attempt, timestamps, completion/failure and observations.
Device.last_network_seen is independent of last_agent_heartbeat/last_endpoint_event.
Existing endpoint risk and containment fields are preserved. New devices are
UNASSESSED / UNKNOWN with a null risk score.

The migration only adds tables using SQLAlchemy create_all. Stop the collector
before rollback; keep a SQLite backup outside Git. Existing baseline data is
preserved. No enforcement point or endpoint ingestion is enabled by this change.

## Manual validation (pending user confirmation)

1. Fresh offline startup: health says offline; no collector/Nmap process starts.
2. Launch with an explicit approved scope/profile/gateway. Confirm the visible
   scope and observed count, names where available, IPs, MACs and timestamps.
3. Wait for a second scan: a new audit row appears, identities are deduplicated.
4. In a lab, disconnect/change Wi-Fi: collector must stop/error without expanding scope.
5. Stop collection: banner becomes inactive; stored devices remain history.
6. Confirm agent heartbeat/event fields remain unchanged or unknown.
7. Unauthenticated GET /discovery/status must return 401. No API start/scan/action
   endpoint is enabled; reader action requests remain 403.
8. Compare with the router's client list manually. Record missed hosts/unknown names.
9. Reports, real agent recovery and containment remain unvalidated and disabled.
10. Report failures with commit, steps, expected/actual behavior and a redacted screenshot.
