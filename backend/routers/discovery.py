"""
Device Discovery Router
Scans LAN for connected devices running AVIGHNA agent
"""

from fastapi import APIRouter, Query
from .. import state
import requests
import socket
import threading
import time
from collections import defaultdict

router = APIRouter()

# Store discovered devices
discovered_devices = {}

def get_subnet_from_ip(ip: str) -> str:
    """Get subnet range from IP (e.g., 192.168.0.x)"""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return None

def scan_host(ip: str, port: int = 8000, timeout: float = 0.5) -> dict:
    """Try to connect to a host and get info"""
    # Prefer contacting a running AVIGHNA agent endpoint if available
    try:
        url = f"http://{ip}:{port}/agent/ping"
        resp = requests.get(url, timeout=timeout)
        if resp.ok:
            try:
                data = resp.json()
            except:
                data = {}

            try:
                hostname = data.get('hostname') or socket.gethostbyaddr(ip)[0]
            except:
                hostname = data.get('hostname') or 'unknown'

            return {
                "ip": ip,
                "port": port,
                "status": "online",
                "hostname": hostname,
                "timestamp": time.time(),
                "agent": True,
                "info": data
            }
    except Exception:
        # If HTTP agent check fails, fall back to basic TCP port probe
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "unknown"
                return {
                    "ip": ip,
                    "port": port,
                    "status": "online",
                    "hostname": hostname,
                    "timestamp": time.time(),
                    "agent": False
                }
        except Exception:
            return None
    return None

def scan_subnet(subnet: str, start: int = 1, end: int = 254, port: int = 8000):
    """Scan a subnet for active hosts"""
    results = []
    threads = []
    
    def worker(ip):
        result = scan_host(ip, port)
        if result:
            results.append(result)
    
    # Scan IPs in range (threaded for speed)
    for i in range(start, end + 1):
        ip = f"{subnet}.{i}"
        t = threading.Thread(target=worker, args=(ip,), daemon=True)
        threads.append(t)
        t.start()
        # Limit concurrent threads
        if len(threads) > 20:
            for thread in threads:
                thread.join(timeout=0.1)
            threads = [t for t in threads if t.is_alive()]
    
    # Wait for all threads
    for t in threads:
        t.join(timeout=2)
    
    return results

@router.get("/scan")
def discover_devices(timeout: int = Query(5, ge=1, le=30)):
    """
    Scan local network for devices running AVIGHNA agent.
    
    Returns list of discovered devices with IP, hostname, status.
    Takes ~timeout seconds to complete.
    """
    global discovered_devices
    
    # Get current device's IP from state (if available)
    current_ip = None
    if hasattr(state, 'devices') and state.devices:
        # Try to get an IP from existing device data
        for dev_id, dev_info in state.devices.items():
            if 'ip' in dev_info:
                current_ip = dev_info['ip']
                break
    
    # If no IP in state, try common defaults
    if not current_ip:
        current_ip = "192.168.0.102"  # Default or detect from socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            current_ip = s.getsockname()[0]
            s.close()
        except:
            pass
    
    subnet = get_subnet_from_ip(current_ip)
    if not subnet:
        return {"error": "Could not determine subnet", "devices": []}

    # Scan the subnet
    discovered = scan_subnet(subnet, port=8000)

    # Build list of local IPs/hostnames to exclude (this machine)
    local_ips = set()
    local_hostnames = set()
    local_ips.add('127.0.0.1')
    if current_ip:
        local_ips.add(current_ip)
    try:
        host = socket.gethostname()
        local_hostnames.add(host)
        # add resolved addresses for this hostname
        try:
            addrs = socket.gethostbyname_ex(host)[2]
            for a in addrs:
                local_ips.add(a)
        except Exception:
            pass
        # also try getaddrinfo to collect IPv4s
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                addr = info[4][0]
                if ':' not in addr:
                    local_ips.add(addr)
        except Exception:
            pass
    except Exception:
        pass

    # Filter out this host, loopback, APIPA, and docker host entries
    def is_local(d):
        ip = d.get('ip', '')
        hn = (d.get('hostname') or '').lower()
        if not ip:
            return True
        if ip in local_ips:
            return True
        if ip.startswith('127.') or ip.startswith('169.254.'):
            return True
        if 'docker' in hn or 'host.docker' in hn:
            return True
        # hostname matches local host
        if any(hn == lh.lower() for lh in local_hostnames):
            return True
        return False

    discovered = [d for d in discovered if not is_local(d)]

    # Store discoveries
    discovered_devices = {d['ip']: d for d in discovered}
    
    return {
        "subnet": f"{subnet}.0/24",
        "scan_time": timeout,
        "devices_found": len(discovered),
        "devices": discovered
    }

@router.post("/connect/{device_ip}")
def connect_device(device_ip: str, force: bool = Query(False)):
    """
    Register and connect to a discovered device.
    Adds it to the monitored devices list.
    """
    # If device wasn't found in last scan, try probing the agent endpoint directly
    device_info = discovered_devices.get(device_ip)
    if not device_info:
        # Try HTTP probe to agent endpoint
        try:
            url = f"http://{device_ip}:8000/agent/ping"
            resp = requests.get(url, timeout=1)
            if resp.ok:
                try:
                    info = resp.json()
                except:
                    info = {}
                hostname = info.get('hostname') or device_ip
                device_info = {
                    'ip': device_ip,
                    'port': 8000,
                    'status': 'online',
                    'hostname': hostname,
                    'timestamp': time.time(),
                    'agent': True,
                    'info': info
                }
            else:
                # If force flag provided, register device without agent
                if force:
                    device_info = {
                        'ip': device_ip,
                        'port': 8000,
                        'status': 'unknown',
                        'hostname': device_ip,
                        'timestamp': time.time(),
                        'agent': False,
                        'info': {}
                    }
                else:
                    return {"error": f"No AVIGHNA agent reachable at {device_ip}:8000", "success": False}
        except Exception:
            if force:
                device_info = {
                    'ip': device_ip,
                    'port': 8000,
                    'status': 'unknown',
                    'hostname': device_ip,
                    'timestamp': time.time(),
                    'agent': False,
                    'info': {}
                }
            else:
                return {"error": f"Could not reach {device_ip}:8000", "success": False}

    # Create a better device ID for phones
    hostname = device_info.get('hostname', device_ip)
    if hostname == device_ip:
        # If no hostname, create a phone-friendly ID
        device_id = f"phone-{device_ip.replace('.', '-')}"
    else:
        device_id = f"phone-{hostname}"
    
    # Add to state devices
    if not hasattr(state, 'devices'):
        state.devices = {}

    verified = bool(device_info.get('agent'))
    status = "OK" if verified else "UNVERIFIED"
    last_seen = time.time() if verified else None

    state.devices[device_id] = {
        "device_id": device_id,
        "ip": device_ip,
        "hostname": device_info['hostname'],
        "status": status,
        "last_risk": 0.0,
        "risk_level": "GREEN",
        "quarantined": False,
        "last_seen": last_seen,
        "source": "discovery" if verified else "manual",
        "verified": verified,
        "agent_info": device_info.get('info', {}) if device_info.get('agent') else {},
        "telemetry_health_score": 100.0 if verified else 50.0,
        "telemetry_status": "ACTIVE" if verified else "WAITING"
    }

    # Create a friendly alert when a device is connected/registered
    try:
        from .. import state as _state
        aid = str(int(time.time())) + '-' + device_id
        alert = {
            "id": aid,
            "device_id": device_id,
            "reason": "Device connected" + (" (verified)" if verified else " (unverified)"),
            "severity": 1,
            "payload": {"ip": device_ip, "verified": verified},
            "risk": {"risk_score": 0.0, "risk_level": "GREEN"},
            "ts": time.time()
        }
        _state.alerts.insert(0, alert)
    except Exception:
        pass
    
    return {
        "success": True,
        "device_id": device_id,
        "ip": device_ip,
        "verified": verified,
        "message": f"Connected to {device_id} at {device_ip}"
    }

@router.get("/discovered")
def list_discovered():
    """List all discovered devices from the last scan"""
    return {
        "devices": list(discovered_devices.values()),
        "count": len(discovered_devices)
    }
