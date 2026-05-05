# backend/background_tasks.py
import threading, time, subprocess, json, os
from typing import Optional
from . import state
from .scanning.active_scanner import active_scanner
import time, re

# simple arp parsing (works on Windows & Linux output)
ARP_IP_MAC_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:-]{11,17})")

def parse_arp_output(out):
    hosts = []
    for line in out.splitlines():
        m = ARP_IP_MAC_RE.search(line)
        if m:
            ip = m.group(1)
            mac = m.group(2).lower()
            
            # Filter out multicast, broadcast, and special addresses
            # Skip multicast IPs (224.0.0.0/4 and 239.0.0.0/8)
            if ip.startswith('224.') or ip.startswith('239.'):
                continue
            # Skip broadcast addresses
            if ip.endswith('.255') or ip == '255.255.255.255':
                continue
            # Skip broadcast MAC
            if mac == 'ff-ff-ff-ff-ff-ff' or mac == 'ff:ff:ff:ff:ff:ff':
                continue
            # Skip multicast MACs (01-00-5e-* range)
            if mac.startswith('01-00-5e') or mac.startswith('01:00:5e'):
                continue
            # Skip localhost
            if ip.startswith('127.') or ip == '0.0.0.0':
                continue
                
            hosts.append({"ip": ip, "mac": mac})
    return hosts

def run_arp():
    try:
        # Windows: arp -a ; Linux: arp -n
        out = subprocess.check_output(["arp", "-a"], text=True, encoding="utf-8", errors="ignore")
        return parse_arp_output(out)
    except Exception:
        try:
            out = subprocess.check_output(["arp", "-n"], text=True, encoding="utf-8", errors="ignore")
            return parse_arp_output(out)
        except Exception:
            return []

def reverse_dns_lookup(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup to get hostname
    Returns hostname or None
    """
    import socket
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname else None
    except:
        return None

def nbtscan_lookup(ip: str) -> Optional[str]:
    """
    Use NetBIOS name lookup (Windows networks)
    Returns NetBIOS name or None
    """
    try:
        # Try nmblookup (Linux) or nbtstat (Windows)
        import platform
        if platform.system().lower() == 'windows':
            result = subprocess.run(
                ['nbtstat', '-A', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                # Parse nbtstat output for computer name
                for line in result.stdout.split('\n'):
                    if '<00>' in line and 'UNIQUE' in line:
                        name = line.split()[0].strip()
                        if name and not name.startswith('~'):
                            return name
        else:
            result = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '<00>' in line:
                        name = line.split()[0].strip()
                        return name
    except:
        pass
    return None

def is_randomized_mac(mac: str) -> bool:
    """
    Detect if MAC address is randomized (privacy feature)
    Randomized MACs have locally administered bit set (2nd hex digit is 2, 6, A, or E)
    """
    if not mac or len(mac) < 2:
        return False
    
    # Get second character (first octet, second hex digit)
    second_char = mac.replace(':', '').replace('-', '')[1].upper()
    
    # Check if locally administered bit is set
    return second_char in ['2', '3', '6', '7', 'A', 'B', 'E', 'F']

def active_arp_population(network_cidr="192.168.0.0/24"):
    """
    Actively ping all IPs in the subnet to populate ARP table
    This wakes up sleeping devices so they appear in ARP table
    Uses fast parallel pinging to minimize scan time
    """
    import socket
    import ipaddress
    import concurrent.futures
    import platform
    
    try:
        # Parse network CIDR
        network = ipaddress.ip_network(network_cidr, strict=False)
        
        # Get local IP to exclude
        local_ip = socket.gethostbyname(socket.gethostname())
        
        # Determine ping command based on OS
        is_windows = platform.system().lower() == 'windows'
        ping_cmd = ['ping', '-n', '1', '-w', '100'] if is_windows else ['ping', '-c', '1', '-W', '1']
        
        def ping_ip(ip_str):
            """Ping a single IP (returns True if responds, False otherwise)"""
            if ip_str == local_ip:
                return None
            try:
                result = subprocess.run(
                    ping_cmd + [ip_str],
                    capture_output=True,
                    timeout=2
                )
                return ip_str if result.returncode == 0 else None
            except:
                return None
        
        # Ping all IPs in parallel (fast)
        import logging
        logger = logging.getLogger('dome')
        logger.debug(f"Pinging {network_cidr} to populate ARP table...")
        
        responding_ips = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            # Submit all ping tasks
            futures = [executor.submit(ping_ip, str(ip)) for ip in network.hosts()]
            
            # Collect results
            for future in concurrent.futures.as_completed(futures, timeout=30):
                try:
                    result = future.result()
                    if result:
                        responding_ips.append(result)
                except:
                    pass
        
        logger.debug(f"Ping sweep complete: {len(responding_ips)} device(s) responded")
        return responding_ips
        
    except Exception as e:
        import logging
        logging.getLogger('dome').error(f"ARP population error: {e}")
        return []

def run_nmap_discovery(network_cidr="192.168.0.0/24"):
    """
    Use nmap to discover ALL devices on the network
    IMPROVED: Multiple scan techniques for maximum detection
    Returns list of discovered hosts with IP, MAC, vendor, hostname
    """
    import platform
    import socket
    
    # Find nmap executable
    nmap_paths = [
        "C:\\Program Files (x86)\\Nmap\\nmap.exe",
        "C:\\Program Files\\Nmap\\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "nmap"
    ]
    
    nmap_cmd = None
    for path in nmap_paths:
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                nmap_cmd = path
                break
        except:
            continue
    
    if not nmap_cmd:
        import logging
        logging.getLogger('dome').warning("Nmap not found - device discovery limited to ARP")
        return []
    
    try:
        # Get local IP to exclude self
        local_ip = socket.gethostbyname(socket.gethostname())
        
        import logging
        logger = logging.getLogger('dome')
        logger.debug(f"Running nmap discovery on {network_cidr}...")
        
        # IMPROVED: Use multiple ping techniques for maximum detection
        # -PR: ARP ping (Layer 2 - works on local network)
        # -PS: TCP SYN ping (Layer 4 - works when ICMP blocked)
        # -PA: TCP ACK ping (Layer 4 - bypasses some firewalls)
        # -sn: No port scan (faster)
        # -n: No DNS (faster, we'll do reverse DNS separately)
        result = subprocess.run(
            [
                nmap_cmd, 
                "-PR",  # ARP ping (primary for local network)
                "-PS80,443,22",  # TCP SYN ping on common ports
                "-PA80,443,22",  # TCP ACK ping on common ports
                "-sn",  # No port scan
                "-n",   # No DNS (we do reverse DNS separately)
                network_cidr,
                "--max-retries", "2",
                "--host-timeout", "5s",
                "--min-rate", "300"  # Faster scanning
            ],
            capture_output=True,
            text=True,
            timeout=45,
            encoding="utf-8",
            errors="ignore"
        )
        
        if result.returncode != 0:
            logger.warning(f"Nmap scan failed with return code {result.returncode}")
            return []
        
        # Parse nmap output
        hosts = []
        lines = result.stdout.split('\n')
        current_ip = None
        current_hostname = None
        current_mac = None
        current_vendor = None
        
        for line in lines:
            line = line.strip()
            
            # Extract IP and hostname
            if line.startswith("Nmap scan report for"):
                if current_ip and current_ip != local_ip:
                    # Perform reverse DNS lookup for hostname
                    hostname = reverse_dns_lookup(current_ip)
                    if not hostname:
                        hostname = nbtscan_lookup(current_ip)
                    
                    hosts.append({
                        "ip": current_ip,
                        "hostname": hostname or current_hostname,
                        "mac": current_mac or "unknown",
                        "vendor": current_vendor or "Unknown",
                        "is_randomized_mac": is_randomized_mac(current_mac) if current_mac else False
                    })
                
                # Reset for new host
                parts = line.replace("Nmap scan report for ", "")
                if '(' in parts and ')' in parts:
                    current_hostname = parts.split('(')[0].strip()
                    current_ip = parts.split('(')[1].rstrip(')')
                else:
                    current_ip = parts.strip()
                    current_hostname = None
                current_mac = None
                current_vendor = None
            
            # Extract MAC
            elif line.startswith("MAC Address:"):
                parts = line.split("MAC Address:")[1].strip()
                if '(' in parts:
                    mac_part, vendor_part = parts.split('(', 1)
                    current_mac = mac_part.strip().lower().replace(':', '-')
                    current_vendor = vendor_part.rstrip(')').strip()
                else:
                    current_mac = parts.strip().lower().replace(':', '-')
        
        # Add last host
        if current_ip and current_ip != local_ip:
            hostname = reverse_dns_lookup(current_ip)
            if not hostname:
                hostname = nbtscan_lookup(current_ip)
            
            hosts.append({
                "ip": current_ip,
                "hostname": hostname or current_hostname,
                "mac": current_mac or "unknown",
                "vendor": current_vendor or "Unknown",
                "is_randomized_mac": is_randomized_mac(current_mac) if current_mac else False
            })
        
        logger.debug(f"Nmap scan complete: found {len(hosts)} device(s)")
        return hosts
        
    except subprocess.TimeoutExpired:
        import logging
        logging.getLogger('dome').error("Nmap scan timeout (45s)")
        return []
    except Exception as e:
        import logging
        logging.getLogger('dome').error(f"Nmap scan error: {e}")
        return []

def network_discovery_worker(interval=20):
    """
    IMPROVED Network Discovery Worker - Maximum device detection accuracy
    
    Multi-layer discovery architecture:
    1. Active ARP population (ping sweep to wake devices)
    2. Nmap multi-technique scan (ARP + TCP SYN/ACK pings)
    3. ARP table parsing (catches devices missed by nmap)
    4. Passive Scapy monitoring (continuous background detection)
    5. Router discovery (if user provides credentials)
    
    Runs every 20 seconds for continuous monitoring
    """
    from .device_manager import device_manager
    from .router_discovery import router_discovery
    import logging
    logger = logging.getLogger('dome')
    
    scan_count = 0
    router_blocked_logged = False
    nmap_consecutive_failures = 0
    
    while True:
        try:
            scan_count += 1
            logger.info(f"🔍 Discovery scan #{scan_count} starting...")
            
            discovered_devices = {}  # MAC -> device info (for deduplication)
            
            # LAYER 1: Active ARP population (wake sleeping devices)
            logger.debug("Layer 1: Ping sweep to wake devices...")
            responding_ips = active_arp_population("192.168.0.0/24")
            logger.info(f"✅ Layer 1: {len(responding_ips)} device(s) responded to ping")
            
            # LAYER 2: Nmap multi-technique scan (PRIMARY)
            # Skip nmap if it's been failing consistently (Windows crash issue)
            if nmap_consecutive_failures < 3:
                logger.debug("Layer 2: Nmap multi-technique scan...")
                nmap_hosts = run_nmap_discovery("192.168.0.0/24")
            else:
                logger.warning("⚠️ Layer 2: Skipping nmap (consecutive failures detected)")
                nmap_hosts = []
            
            if nmap_hosts:
                logger.info(f"✅ Layer 2: {len(nmap_hosts)} device(s) found via nmap")
                nmap_consecutive_failures = 0  # Reset failure counter
                
                for host in nmap_hosts:
                    mac = host["mac"]
                    
                    # Handle randomized MAC addresses
                    if host.get("is_randomized_mac"):
                        # Mark as private MAC device
                        device_name = f"Private MAC Device ({host['ip']})"
                        logger.debug(f"Detected randomized MAC: {mac} at {host['ip']}")
                    else:
                        device_name = host.get("hostname")
                    
                    # Store in deduplication map
                    if mac != "unknown":
                        discovered_devices[mac] = {
                            "ip": host["ip"],
                            "mac": mac,
                            "hostname": host.get("hostname"),
                            "vendor": host["vendor"],
                            "device_name": device_name,
                            "source": "nmap",
                            "confidence": "high" if not host.get("is_randomized_mac") else "medium"
                        }
            else:
                nmap_consecutive_failures += 1
                logger.warning(f"⚠️ Layer 2: Nmap scan returned no results (failure #{nmap_consecutive_failures})")
            
            # LAYER 3: ARP table parsing (catches devices missed by nmap)
            logger.debug("Layer 3: Parsing ARP table...")
            arp_hosts = run_arp()
            
            new_from_arp = 0
            for host in arp_hosts:
                mac = host["mac"]
                
                # Only add if not already discovered
                if mac not in discovered_devices:
                    # Try to get hostname via reverse DNS
                    hostname = reverse_dns_lookup(host["ip"])
                    if not hostname:
                        hostname = nbtscan_lookup(host["ip"])
                    
                    # Check if randomized MAC
                    is_random = is_randomized_mac(mac)
                    device_name = f"Private MAC Device ({host['ip']})" if is_random else hostname
                    
                    discovered_devices[mac] = {
                        "ip": host["ip"],
                        "mac": mac,
                        "hostname": hostname,
                        "vendor": "Unknown",
                        "device_name": device_name,
                        "source": "arp",
                        "confidence": "medium" if not is_random else "low"
                    }
                    new_from_arp += 1
            
            logger.info(f"✅ Layer 3: {new_from_arp} additional device(s) from ARP table")
            
            # LAYER 3.5: Create devices from ping responses if not in discovered_devices
            # This ensures devices that respond to ping but aren't in ARP/nmap get registered
            logger.debug("Layer 3.5: Registering ping-responsive devices...")
            new_from_ping = 0
            for ip in responding_ips:
                # Check if this IP is already in discovered_devices
                ip_found = any(d['ip'] == ip for d in discovered_devices.values())
                
                if not ip_found:
                    # Device responded to ping but not in ARP/nmap - create it
                    # Try to get MAC from ARP table
                    mac = None
                    for arp_host in arp_hosts:
                        if arp_host['ip'] == ip:
                            mac = arp_host['mac']
                            break
                    
                    if not mac:
                        # No MAC found - use IP as device_id
                        mac = f"unknown-{ip}"
                    
                    # Try to get hostname
                    hostname = reverse_dns_lookup(ip)
                    if not hostname:
                        hostname = nbtscan_lookup(ip)
                    
                    is_random = is_randomized_mac(mac) if mac and mac != f"unknown-{ip}" else False
                    device_name = f"Private MAC Device ({ip})" if is_random else hostname
                    
                    discovered_devices[mac] = {
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "vendor": "Unknown",
                        "device_name": device_name,
                        "source": "ping",
                        "confidence": "low"
                    }
                    new_from_ping += 1
            
            if new_from_ping > 0:
                logger.info(f"✅ Layer 3.5: {new_from_ping} additional device(s) from ping responses")
            
            # LAYER 4: Router discovery (if authentication allows)
            if not router_blocked_logged:
                logger.debug("Layer 4: Attempting router discovery...")
                router_devices = router_discovery.discover_devices()
                
                if router_devices:
                    new_from_router = 0
                    for device in router_devices:
                        mac = device['mac']
                        
                        # Router provides most accurate device names
                        if mac not in discovered_devices:
                            discovered_devices[mac] = {
                                "ip": device['ip'],
                                "mac": mac,
                                "hostname": device.get('hostname'),
                                "vendor": device.get('vendor', 'Unknown'),
                                "device_name": device.get('name'),
                                "source": "router",
                                "confidence": "high"
                            }
                            new_from_router += 1
                        else:
                            # Update with better info from router
                            if device.get('name'):
                                discovered_devices[mac]['device_name'] = device['name']
                                discovered_devices[mac]['confidence'] = "high"
                    
                    logger.info(f"✅ Layer 4: {new_from_router} additional device(s) from router")
                else:
                    logger.warning("⚠️ Layer 4: Router discovery blocked by authentication")
                    router_blocked_logged = True
            
            # Register all discovered devices
            total_registered = 0
            for mac, device_info in discovered_devices.items():
                result = device_manager.register_device(
                    ip=device_info["ip"],
                    mac=device_info["mac"],
                    hostname=device_info.get("hostname"),
                    vendor=device_info.get("vendor", "Unknown"),
                    source=device_info["source"],
                    device_name=device_info.get("device_name")
                )
                if result:
                    total_registered += 1
            
            # Summary
            logger.info(f"🎯 Scan #{scan_count} complete: {len(discovered_devices)} unique device(s) discovered, {total_registered} registered")
            
            if len(discovered_devices) == 0:
                logger.error("❌ WARNING: No devices discovered - check network connectivity")
            
            time.sleep(interval)
            
        except Exception as e:
            try:
                import logging
                logging.getLogger('dome').exception('Network discovery worker error: %s', e)
            except Exception:
                pass
            time.sleep(interval)

def cti_update_worker(interval=3600):
    """Background worker to update CTI feeds periodically"""
    from .core.cti import cti_manager
    
    while True:
        try:
            import logging
            logger = logging.getLogger('dome')
            logger.info("Starting CTI feed update...")
            
            stats = cti_manager.update_feeds()
            
            logger.info(f"CTI update complete: {stats['new_ips']} IPs, "
                       f"{stats['new_domains']} domains, {stats['new_hashes']} hashes")
            
            time.sleep(interval)
            
        except Exception as e:
            try:
                import logging
                logging.getLogger('dome').exception('CTI update worker error: %s', e)
            except Exception:
                pass
            time.sleep(interval)


def start_background_tasks():
    from .config import settings
    from .scanning.scapy_monitor import scapy_monitor
    import logging
    logger = logging.getLogger('dome')
    
    # Start network discovery worker (replaces ARP worker)
    t = threading.Thread(target=network_discovery_worker, daemon=True, name="Network-Discovery")
    t.start()
    logger.info("Network discovery worker started (using nmap)")
    
    # Start active reconnaissance scanner
    active_scanner.start()
    logger.info("✅ Active reconnaissance scanner started")
    
    # Start Scapy passive monitor (if enabled)
    if settings.enable_scapy_monitor:
        try:
            success = scapy_monitor.start()
            if success:
                logger.info("✅ Scapy passive network monitor started")
            else:
                logger.warning("⚠️ Scapy monitor failed to start (may require admin privileges)")
        except Exception as e:
            logger.error(f"Failed to start Scapy monitor: {e}")
    else:
        logger.info("Scapy passive monitoring disabled in config")
    
    # Start telemetry health monitoring
    health_monitor = threading.Thread(target=telemetry_health_worker, daemon=True, name="Health-Monitor")
    health_monitor.start()
    
    # Start CTI feed updater
    cti_interval = int(os.environ.get('CTI_UPDATE_INTERVAL', 3600))  # Default: 1 hour
    cti_worker = threading.Thread(target=cti_update_worker, args=(cti_interval,), daemon=True, name="CTI-Worker")
    cti_worker.start()
    
    logger.info("Background tasks started")

def telemetry_health_worker(interval=30):
    """Background worker to update device statuses based on last_seen"""
    from .device_manager import device_manager
    
    while True:
        try:
            # Update all device statuses (ACTIVE/RECENTLY_SEEN/OFFLINE)
            device_manager.update_all_device_statuses()
            time.sleep(interval)
            
        except Exception as e:
            try:
                import logging
                logging.getLogger('dome').exception('Device status worker error: %s', e)
            except Exception:
                pass
            time.sleep(interval)
