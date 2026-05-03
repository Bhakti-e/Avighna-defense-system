# backend/background_tasks.py
import threading, time, subprocess, json, os
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

def run_nmap_discovery(network_cidr="192.168.0.0/24"):
    """
    Use nmap to discover ALL devices on the network
    Optimized configuration for maximum device detection
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
        
        # OPTIMIZED nmap configuration for WiFi device detection:
        # -PR: ARP ping (most reliable for local network, works even when devices ignore ICMP)
        # -sn: No port scan (faster)
        # -n: No DNS resolution (faster)
        # --send-ip: Send IP-level pings too
        
        import logging
        logger = logging.getLogger('dome')
        logger.info(f"Starting ARP-based nmap scan on {network_cidr}...")
        
        result = subprocess.run(
            [
                nmap_cmd, 
                "-PR",  # ARP ping (works on sleeping WiFi devices)
                "-sn",  # No port scan
                "-n",   # No DNS (faster)
                network_cidr,
                "--max-retries", "3",
                "--host-timeout", "10s"
            ],
            capture_output=True,
            text=True,
            timeout=60,  # Shorter timeout for ARP scan
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
                    hosts.append({
                        "ip": current_ip,
                        "hostname": current_hostname,
                        "mac": current_mac or "unknown",
                        "vendor": current_vendor or "Unknown"
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
            hosts.append({
                "ip": current_ip,
                "hostname": current_hostname,
                "mac": current_mac or "unknown",
                "vendor": current_vendor or "Unknown"
            })
        
        logger.info(f"✅ Nmap ARP scan complete: found {len(hosts)} device(s)")
        return hosts
        
    except subprocess.TimeoutExpired:
        import logging
        logging.getLogger('dome').error("Nmap scan timeout (60s)")
        return []
    except Exception as e:
        import logging
        logging.getLogger('dome').error(f"Nmap scan error: {e}")
        return []

def network_discovery_worker(interval=30):
    """
    Network discovery worker - uses ARP-based nmap as PRIMARY source
    
    Architecture:
    1. Nmap with ARP ping (PRIMARY - detects idle WiFi devices)
    2. Active ARP population (pings all IPs to wake devices)
    3. ARP table (FALLBACK - if nmap fails)
    4. Router (BLOCKED - authentication prevents access)
    """
    from .device_manager import device_manager
    from .router_discovery import router_discovery
    import logging
    logger = logging.getLogger('dome')
    
    scan_count = 0
    router_blocked_logged = False
    
    while True:
        try:
            scan_count += 1
            logger.info(f"Starting network discovery scan #{scan_count}...")
            
            # Try router discovery first (will likely fail due to auth)
            if not router_blocked_logged:
                router_devices = router_discovery.discover_devices()
                
                if router_devices:
                    logger.info(f"✅ Router discovery: {len(router_devices)} device(s) found via {router_discovery.discovery_method}")
                    
                    for device in router_devices:
                        device_manager.register_device(
                            ip=device['ip'],
                            mac=device['mac'],
                            hostname=device.get('hostname'),
                            vendor=device.get('vendor', 'Unknown'),
                            source='router',
                            device_name=device.get('name')
                        )
                else:
                    logger.warning("⚠️ Router discovery blocked by authentication - using nmap as PRIMARY")
                    router_blocked_logged = True  # Only log once
            
            # PRIMARY: Use ARP-based nmap discovery
            discovered_hosts = run_nmap_discovery("192.168.0.0/24")
            
            if discovered_hosts:
                logger.info(f"✅ Nmap ARP PRIMARY: {len(discovered_hosts)} device(s) found")
                
                for host in discovered_hosts:
                    device_manager.register_device(
                        ip=host["ip"],
                        mac=host["mac"],
                        hostname=host.get("hostname"),
                        vendor=host["vendor"],
                        source="nmap",
                        device_name=host.get("hostname")  # Use hostname as device name
                    )
            else:
                # FALLBACK: ARP table
                logger.warning("⚠️ Nmap failed, using ARP table fallback")
                hosts = run_arp()
                
                if hosts:
                    logger.info(f"ARP fallback: {len(hosts)} device(s)")
                    for h in hosts:
                        device_manager.register_device(
                            ip=h["ip"],
                            mac=h["mac"],
                            vendor="Unknown",
                            source="arp"
                        )
                else:
                    logger.error("❌ All discovery methods failed - no devices found")
            
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
