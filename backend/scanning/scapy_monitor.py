"""
Scapy Passive Network Monitor for AVIGHNA Defense
==================================================
Real-time ARP/WiFi monitoring to detect:
- Rogue devices
- ARP spoofing attacks
- MAC address spoofing
- Probe request floods
- Unauthorized access attempts

NO DEMO DATA - Only real network traffic
"""

import logging
import threading
import time
from typing import Dict, List, Any, Optional, Callable
from collections import defaultdict
from datetime import datetime
import socket

try:
    from scapy.all import sniff, ARP, Dot11, Dot11ProbeReq, get_if_list, IP, TCP, UDP, DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - passive monitoring disabled")

logger = logging.getLogger(__name__)

# Import brute force detector
try:
    from .brute_force_detector import brute_force_detector
    BRUTE_FORCE_DETECTION_ENABLED = True
except ImportError:
    BRUTE_FORCE_DETECTION_ENABLED = False
    logger.warning("Brute force detector not available")

# Import DNS anomaly detector
try:
    from .dns_anomaly_detector import dns_anomaly_detector
    DNS_ANOMALY_DETECTION_ENABLED = True
except ImportError:
    DNS_ANOMALY_DETECTION_ENABLED = False
    logger.warning("DNS anomaly detector not available")

# Import brute force detector
try:
    from .brute_force_detector import brute_force_detector
    BRUTE_FORCE_DETECTION_ENABLED = True
except ImportError:
    BRUTE_FORCE_DETECTION_ENABLED = False
    logger.warning("Brute force detector not available")

# Import DNS anomaly detector
try:
    from .dns_anomaly_detector import dns_anomaly_detector
    DNS_ANOMALY_DETECTION_ENABLED = True
except ImportError:
    DNS_ANOMALY_DETECTION_ENABLED = False
    logger.warning("DNS anomaly detector not available")


class ScapyNetworkMonitor:
    """
    Passive network monitor using Scapy
    Detects attacks and rogue devices in real-time
    """
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.running = False
        self.thread = None
        
        # Track seen devices
        self.arp_table: Dict[str, Dict[str, Any]] = {}  # IP -> {mac, vendor, first_seen, last_seen, count}
        self.mac_to_ips: Dict[str, List[str]] = defaultdict(list)  # MAC -> [IPs]
        self.ip_to_macs: Dict[str, List[str]] = defaultdict(list)  # IP -> [MACs]
        
        # PORT SCAN DETECTION
        self.port_scan_tracking: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'ports': set(),
            'syn_packets': 0,
            'first_seen': 0,
            'last_seen': 0,
            'targets': set()
        })  # source_ip -> scan data
        
        # Attack detection
        self.arp_spoof_alerts: List[Dict[str, Any]] = []
        self.probe_flood_count: Dict[str, int] = defaultdict(int)  # MAC -> count
        self.rogue_devices: List[Dict[str, Any]] = []
        self.port_scan_alerts: List[Dict[str, Any]] = []
        
        # Callbacks for real-time alerts
        self.alert_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'arp_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'dns_packets': 0,
            'syn_packets': 0,
            'probe_requests': 0,
            'devices_discovered': 0,
            'attacks_detected': 0,
            'port_scans_detected': 0,
            'dns_anomalies_detected': 0,
            'started_at': None
        }
    
    def add_alert_callback(self, callback: Callable):
        """Register callback for real-time alerts"""
        self.alert_callbacks.append(callback)
    
    def _trigger_alert(self, alert: Dict[str, Any]):
        """Trigger alert to all registered callbacks"""
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor name from MAC address OUI"""
        # Extract OUI prefix
        oui_prefix = mac.upper().replace(':', '')[:6]
        
        # Common vendors (hardcoded minimal list)
        oui_map = {
            '001122': 'Cisco',
            'D4F5EF': 'Xiaomi',
            '28F076': 'Xiaomi',
            'F0B429': 'Xiaomi',
            '001D0F': 'Apple',
            '0050F2': 'Microsoft',
            'B827EB': 'Raspberry Pi',
            'DCA632': 'Raspberry Pi',
            '00259C': 'Apple',
            '001EC2': 'Apple',
            '0C7738': 'Samsung',
            '5C0A5B': 'Samsung',
            '001A11': 'Google',
            '3C5A37': 'Google'
        }
        return oui_map.get(oui_prefix, 'Unknown')
    
    def _handle_arp_packet(self, packet):
        """Process ARP packet - only updates existing devices, does NOT create new ones"""
        try:
            if not packet.haslayer(ARP):
                return
            
            self.stats['arp_packets'] += 1
            
            arp = packet[ARP]
            src_ip = arp.psrc
            src_mac = arp.hwsrc.upper()
            
            # Skip invalid/broadcast
            if src_ip == '0.0.0.0' or src_mac == 'FF:FF:FF:FF:FF:FF':
                return
            
            timestamp = time.time()
            
            # Track device in Scapy's internal table for monitoring
            if src_ip not in self.arp_table:
                vendor = self._get_vendor_from_mac(src_mac)
                self.arp_table[src_ip] = {
                    'mac': src_mac,
                    'vendor': vendor,
                    'first_seen': timestamp,
                    'last_seen': timestamp,
                    'count': 1
                }
                self.stats['devices_discovered'] += 1
                logger.debug(f"Scapy detected traffic: {src_ip} ({src_mac}) - {vendor}")
            else:
                self.arp_table[src_ip]['last_seen'] = timestamp
                self.arp_table[src_ip]['count'] += 1
            
            # Update device in database through device manager
            # This only updates last_seen for existing devices
            from ..device_manager import device_manager
            device_manager.update_device_from_traffic(src_ip, src_mac, 1)
            
            # Track MAC-IP mappings for spoof detection
            self.mac_to_ips[src_mac].append(src_ip)
            self.ip_to_macs[src_ip].append(src_mac)
            
            # ATTACK DETECTION: ARP Spoofing
            unique_macs = list(set(self.ip_to_macs[src_ip]))
            if len(unique_macs) > 1:
                alert = {
                    'type': 'arp_spoof',
                    'severity': 'CRITICAL',
                    'ip': src_ip,
                    'macs': unique_macs,
                    'current_mac': src_mac,
                    'timestamp': timestamp,
                    'description': f'ARP spoofing detected: IP {src_ip} claimed by multiple MACs'
                }
                self.arp_spoof_alerts.append(alert)
                self.stats['attacks_detected'] += 1
                logger.warning(f"🚨 ARP SPOOF DETECTED: {src_ip} has multiple MACs: {unique_macs}")
                self._trigger_alert(alert)
            
            # Check if same MAC has multiple IPs
            unique_ips = list(set(self.mac_to_ips[src_mac]))
            if len(unique_ips) > 3:
                alert = {
                    'type': 'mac_spoof',
                    'severity': 'HIGH',
                    'mac': src_mac,
                    'ips': unique_ips,
                    'timestamp': timestamp,
                    'description': f'MAC spoofing suspected: {src_mac} claims {len(unique_ips)} IPs'
                }
                self.stats['attacks_detected'] += 1
                logger.warning(f"⚠️ MAC SPOOF SUSPECTED: {src_mac} has {len(unique_ips)} IPs")
                self._trigger_alert(alert)
        
        except Exception as e:
            logger.error(f"Error processing ARP packet: {e}")
    
    def _handle_wifi_packet(self, packet):
        """Process WiFi probe requests for rogue device detection"""
        try:
            if not packet.haslayer(Dot11ProbeReq):
                return
            
            self.stats['probe_requests'] += 1
            
            dot11 = packet[Dot11]
            src_mac = dot11.addr2.upper() if dot11.addr2 else None
            
            if not src_mac or src_mac == 'FF:FF:FF:FF:FF:FF':
                return
            
            # Track probe flood (potential reconnaissance)
            self.probe_flood_count[src_mac] += 1
            
            # Alert on probe flood (>50 probes in monitoring window)
            if self.probe_flood_count[src_mac] > 50:
                vendor = self._get_vendor_from_mac(src_mac)
                alert = {
                    'type': 'probe_flood',
                    'severity': 'MEDIUM',
                    'mac': src_mac,
                    'vendor': vendor,
                    'count': self.probe_flood_count[src_mac],
                    'timestamp': time.time(),
                    'description': f'Probe request flood from {src_mac} ({vendor})'
                }
                self.stats['attacks_detected'] += 1
                
                logger.warning(f"⚠️ PROBE FLOOD: {src_mac} sent {self.probe_flood_count[src_mac]} probes")
                self._trigger_alert(alert)
                
                # Reset counter after alert
                self.probe_flood_count[src_mac] = 0
        
        except Exception as e:
            logger.error(f"Error processing WiFi packet: {e}")
    
    def _handle_dns_packet(self, packet):
        """Process DNS packet - detect DNS anomalies"""
        try:
            if not packet.haslayer(DNS) or not packet.haslayer(IP):
                return
            
            self.stats['dns_packets'] += 1
            
            dns = packet[DNS]
            ip = packet[IP]
            
            src_ip = ip.src
            timestamp = time.time()
            
            # Only process DNS queries (not responses)
            if dns.qr == 0 and dns.qdcount > 0:  # qr=0 means query
                # Extract query information
                query = dns.qd
                if query:
                    domain = query.qname.decode('utf-8', errors='ignore').strip('.')
                    qtype_num = query.qtype
                    
                    # Map query type number to name
                    qtype_map = {
                        1: 'A',
                        2: 'NS',
                        5: 'CNAME',
                        6: 'SOA',
                        12: 'PTR',
                        15: 'MX',
                        16: 'TXT',
                        28: 'AAAA',
                        33: 'SRV',
                        255: 'ANY'
                    }
                    qtype = qtype_map.get(qtype_num, f'TYPE{qtype_num}')
                    
                    # DNS ANOMALY DETECTION
                    if DNS_ANOMALY_DETECTION_ENABLED:
                        dns_anomaly_detector.track_dns_query(
                            src_ip=src_ip,
                            domain=domain,
                            qtype=qtype,
                            response_code=0,  # We don't have response code in query
                            timestamp=timestamp
                        )
                    
                    logger.debug(f"DNS query: {src_ip} → {domain} ({qtype})")
            
            # Process DNS responses (for NXDOMAIN detection)
            elif dns.qr == 1 and dns.qdcount > 0:  # qr=1 means response
                query = dns.qd
                if query:
                    domain = query.qname.decode('utf-8', errors='ignore').strip('.')
                    response_code = dns.rcode  # 0=success, 3=NXDOMAIN
                    
                    # Track failed queries
                    if response_code == 3 and DNS_ANOMALY_DETECTION_ENABLED:
                        qtype_num = query.qtype
                        qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'}
                        qtype = qtype_map.get(qtype_num, f'TYPE{qtype_num}')
                        
                        dns_anomaly_detector.track_dns_query(
                            src_ip=src_ip,
                            domain=domain,
                            qtype=qtype,
                            response_code=response_code,
                            timestamp=timestamp
                        )
                        
                        logger.debug(f"DNS NXDOMAIN: {src_ip} → {domain}")
        
        except Exception as e:
            logger.error(f"Error processing DNS packet: {e}")
    
    def _handle_tcp_packet(self, packet):
        """Process TCP packet - detect port scanning and brute force attacks"""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                return
            
            self.stats['tcp_packets'] += 1
            
            tcp = packet[TCP]
            ip = packet[IP]
            
            src_ip = ip.src
            dst_ip = ip.dst
            dst_port = tcp.dport
            flags = tcp.flags
            
            timestamp = time.time()
            
            # BRUTE FORCE DETECTION
            if BRUTE_FORCE_DETECTION_ENABLED:
                brute_force_detector.track_connection_attempt(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    flags=flags,
                    timestamp=timestamp
                )
            
            # WHITELIST: Ignore legitimate traffic sources
            WHITELISTED_IPS = [
                '8.8.8.8', '8.8.4.4',  # Google DNS
                '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
                '208.67.222.222', '208.67.220.220',  # OpenDNS
            ]
            
            # Whitelist AWS, Google, Microsoft, Cloudflare IP ranges (simplified)
            WHITELISTED_PREFIXES = [
                '18.',  # AWS
                '52.',  # AWS
                '54.',  # AWS
                '3.',   # AWS
                '13.',  # AWS/Microsoft
                '20.',  # Microsoft
                '40.',  # Microsoft
                '104.', # Microsoft/Cloudflare
                '172.', # Various CDNs
                '151.', # Cloudflare/Fastly
                '142.', # Various CDNs
                '98.',  # Microsoft
                '100.', # Various CDNs
                '32.',  # Various CDNs
                '44.',  # AWS
                '34.',  # Google Cloud
            ]
            
            # Whitelist common legitimate ports
            LEGITIMATE_PORTS = {
                80, 443,  # HTTP/HTTPS
                53,       # DNS
                123,      # NTP
                22,       # SSH (if you use it)
                3389,     # RDP (if you use it)
            }
            
            # Check if source is whitelisted
            if src_ip in WHITELISTED_IPS:
                return
            
            for prefix in WHITELISTED_PREFIXES:
                if src_ip.startswith(prefix):
                    return
            
            # Check if destination port is legitimate
            if dst_port in LEGITIMATE_PORTS:
                return
            
            # Get local network info
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
                local_network_prefix = '.'.join(local_ip.split('.')[:3])
            except:
                local_network_prefix = '192.168.0'
            
            # Ignore traffic from router/gateway
            if src_ip.endswith('.1') or src_ip.endswith('.254'):
                return
            
            # Detect SYN packets (port scan indicator)
            if flags & 0x02:  # SYN flag
                self.stats['syn_packets'] += 1
                
                # Track port scan activity
                scan_data = self.port_scan_tracking[src_ip]
                
                if scan_data['first_seen'] == 0:
                    scan_data['first_seen'] = timestamp
                
                scan_data['last_seen'] = timestamp
                scan_data['ports'].add(dst_port)
                scan_data['targets'].add(dst_ip)
                scan_data['syn_packets'] += 1
                
                # VERBOSE LOGGING (reduced)
                logger.info(f"🔍 [TCP SYN] {src_ip} → {dst_ip}:{dst_port}")
                
                # Check if this looks like a port scan
                time_window = timestamp - scan_data['first_seen']
                num_ports = len(scan_data['ports'])
                num_targets = len(scan_data['targets'])
                
                # STRICTER Port scan detection thresholds
                # Must scan UNUSUAL ports (not 80/443/53)
                unusual_ports = [p for p in scan_data['ports'] if p not in LEGITIMATE_PORTS]
                num_unusual_ports = len(unusual_ports)
                
                # Only flag if:
                # 1. 15+ UNUSUAL ports scanned
                # 2. Within 5 minutes
                # 3. From local network (not external)
                if (num_unusual_ports >= 15 and 
                    time_window < 300 and
                    src_ip.startswith(local_network_prefix)):
                    
                    # PORT SCAN DETECTED!
                    alert = {
                        'type': 'port_scan',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'target_ips': list(scan_data['targets']),
                        'ports_scanned': unusual_ports,
                        'port_count': num_unusual_ports,
                        'syn_count': scan_data['syn_packets'],
                        'duration': time_window,
                        'timestamp': timestamp,
                        'description': f'Port scan detected: {src_ip} scanned {num_unusual_ports} unusual ports on {num_targets} target(s)'
                    }
                    
                    # Check if we already alerted for this scan
                    already_alerted = False
                    for existing_alert in self.port_scan_alerts:
                        if (existing_alert['source_ip'] == src_ip and 
                            timestamp - existing_alert['timestamp'] < 300):
                            already_alerted = True
                            break
                    
                    if not already_alerted:
                        self.port_scan_alerts.append(alert)
                        self.stats['attacks_detected'] += 1
                        self.stats['port_scans_detected'] += 1
                        
                        logger.warning(f"🚨 [PORT SCAN DETECTED]")
                        logger.warning(f"   Source: {src_ip}")
                        logger.warning(f"   Targets: {list(scan_data['targets'])}")
                        logger.warning(f"   Unusual Ports: {num_unusual_ports} ports scanned")
                        logger.warning(f"   Duration: {time_window:.1f} seconds")
                        logger.warning(f"   Risk Score: HIGH")
                        
                        self._trigger_alert(alert)
                        
                        # Add to reconnaissance findings
                        from .. import state
                        recon_finding = {
                            'timestamp': timestamp,
                            'source_ip': src_ip,
                            'threat_type': 'port_scan',
                            'recon_score': min(100, num_unusual_ports * 3),
                            'indicators': [
                                f"Port scanning ({num_unusual_ports} unusual ports)",
                                f"Multiple targets ({num_targets} hosts)",
                                f"Rapid scanning ({time_window:.1f}s)"
                            ],
                            'details': alert
                        }
                        
                        if not hasattr(state, 'reconnaissance_findings'):
                            state.reconnaissance_findings = []
                        
                        state.reconnaissance_findings.insert(0, recon_finding)
                        logger.info(f"✅ Added to reconnaissance findings")
                
                # Cleanup old scan data (older than 10 minutes)
                if time_window > 600:
                    self.port_scan_tracking[src_ip] = {
                        'ports': set(),
                        'syn_packets': 0,
                        'first_seen': 0,
                        'last_seen': 0,
                        'targets': set()
                    }
        
        except Exception as e:
            logger.error(f"Error processing TCP packet: {e}")
    
    def _handle_dns_packet(self, packet):
        """Process DNS packet - detect DNS anomalies"""
        try:
            if not packet.haslayer(DNS) or not packet.haslayer(IP):
                return
            
            dns = packet[DNS]
            ip = packet[IP]
            
            # Only process DNS queries (not responses)
            if dns.qr != 0:  # qr=0 means query, qr=1 means response
                return
            
            src_ip = ip.src
            timestamp = time.time()
            
            # Process each DNS question
            if dns.qd:  # Query section exists
                for i in range(dns.qdcount):
                    try:
                        query = dns.qd[i] if isinstance(dns.qd, list) else dns.qd
                        
                        # Extract domain name
                        domain = query.qname.decode('utf-8', errors='ignore') if isinstance(query.qname, bytes) else str(query.qname)
                        domain = domain.strip('.')
                        
                        # Extract query type
                        qtype_num = query.qtype
                        qtype_map = {
                            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
                            12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
                            33: 'SRV', 255: 'ANY'
                        }
                        qtype = qtype_map.get(qtype_num, f'TYPE{qtype_num}')
                        
                        # Track DNS query
                        if DNS_ANOMALY_DETECTION_ENABLED:
                            dns_anomaly_detector.track_dns_query(
                                src_ip=src_ip,
                                domain=domain,
                                qtype=qtype,
                                timestamp=timestamp
                            )
                        
                        logger.debug(f"🔍 [DNS] {src_ip} → {domain} ({qtype})")
                    
                    except Exception as e:
                        logger.debug(f"Error parsing DNS query: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error processing DNS packet: {e}")
    
    def _packet_handler(self, packet):
        """Main packet handler"""
        self.stats['packets_processed'] += 1
        
        # Process ARP packets
        if packet.haslayer(ARP):
            self._handle_arp_packet(packet)
        
        # Process TCP packets (PORT SCAN + BRUTE FORCE DETECTION)
        if packet.haslayer(TCP):
            self._handle_tcp_packet(packet)
        
        # Process UDP packets (for DNS)
        if packet.haslayer(UDP):
            self.stats['udp_packets'] += 1
            
            # Process DNS packets
            if packet.haslayer(DNS):
                self._handle_dns_packet(packet)
        
        # Process WiFi packets
        if packet.haslayer(Dot11):
            self._handle_wifi_packet(packet)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - cannot start monitoring")
            return
        
        logger.info(f"Starting Scapy network monitor on interface: {self.interface or 'default'}")
        self.stats['started_at'] = time.time()
        
        try:
            # Sniff ARP, TCP, UDP (DNS), and WiFi packets
            # Filter: capture ARP packets OR TCP SYN packets OR UDP port 53 (DNS)
            sniff(
                iface=self.interface,
                filter="arp or (tcp[tcpflags] & tcp-syn != 0) or (udp port 53)",
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("❌ Permission denied - Scapy requires administrator/root privileges")
            logger.error("Run as: sudo python -m uvicorn backend.main:app (Linux) or Run as Administrator (Windows)")
        except Exception as e:
            logger.error(f"Scapy monitoring error: {e}")
        finally:
            logger.info("Scapy network monitor stopped")
    
    def start(self):
        """Start passive monitoring"""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available - passive monitoring disabled")
            return False
        
        if self.running:
            logger.warning("Scapy monitor already running")
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ScapyMonitor")
        self.thread.start()
        logger.info("✅ Scapy passive network monitor started")
        return True
    
    def stop(self):
        """Stop passive monitoring"""
        if not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Scapy monitor stopped")
    
    def get_discovered_devices(self) -> List[Dict[str, Any]]:
        """Get all discovered devices"""
        devices = []
        for ip, info in self.arp_table.items():
            devices.append({
                'ip': ip,
                'mac': info['mac'],
                'vendor': info['vendor'],
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'packet_count': info['count']
            })
        return devices
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get all detected attacks/alerts including brute force and DNS anomalies"""
        alerts = self.arp_spoof_alerts + self.port_scan_alerts
        
        # Add brute force alerts if available
        if BRUTE_FORCE_DETECTION_ENABLED:
            brute_force_alerts = brute_force_detector.get_alerts()
            alerts.extend(brute_force_alerts)
        
        # Add DNS anomaly alerts if available
        if DNS_ANOMALY_DETECTION_ENABLED:
            dns_alerts = dns_anomaly_detector.get_alerts()
            alerts.extend(dns_alerts)
        
        return alerts
    
    def get_brute_force_stats(self) -> Dict[str, Any]:
        """Get brute force detection statistics"""
        if BRUTE_FORCE_DETECTION_ENABLED:
            return brute_force_detector.get_stats()
        return {}
    
    def get_dns_anomaly_stats(self) -> Dict[str, Any]:
        """Get DNS anomaly detection statistics"""
        if DNS_ANOMALY_DETECTION_ENABLED:
            return dns_anomaly_detector.get_stats()
        return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        stats = self.stats.copy()
        if stats['started_at']:
            stats['uptime_seconds'] = time.time() - stats['started_at']
        return stats


# Global instance
scapy_monitor = ScapyNetworkMonitor()
