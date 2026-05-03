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
    from scapy.all import sniff, ARP, Dot11, Dot11ProbeReq, get_if_list, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - passive monitoring disabled")

logger = logging.getLogger(__name__)


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
            'syn_packets': 0,
            'probe_requests': 0,
            'devices_discovered': 0,
            'attacks_detected': 0,
            'port_scans_detected': 0,
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
    
    def _handle_tcp_packet(self, packet):
        """Process TCP packet - detect port scanning"""
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
                
                # VERBOSE LOGGING
                logger.info(f"🔍 [TCP SYN] {src_ip} → {dst_ip}:{dst_port}")
                
                # Check if this looks like a port scan
                time_window = timestamp - scan_data['first_seen']
                num_ports = len(scan_data['ports'])
                num_targets = len(scan_data['targets'])
                
                # Port scan detection thresholds
                if num_ports >= 20 and time_window < 300:  # 20+ ports in 5 minutes
                    # PORT SCAN DETECTED!
                    alert = {
                        'type': 'port_scan',
                        'severity': 'HIGH',
                        'source_ip': src_ip,
                        'target_ips': list(scan_data['targets']),
                        'ports_scanned': list(scan_data['ports']),
                        'port_count': num_ports,
                        'syn_count': scan_data['syn_packets'],
                        'duration': time_window,
                        'timestamp': timestamp,
                        'description': f'Port scan detected: {src_ip} scanned {num_ports} ports on {num_targets} target(s)'
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
                        logger.warning(f"   Ports: {num_ports} ports scanned")
                        logger.warning(f"   Duration: {time_window:.1f} seconds")
                        logger.warning(f"   Risk Score: HIGH")
                        
                        self._trigger_alert(alert)
                        
                        # Add to reconnaissance findings
                        from .. import state
                        recon_finding = {
                            'timestamp': timestamp,
                            'source_ip': src_ip,
                            'threat_type': 'port_scan',
                            'recon_score': min(100, num_ports * 2),
                            'indicators': [
                                f"Port scanning ({num_ports} ports)",
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
    
    def _packet_handler(self, packet):
        """Main packet handler"""
        self.stats['packets_processed'] += 1
        
        # Process ARP packets
        if packet.haslayer(ARP):
            self._handle_arp_packet(packet)
        
        # Process TCP packets (PORT SCAN DETECTION)
        if packet.haslayer(TCP):
            self._handle_tcp_packet(packet)
        
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
            # Sniff ARP and TCP packets
            # Filter: capture ARP packets OR TCP SYN packets (port scans)
            sniff(
                iface=self.interface,
                filter="arp or (tcp[tcpflags] & tcp-syn != 0)",
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
        """Get all detected attacks/alerts"""
        return self.arp_spoof_alerts + self.port_scan_alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        stats = self.stats.copy()
        if stats['started_at']:
            stats['uptime_seconds'] = time.time() - stats['started_at']
        return stats


# Global instance
scapy_monitor = ScapyNetworkMonitor()
