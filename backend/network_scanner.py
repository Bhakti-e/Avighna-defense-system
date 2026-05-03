"""
Network Scanner for AVIGHNA
============================
Discovers all devices on local network (agent + non-agent devices)
Detects rogue/unauthorized devices automatically

Features:
- ARP-based network scanning (fast)
- Device fingerprinting (OS, vendor detection)
- Whitelist/blacklist management
- Auto-blocking of rogue devices
"""

import time
import subprocess
import re
import logging
import threading
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    Active network scanner that discovers all devices on local network
    Runs periodically to detect new/rogue devices
    """
    
    def __init__(self, network_cidr: str = "192.168.1.0/24", scan_interval: int = 60):
        self.network_cidr = network_cidr
        self.scan_interval = scan_interval
        self.running = False
        self.thread = None
        
        # Device tracking
        self.known_devices = {}  # MAC -> device info
        self.authorized_macs = set()  # Whitelist
        self.blocked_macs = set()  # Blacklist
        
        # Statistics
        self.scan_count = 0
        self.rogue_detected_count = 0
        self.last_scan_time = 0
        
    def start(self):
        """Start background scanning"""
        if self.running:
            logger.warning("Network scanner already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.thread.start()
        logger.info(f"Network scanner started - scanning {self.network_cidr} every {self.scan_interval}s")
        
    def stop(self):
        """Stop background scanning"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Network scanner stopped")
        
    def _scan_loop(self):
        """Main scanning loop"""
        while self.running:
            try:
                self._perform_scan()
                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Network scan error: {e}")
                time.sleep(self.scan_interval)
                
    def _perform_scan(self):
        """Perform network scan and detect rogue devices"""
        try:
            self.scan_count += 1
            self.last_scan_time = time.time()
            
            logger.info(f"Starting network scan #{self.scan_count}...")
            
            # Scan network using ARP
            devices = self._scan_arp()
            
            logger.info(f"Found {len(devices)} device(s) on network")
            
            # Update device inventory
            for device in devices:
                self._update_device(device)
            
            # Detect rogue devices
            rogue_devices = self._detect_rogue_devices(devices)
            
            if rogue_devices:
                logger.warning(f"ROGUE DEVICES DETECTED: {len(rogue_devices)}")
                for rogue in rogue_devices:
                    self._handle_rogue_device(rogue)
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            
    def _scan_arp(self) -> List[Dict[str, Any]]:
        """
        Scan network using ARP (works on Windows/Linux/Mac)
        Returns list of devices: [{"ip": "...", "mac": "...", "vendor": "..."}]
        """
        devices = []
        
        try:
            # Use arp command (available on all platforms)
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error(f"ARP command failed: {result.stderr}")
                return devices
            
            # Parse ARP output
            # Windows format: 192.168.1.1    aa-bb-cc-dd-ee-ff     dynamic
            # Linux format:   192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Extract IP address
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if not ip_match:
                    continue
                ip = ip_match.group(1)
                
                # Skip localhost and broadcast
                if ip.startswith('127.') or ip.endswith('.255') or ip == '0.0.0.0':
                    continue
                
                # Extract MAC address (both formats: aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff)
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                if not mac_match:
                    continue
                mac = mac_match.group(0).upper().replace('-', ':')
                
                # Get vendor from MAC OUI (first 3 octets)
                vendor = self._get_vendor_from_mac(mac)
                
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'timestamp': time.time(),
                    'scan_method': 'arp'
                })
            
            logger.debug(f"ARP scan found {len(devices)} devices")
            
        except subprocess.TimeoutExpired:
            logger.error("ARP scan timeout")
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
        
        return devices
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """
        Get vendor name from MAC address OUI (Organizationally Unique Identifier)
        First 3 octets identify manufacturer
        """
        # Common vendor OUI prefixes (simplified list)
        oui_map = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:05:69': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:1B:44': 'Cisco',
            '00:1C:0E': 'Cisco',
            '00:50:F2': 'Microsoft',
            '00:15:5D': 'Microsoft',
            '3C:5A:B4': 'Google',
            '54:60:09': 'Google',
            'AC:DE:48': 'Apple',
            '00:03:93': 'Apple',
            '00:1C:B3': 'Apple',
            '28:6A:BA': 'Apple',
            '40:6C:8F': 'Apple',
            '00:1A:11': 'Google',
            '00:1E:C2': 'Apple',
            '00:26:BB': 'Apple',
            '00:50:C2': 'IEEE 802.11',
            '02:00:00': 'Xerox',
        }
        
        # Get first 3 octets
        oui = ':'.join(mac.split(':')[:3])
        
        return oui_map.get(oui, 'Unknown')
    
    def _update_device(self, device: Dict[str, Any]):
        """Update device in known devices registry"""
        mac = device['mac']
        
        if mac in self.known_devices:
            # Update existing device
            self.known_devices[mac]['last_seen'] = device['timestamp']
            self.known_devices[mac]['ip'] = device['ip']
            self.known_devices[mac]['connection_count'] = self.known_devices[mac].get('connection_count', 0) + 1
        else:
            # New device discovered
            self.known_devices[mac] = {
                'mac': mac,
                'ip': device['ip'],
                'vendor': device['vendor'],
                'first_seen': device['timestamp'],
                'last_seen': device['timestamp'],
                'connection_count': 1,
                'is_authorized': False,
                'is_blocked': False
            }
            logger.info(f"NEW DEVICE: {mac} ({device['ip']}) - {device['vendor']}")
    
    def _detect_rogue_devices(self, current_devices: List[Dict]) -> List[Dict]:
        """
        Detect unauthorized devices
        Returns list of rogue devices
        """
        rogue_devices = []
        
        for device in current_devices:
            mac = device['mac']
            
            # Skip if already blocked
            if mac in self.blocked_macs:
                continue
            
            # Check if authorized
            if mac not in self.authorized_macs:
                # Not in whitelist = rogue device
                rogue_devices.append({
                    **device,
                    'threat_type': 'rogue_device',
                    'reason': 'Unauthorized device on network (not in whitelist)',
                    'risk_score': 80.0
                })
                
                self.rogue_detected_count += 1
        
        return rogue_devices
    
    def _handle_rogue_device(self, rogue: Dict[str, Any]):
        """Handle detected rogue device"""
        mac = rogue['mac']
        ip = rogue['ip']
        
        logger.warning(f"ROGUE DEVICE: {mac} ({ip}) - {rogue['vendor']}")
        logger.warning(f"Reason: {rogue['reason']}")
        
        # Mark as blocked
        self.blocked_macs.add(mac)
        
        # Update device info
        if mac in self.known_devices:
            self.known_devices[mac]['is_blocked'] = True
            self.known_devices[mac]['block_reason'] = rogue['reason']
            self.known_devices[mac]['blocked_at'] = time.time()
        
        # TODO: Trigger alert in main system
        # TODO: Auto-block at router level (if enabled)
        # TODO: Block at gateway level (iptables)
    
    def authorize_device(self, mac: str):
        """Add device to whitelist"""
        mac = mac.upper().replace('-', ':')
        self.authorized_macs.add(mac)
        
        if mac in self.known_devices:
            self.known_devices[mac]['is_authorized'] = True
            self.known_devices[mac]['authorized_at'] = time.time()
        
        logger.info(f"Device authorized: {mac}")
    
    def unauthorize_device(self, mac: str):
        """Remove device from whitelist"""
        mac = mac.upper().replace('-', ':')
        self.authorized_macs.discard(mac)
        
        if mac in self.known_devices:
            self.known_devices[mac]['is_authorized'] = False
        
        logger.info(f"Device unauthorized: {mac}")
    
    def block_device(self, mac: str, reason: str = "Manual block"):
        """Add device to blacklist"""
        mac = mac.upper().replace('-', ':')
        self.blocked_macs.add(mac)
        
        if mac in self.known_devices:
            self.known_devices[mac]['is_blocked'] = True
            self.known_devices[mac]['block_reason'] = reason
            self.known_devices[mac]['blocked_at'] = time.time()
        
        logger.info(f"Device blocked: {mac} - {reason}")
    
    def unblock_device(self, mac: str):
        """Remove device from blacklist"""
        mac = mac.upper().replace('-', ':')
        self.blocked_macs.discard(mac)
        
        if mac in self.known_devices:
            self.known_devices[mac]['is_blocked'] = False
        
        logger.info(f"Device unblocked: {mac}")
    
    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get list of all known devices"""
        return list(self.known_devices.values())
    
    def get_rogue_devices(self) -> List[Dict[str, Any]]:
        """Get list of rogue (unauthorized) devices"""
        return [
            device for device in self.known_devices.values()
            if not device.get('is_authorized', False) and not device.get('is_blocked', False)
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return {
            'scan_count': self.scan_count,
            'last_scan_time': self.last_scan_time,
            'total_devices': len(self.known_devices),
            'authorized_devices': len(self.authorized_macs),
            'blocked_devices': len(self.blocked_macs),
            'rogue_detected_count': self.rogue_detected_count,
            'is_running': self.running
        }

# Global scanner instance
network_scanner = NetworkScanner()
