"""
Active Network Scanner for DOME
===============================
Background task that periodically inspects network connections from the backend machine
Detects port scanning patterns, lateral movement, and reconnaissance activities
Feeds recon_score into the risk engine for proactive threat detection
"""

import time
import subprocess
import re
import threading
import logging
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict
from .. import state

logger = logging.getLogger(__name__)

class ActiveNetworkScanner:
    """
    Background scanner that monitors network activity from the backend machine
    Detects reconnaissance patterns and lateral movement attempts
    """
    
    def __init__(self, scan_interval=30):
        self.scan_interval = scan_interval
        self.running = False
        self.thread = None
        
        # Get local IP to exclude from recon detection
        import socket
        try:
            self.local_ip = socket.gethostbyname(socket.gethostname())
        except:
            self.local_ip = "127.0.0.1"
        
        # Track network activity patterns
        self.connection_history = defaultdict(list)  # ip -> [(timestamp, port, status)]
        self.arp_history = defaultdict(list)         # ip -> [(timestamp, mac)]
        self.scan_patterns = defaultdict(dict)       # ip -> pattern analysis
        
        # Reconnaissance scoring thresholds
        self.PORT_SCAN_THRESHOLD = 10    # ports scanned to same IP
        self.TIME_WINDOW = 300           # 5 minutes
        self.LATERAL_MOVEMENT_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}
        
    def start(self):
        """Start the background scanner"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.thread.start()
        logger.info("Active network scanner started")
        
    def stop(self):
        """Stop the background scanner"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Active network scanner stopped")
        
    def _scan_loop(self):
        """Main scanning loop"""
        while self.running:
            try:
                self._scan_network_connections()
                self._scan_arp_table()
                self._analyze_patterns()
                self._update_recon_findings()
                
                time.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"Active scanner error: {e}")
                time.sleep(self.scan_interval)
                
    def _scan_network_connections(self):
        """Scan current network connections using netstat"""
        try:
            # Use netstat to get current connections
            if hasattr(subprocess, 'run'):
                result = subprocess.run(['netstat', '-an'], 
                                      capture_output=True, text=True, timeout=10)
            else:
                # Fallback for older Python
                result = subprocess.Popen(['netstat', '-an'], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE)
                stdout, stderr = result.communicate()
                result.stdout = stdout.decode() if stdout else ""
                result.returncode = result.returncode or 0
                
            if result.returncode != 0:
                return
                
            current_time = time.time()
            
            # Parse netstat output
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or 'ESTABLISHED' not in line:
                    continue
                    
                # Extract IP and port information
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if match:
                    ip = match.group(1)
                    port = int(match.group(2))
                    
                    # Skip localhost and local machine IP
                    if ip.startswith(('127.', '0.0.0.0', '::1')) or ip == self.local_ip:
                        continue
                        
                    # Record connection
                    self.connection_history[ip].append((current_time, port, 'ESTABLISHED'))
                    
                    # Keep only recent history
                    cutoff = current_time - self.TIME_WINDOW
                    self.connection_history[ip] = [
                        (ts, p, s) for ts, p, s in self.connection_history[ip] 
                        if ts > cutoff
                    ]
                    
        except Exception as e:
            logger.warning(f"Failed to scan network connections: {e}")
            
    def _scan_arp_table(self):
        """Scan ARP table for network topology changes"""
        try:
            # Use arp command to get ARP table
            if hasattr(subprocess, 'run'):
                result = subprocess.run(['arp', '-a'], 
                                      capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.Popen(['arp', '-a'], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE)
                stdout, stderr = result.communicate()
                result.stdout = stdout.decode() if stdout else ""
                result.returncode = result.returncode or 0
                
            if result.returncode != 0:
                return
                
            current_time = time.time()
            
            # Parse ARP output
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                # Extract IP and MAC
                # Format: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(0)
                    
                    # Record ARP entry
                    self.arp_history[ip].append((current_time, mac))
                    
                    # Keep only recent history
                    cutoff = current_time - self.TIME_WINDOW
                    self.arp_history[ip] = [
                        (ts, m) for ts, m in self.arp_history[ip] 
                        if ts > cutoff
                    ]
                    
        except Exception as e:
            logger.warning(f"Failed to scan ARP table: {e}")
            
    def _analyze_patterns(self):
        """Analyze connection patterns for reconnaissance indicators"""
        current_time = time.time()
        cutoff = current_time - self.TIME_WINDOW
        
        for ip, connections in self.connection_history.items():
            if not connections:
                continue
            
            # Skip local machine - don't analyze own traffic
            if ip == self.local_ip or ip.startswith('127.'):
                continue
                
            # Filter to recent connections
            recent_connections = [(ts, port, status) for ts, port, status in connections if ts > cutoff]
            
            if len(recent_connections) < 3:  # Need minimum activity for analysis
                continue
                
            # Analyze for port scanning
            unique_ports = set(port for _, port, _ in recent_connections)
            port_scan_score = 0.0
            
            # Require MORE ports to trigger alert (reduce false positives)
            if len(unique_ports) >= 20:  # Increased from 10 to 20
                port_scan_score = min(50.0, len(unique_ports) * 2.0)
                
            # Analyze for lateral movement
            lateral_movement_score = 0.0
            lateral_ports = unique_ports.intersection(self.LATERAL_MOVEMENT_PORTS)
            if lateral_ports:
                lateral_movement_score = min(30.0, len(lateral_ports) * 10.0)
                
            # Analyze connection frequency
            time_span = max(1, recent_connections[-1][0] - recent_connections[0][0])
            connection_rate = len(recent_connections) / time_span
            
            rapid_connection_score = 0.0
            # Require MUCH higher rate to trigger (reduce false positives from normal browsing)
            if connection_rate > 2.0:  # Increased from 0.5 to 2.0 (more than 2 connections/sec)
                rapid_connection_score = min(25.0, connection_rate * 10.0)
                
            # Calculate total recon score for this IP
            total_recon_score = port_scan_score + lateral_movement_score + rapid_connection_score
            
            # Store pattern analysis
            self.scan_patterns[ip] = {
                'timestamp': current_time,
                'port_scan_score': port_scan_score,
                'lateral_movement_score': lateral_movement_score,
                'rapid_connection_score': rapid_connection_score,
                'total_recon_score': total_recon_score,
                'unique_ports': len(unique_ports),
                'lateral_ports': list(lateral_ports),
                'connection_rate': connection_rate,
                'recent_connections': len(recent_connections)
            }
            
    def _update_recon_findings(self):
        """Update global reconnaissance findings for dashboard display"""
        current_time = time.time()
        
        # Clear old findings
        state.reconnaissance_findings = [
            finding for finding in state.reconnaissance_findings 
            if current_time - finding.get('timestamp', 0) < 3600  # Keep 1 hour
        ]
        
        # Add new findings from pattern analysis
        for ip, pattern in self.scan_patterns.items():
            if pattern['total_recon_score'] > 10.0:  # Threshold for reporting
                
                # Check if we already have a recent finding for this IP
                existing = False
                for finding in state.reconnaissance_findings:
                    if (finding.get('source_ip') == ip and 
                        current_time - finding.get('timestamp', 0) < 300):  # 5 minutes
                        existing = True
                        break
                        
                if not existing:
                    finding = {
                        'timestamp': current_time,
                        'source_ip': ip,
                        'threat_type': 'reconnaissance',
                        'recon_score': pattern['total_recon_score'],
                        'indicators': [],
                        'details': pattern
                    }
                    
                    # Add specific indicators
                    if pattern['port_scan_score'] > 0:
                        finding['indicators'].append(f"Port scanning ({pattern['unique_ports']} ports)")
                    if pattern['lateral_movement_score'] > 0:
                        finding['indicators'].append(f"Lateral movement ({len(pattern['lateral_ports'])} admin ports)")
                    if pattern['rapid_connection_score'] > 0:
                        finding['indicators'].append(f"Rapid connections ({pattern['connection_rate']:.1f}/sec)")
                        
                    state.reconnaissance_findings.append(finding)
                    logger.info(f"New reconnaissance activity detected from {ip}: {finding['indicators']}")
                    
    def get_recon_score_for_ip(self, ip: str) -> float:
        """Get current reconnaissance score for a specific IP"""
        pattern = self.scan_patterns.get(ip, {})
        return pattern.get('total_recon_score', 0.0)
        
    def get_all_recon_scores(self) -> Dict[str, float]:
        """Get reconnaissance scores for all monitored IPs"""
        return {ip: pattern.get('total_recon_score', 0.0) 
                for ip, pattern in self.scan_patterns.items()}

# Global scanner instance
active_scanner = ActiveNetworkScanner()