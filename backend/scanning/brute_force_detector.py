"""
Brute Force Attack Detection for AVIGHNA Defense
=================================================
Detects multiple failed login attempts across:
- SSH (port 22)
- RDP (port 3389)
- FTP (port 21)
- Telnet (port 23)
- HTTP/HTTPS web logins (ports 80, 443)
- SMB (port 445)
- MySQL (port 3306)
- PostgreSQL (port 5432)

NO FAKE DATA - Only real network traffic analysis
"""

import logging
import time
from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


class BruteForceDetector:
    """
    Detects brute force attacks by monitoring:
    1. Multiple connection attempts to authentication ports
    2. Rapid connection/disconnection patterns
    3. Failed authentication indicators (TCP RST after SYN-ACK)
    """
    
    # Authentication service ports
    AUTH_PORTS = {
        22: 'SSH',
        23: 'Telnet',
        21: 'FTP',
        3389: 'RDP',
        445: 'SMB',
        139: 'NetBIOS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        1433: 'MSSQL',
        5900: 'VNC',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    
    def __init__(self):
        # Track connection attempts per source IP
        self.connection_attempts: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'attempts': [],  # List of (timestamp, dst_ip, dst_port, service)
            'failed_count': 0,
            'success_count': 0,
            'first_seen': 0,
            'last_seen': 0,
            'targeted_services': set(),
            'targeted_hosts': set()
        })
        
        # Track failed authentication patterns
        self.failed_auth_patterns: Dict[str, List[float]] = defaultdict(list)  # src_ip -> [timestamps]
        
        # Detected brute force attacks
        self.brute_force_alerts: List[Dict[str, Any]] = []
        
        # Statistics
        self.stats = {
            'total_auth_attempts': 0,
            'failed_auth_attempts': 0,
            'brute_force_detected': 0,
            'unique_attackers': 0
        }
    
    def track_connection_attempt(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        flags: int,
        timestamp: Optional[float] = None
    ):
        """
        Track connection attempt to authentication service
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            flags: TCP flags (SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01)
            timestamp: Timestamp (defaults to current time)
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Only track authentication ports
        if dst_port not in self.AUTH_PORTS:
            return
        
        service = self.AUTH_PORTS[dst_port]
        
        # Get tracking data for this source IP
        data = self.connection_attempts[src_ip]
        
        if data['first_seen'] == 0:
            data['first_seen'] = timestamp
        
        data['last_seen'] = timestamp
        data['targeted_services'].add(service)
        data['targeted_hosts'].add(dst_ip)
        
        # Track attempt
        data['attempts'].append((timestamp, dst_ip, dst_port, service))
        self.stats['total_auth_attempts'] += 1
        
        # Detect failed authentication patterns
        # RST flag after connection attempt indicates failure
        if flags & 0x04:  # RST flag
            data['failed_count'] += 1
            self.failed_auth_patterns[src_ip].append(timestamp)
            self.stats['failed_auth_attempts'] += 1
            
            logger.debug(f"Failed auth attempt: {src_ip} → {dst_ip}:{dst_port} ({service})")
        
        # Analyze for brute force patterns
        self._analyze_brute_force(src_ip, timestamp)
        
        # Cleanup old attempts (older than 10 minutes)
        cutoff = timestamp - 600
        data['attempts'] = [(t, ip, port, svc) for t, ip, port, svc in data['attempts'] if t > cutoff]
        self.failed_auth_patterns[src_ip] = [t for t in self.failed_auth_patterns[src_ip] if t > cutoff]
    
    def _analyze_brute_force(self, src_ip: str, current_time: float):
        """
        Analyze connection patterns to detect brute force attacks
        
        Brute force indicators:
        1. Multiple failed authentication attempts (5+ in 5 minutes)
        2. Rapid connection attempts (10+ in 1 minute)
        3. Multiple services targeted (credential stuffing)
        4. Multiple hosts targeted (lateral movement)
        """
        data = self.connection_attempts[src_ip]
        
        # Need minimum attempts to analyze
        if len(data['attempts']) < 5:
            return
        
        # Time window analysis (last 5 minutes)
        time_window = 300  # 5 minutes
        recent_cutoff = current_time - time_window
        
        recent_attempts = [a for a in data['attempts'] if a[0] > recent_cutoff]
        recent_failed = [t for t in self.failed_auth_patterns[src_ip] if t > recent_cutoff]
        
        num_recent_attempts = len(recent_attempts)
        num_recent_failed = len(recent_failed)
        
        # Calculate attempt rate
        if recent_attempts:
            time_span = current_time - recent_attempts[0][0]
            attempt_rate = num_recent_attempts / max(time_span, 1)  # attempts per second
        else:
            attempt_rate = 0
        
        # BRUTE FORCE DETECTION THRESHOLDS
        is_brute_force = False
        severity = 'MEDIUM'
        indicators = []
        confidence = 0
        
        # Indicator 1: Multiple failed attempts
        if num_recent_failed >= 5:
            is_brute_force = True
            indicators.append(f"{num_recent_failed} failed authentication attempts")
            confidence += 30
            severity = 'HIGH'
        
        # Indicator 2: Rapid connection attempts
        if attempt_rate > 0.5:  # More than 1 attempt every 2 seconds
            is_brute_force = True
            indicators.append(f"Rapid attempts ({attempt_rate:.1f}/sec)")
            confidence += 20
        
        # Indicator 3: Multiple services targeted (credential stuffing)
        if len(data['targeted_services']) >= 3:
            is_brute_force = True
            indicators.append(f"Multiple services targeted ({len(data['targeted_services'])})")
            confidence += 25
            severity = 'CRITICAL'
        
        # Indicator 4: Multiple hosts targeted (lateral movement)
        if len(data['targeted_hosts']) >= 2:
            indicators.append(f"Multiple hosts targeted ({len(data['targeted_hosts'])})")
            confidence += 15
        
        # Indicator 5: High failure rate
        if num_recent_attempts > 0:
            failure_rate = num_recent_failed / num_recent_attempts
            if failure_rate > 0.7:  # 70%+ failure rate
                indicators.append(f"High failure rate ({failure_rate*100:.0f}%)")
                confidence += 10
        
        # Trigger alert if brute force detected
        if is_brute_force and confidence >= 40:
            # Check if we already alerted for this attacker recently
            already_alerted = False
            for alert in self.brute_force_alerts:
                if (alert['source_ip'] == src_ip and 
                    current_time - alert['timestamp'] < 300):  # 5 minutes
                    already_alerted = True
                    break
            
            if not already_alerted:
                alert = {
                    'type': 'brute_force',
                    'severity': severity,
                    'source_ip': src_ip,
                    'target_hosts': list(data['targeted_hosts']),
                    'target_services': list(data['targeted_services']),
                    'total_attempts': num_recent_attempts,
                    'failed_attempts': num_recent_failed,
                    'attempt_rate': attempt_rate,
                    'confidence': confidence,
                    'indicators': indicators,
                    'timestamp': current_time,
                    'duration': current_time - data['first_seen'],
                    'description': f"Brute force attack detected from {src_ip}"
                }
                
                self.brute_force_alerts.append(alert)
                self.stats['brute_force_detected'] += 1
                self.stats['unique_attackers'] = len(set(a['source_ip'] for a in self.brute_force_alerts))
                
                logger.warning(f"🚨 [BRUTE FORCE DETECTED]")
                logger.warning(f"   Source: {src_ip}")
                logger.warning(f"   Targets: {list(data['targeted_hosts'])}")
                logger.warning(f"   Services: {list(data['targeted_services'])}")
                logger.warning(f"   Attempts: {num_recent_attempts} ({num_recent_failed} failed)")
                logger.warning(f"   Confidence: {confidence}%")
                logger.warning(f"   Severity: {severity}")
                logger.warning(f"   Indicators: {', '.join(indicators)}")
                
                # Add to reconnaissance findings
                try:
                    from .. import state
                    recon_finding = {
                        'timestamp': current_time,
                        'source_ip': src_ip,
                        'threat_type': 'brute_force',
                        'recon_score': min(100, confidence),
                        'indicators': indicators,
                        'details': alert
                    }
                    
                    if not hasattr(state, 'reconnaissance_findings'):
                        state.reconnaissance_findings = []
                    
                    state.reconnaissance_findings.insert(0, recon_finding)
                    logger.info(f"✅ Added brute force attack to reconnaissance findings")
                except Exception as e:
                    logger.error(f"Failed to add to reconnaissance findings: {e}")
    
    def get_alerts(self, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Get brute force alerts
        
        Args:
            since: Only return alerts after this timestamp (optional)
        
        Returns:
            List of alert dictionaries
        """
        if since is None:
            return self.brute_force_alerts
        
        return [a for a in self.brute_force_alerts if a['timestamp'] > since]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return self.stats.copy()
    
    def get_attacker_profile(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed profile of an attacker
        
        Args:
            src_ip: Source IP address
        
        Returns:
            Attacker profile dictionary or None
        """
        if src_ip not in self.connection_attempts:
            return None
        
        data = self.connection_attempts[src_ip]
        
        return {
            'source_ip': src_ip,
            'total_attempts': len(data['attempts']),
            'failed_attempts': data['failed_count'],
            'success_attempts': data['success_count'],
            'targeted_services': list(data['targeted_services']),
            'targeted_hosts': list(data['targeted_hosts']),
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'duration': data['last_seen'] - data['first_seen'] if data['first_seen'] > 0 else 0
        }
    
    def cleanup_old_data(self, max_age: int = 3600):
        """
        Cleanup tracking data older than max_age seconds
        
        Args:
            max_age: Maximum age in seconds (default: 1 hour)
        """
        current_time = time.time()
        cutoff = current_time - max_age
        
        # Cleanup connection attempts
        ips_to_remove = []
        for src_ip, data in self.connection_attempts.items():
            if data['last_seen'] < cutoff:
                ips_to_remove.append(src_ip)
        
        for ip in ips_to_remove:
            del self.connection_attempts[ip]
            if ip in self.failed_auth_patterns:
                del self.failed_auth_patterns[ip]
        
        # Cleanup old alerts (keep last 24 hours)
        alert_cutoff = current_time - 86400
        self.brute_force_alerts = [a for a in self.brute_force_alerts if a['timestamp'] > alert_cutoff]
        
        if ips_to_remove:
            logger.debug(f"Cleaned up {len(ips_to_remove)} old brute force tracking entries")


# Global instance
brute_force_detector = BruteForceDetector()
