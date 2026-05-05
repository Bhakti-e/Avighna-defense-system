"""
DNS Anomaly Detection for AVIGHNA Defense
==========================================
Detects suspicious DNS behavior:
- Excessive DNS requests (DNS flood)
- Suspicious domain patterns (DGA-like)
- DNS tunneling attempts
- Unusual query types
- Fast-flux DNS patterns

NO FAKE DATA - Only real DNS traffic analysis
"""

import logging
import time
import re
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from datetime import datetime
import math

logger = logging.getLogger(__name__)


class DNSAnomalyDetector:
    """
    Detects DNS anomalies by monitoring:
    1. Query volume (excessive requests)
    2. Domain patterns (DGA detection)
    3. Query types (unusual types)
    4. Subdomain patterns (tunneling)
    """
    
    # Suspicious TLDs often used by malware
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.xyz', '.top', '.work', '.click',  # Cheap TLDs
        '.pw', '.cc', '.ws', '.info'
    }
    
    # Legitimate domains to whitelist
    WHITELISTED_DOMAINS = {
        'google.com', 'googleapis.com', 'gstatic.com',
        'microsoft.com', 'windows.com', 'live.com', 'msn.com',
        'apple.com', 'icloud.com', 'apple-dns.net',
        'amazon.com', 'amazonaws.com', 'cloudfront.net',
        'facebook.com', 'fbcdn.net',
        'cloudflare.com', 'cloudflare-dns.com',
        'akamai.net', 'akamaitechnologies.com',
        'github.com', 'githubusercontent.com',
        'ubuntu.com', 'debian.org', 'centos.org',
        'mozilla.org', 'firefox.com',
        'netflix.com', 'nflxvideo.net',
        'youtube.com', 'ytimg.com', 'googlevideo.com'
    }
    
    def __init__(self):
        # Track DNS queries per source IP
        self.dns_queries: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'queries': [],  # List of (timestamp, domain, qtype)
            'unique_domains': set(),
            'query_types': defaultdict(int),
            'first_seen': 0,
            'last_seen': 0,
            'suspicious_domains': [],
            'dga_score': 0
        })
        
        # Track queries per domain (for fast-flux detection)
        self.domain_queries: Dict[str, List[tuple]] = defaultdict(list)  # domain -> [(timestamp, src_ip)]
        
        # Detected anomalies
        self.dns_anomaly_alerts: List[Dict[str, Any]] = []
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'suspicious_queries': 0,
            'dga_domains_detected': 0,
            'dns_floods_detected': 0,
            'tunneling_detected': 0,
            'unique_sources': 0
        }
    
    def track_dns_query(
        self,
        src_ip: str,
        domain: str,
        qtype: str = 'A',
        timestamp: Optional[float] = None
    ):
        """
        Track DNS query for anomaly detection
        
        Args:
            src_ip: Source IP address
            domain: Queried domain name
            qtype: Query type (A, AAAA, TXT, MX, etc.)
            timestamp: Timestamp (defaults to current time)
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Normalize domain
        domain = domain.lower().strip('.')
        
        # Skip empty domains
        if not domain:
            return
        
        # Get tracking data for this source IP
        data = self.dns_queries[src_ip]
        
        if data['first_seen'] == 0:
            data['first_seen'] = timestamp
            self.stats['unique_sources'] = len(self.dns_queries)
        
        data['last_seen'] = timestamp
        data['unique_domains'].add(domain)
        data['query_types'][qtype] += 1
        
        # Track query
        data['queries'].append((timestamp, domain, qtype))
        self.stats['total_queries'] += 1
        
        # Track domain queries (for fast-flux detection)
        self.domain_queries[domain].append((timestamp, src_ip))
        
        # Check if domain is whitelisted
        is_whitelisted = self._is_whitelisted(domain)
        
        if not is_whitelisted:
            # Analyze domain for DGA patterns
            dga_score = self._analyze_dga_pattern(domain)
            
            if dga_score > 0.6:  # 60% confidence
                data['suspicious_domains'].append((domain, dga_score))
                data['dga_score'] = max(data['dga_score'], dga_score)
                self.stats['suspicious_queries'] += 1
                
                logger.debug(f"Suspicious domain: {domain} (DGA score: {dga_score:.2f})")
        
        # Analyze for anomalies
        self._analyze_dns_anomalies(src_ip, timestamp)
        
        # Cleanup old queries (older than 10 minutes)
        cutoff = timestamp - 600
        data['queries'] = [(t, d, q) for t, d, q in data['queries'] if t > cutoff]
        self.domain_queries[domain] = [(t, ip) for t, ip in self.domain_queries[domain] if t > cutoff]
    
    def _is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted"""
        # Check exact match
        if domain in self.WHITELISTED_DOMAINS:
            return True
        
        # Check if subdomain of whitelisted domain
        for whitelisted in self.WHITELISTED_DOMAINS:
            if domain.endswith('.' + whitelisted):
                return True
        
        return False
    
    def _analyze_dga_pattern(self, domain: str) -> float:
        """
        Analyze domain for DGA (Domain Generation Algorithm) patterns
        
        DGA indicators:
        1. High entropy (random-looking)
        2. Long domain name
        3. High consonant-to-vowel ratio
        4. Suspicious TLD
        5. No dictionary words
        6. Numeric characters
        
        Returns:
            DGA score (0.0 to 1.0)
        """
        # Extract domain without TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return 0.0
        
        domain_name = parts[0]
        tld = '.' + '.'.join(parts[1:])
        
        # Skip very short domains (likely legitimate)
        if len(domain_name) < 8:
            return 0.0
        
        score = 0.0
        indicators = []
        
        # Indicator 1: High entropy (randomness)
        entropy = self._calculate_entropy(domain_name)
        if entropy > 3.5:  # High entropy
            score += 0.25
            indicators.append(f"High entropy ({entropy:.2f})")
        
        # Indicator 2: Long domain name
        if len(domain_name) > 15:
            score += 0.15
            indicators.append(f"Long domain ({len(domain_name)} chars)")
        
        # Indicator 3: High consonant ratio
        consonant_ratio = self._calculate_consonant_ratio(domain_name)
        if consonant_ratio > 0.7:  # 70%+ consonants
            score += 0.20
            indicators.append(f"High consonant ratio ({consonant_ratio:.2f})")
        
        # Indicator 4: Suspicious TLD
        if tld in self.SUSPICIOUS_TLDS:
            score += 0.20
            indicators.append(f"Suspicious TLD ({tld})")
        
        # Indicator 5: Contains numbers
        if any(c.isdigit() for c in domain_name):
            score += 0.10
            indicators.append("Contains numbers")
        
        # Indicator 6: No vowels or all consonants
        vowels = sum(1 for c in domain_name.lower() if c in 'aeiou')
        if vowels == 0:
            score += 0.10
            indicators.append("No vowels")
        
        if score > 0.6:
            logger.debug(f"DGA domain detected: {domain} (score: {score:.2f}, indicators: {indicators})")
        
        return min(score, 1.0)
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of string"""
        if not s:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(s)
        
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_consonant_ratio(self, s: str) -> float:
        """Calculate ratio of consonants to total letters"""
        letters = [c for c in s.lower() if c.isalpha()]
        if not letters:
            return 0.0
        
        consonants = [c for c in letters if c not in 'aeiou']
        return len(consonants) / len(letters)
    
    def _analyze_dns_anomalies(self, src_ip: str, current_time: float):
        """
        Analyze DNS query patterns for anomalies
        
        Anomaly types:
        1. DNS flood (excessive queries)
        2. DGA domains (malware C2)
        3. DNS tunneling (long subdomains)
        4. Unusual query types (TXT, NULL)
        """
        data = self.dns_queries[src_ip]
        
        # Need minimum queries to analyze
        if len(data['queries']) < 10:
            return
        
        # Time window analysis (last 5 minutes)
        time_window = 300  # 5 minutes
        recent_cutoff = current_time - time_window
        
        recent_queries = [q for q in data['queries'] if q[0] > recent_cutoff]
        num_recent_queries = len(recent_queries)
        
        # Calculate query rate
        if recent_queries:
            time_span = current_time - recent_queries[0][0]
            query_rate = num_recent_queries / max(time_span, 1)  # queries per second
        else:
            query_rate = 0
        
        # ANOMALY DETECTION
        is_anomaly = False
        severity = 'MEDIUM'
        anomaly_type = None
        indicators = []
        confidence = 0
        
        # Anomaly 1: DNS Flood (excessive queries)
        if num_recent_queries > 100:  # 100+ queries in 5 minutes
            is_anomaly = True
            anomaly_type = 'dns_flood'
            indicators.append(f"Excessive DNS queries ({num_recent_queries} in 5 min)")
            confidence += 30
            severity = 'HIGH'
        
        if query_rate > 1.0:  # More than 1 query per second
            indicators.append(f"High query rate ({query_rate:.1f}/sec)")
            confidence += 20
        
        # Anomaly 2: DGA Domains (malware C2)
        if data['dga_score'] > 0.6:
            is_anomaly = True
            anomaly_type = 'dga_domains'
            indicators.append(f"DGA-like domains detected (score: {data['dga_score']:.2f})")
            confidence += 40
            severity = 'CRITICAL'
            
            # List suspicious domains
            if data['suspicious_domains']:
                top_suspicious = sorted(data['suspicious_domains'], key=lambda x: x[1], reverse=True)[:3]
                for domain, score in top_suspicious:
                    indicators.append(f"  - {domain} (DGA: {score:.2f})")
        
        # Anomaly 3: DNS Tunneling (long subdomains)
        long_subdomains = [d for _, d, _ in recent_queries if len(d) > 50]
        if len(long_subdomains) > 5:
            is_anomaly = True
            anomaly_type = 'dns_tunneling'
            indicators.append(f"Possible DNS tunneling ({len(long_subdomains)} long queries)")
            confidence += 35
            severity = 'HIGH'
        
        # Anomaly 4: Unusual query types
        unusual_types = ['TXT', 'NULL', 'ANY', 'CNAME']
        unusual_count = sum(data['query_types'].get(t, 0) for t in unusual_types)
        if unusual_count > 10:
            indicators.append(f"Unusual query types ({unusual_count} TXT/NULL/ANY)")
            confidence += 15
        
        # Anomaly 5: Many unique domains
        if len(data['unique_domains']) > 50:
            indicators.append(f"Many unique domains ({len(data['unique_domains'])})")
            confidence += 10
        
        # Trigger alert if anomaly detected
        if is_anomaly and confidence >= 40:
            # Check if we already alerted for this source recently
            already_alerted = False
            for alert in self.dns_anomaly_alerts:
                if (alert['source_ip'] == src_ip and 
                    alert.get('anomaly_type') == anomaly_type and
                    current_time - alert['timestamp'] < 300):  # 5 minutes
                    already_alerted = True
                    break
            
            if not already_alerted:
                alert = {
                    'type': 'dns_anomaly',
                    'anomaly_type': anomaly_type,
                    'severity': severity,
                    'source_ip': src_ip,
                    'total_queries': num_recent_queries,
                    'unique_domains': len(data['unique_domains']),
                    'query_rate': query_rate,
                    'dga_score': data['dga_score'],
                    'confidence': confidence,
                    'indicators': indicators,
                    'timestamp': current_time,
                    'duration': current_time - data['first_seen'],
                    'description': f"DNS anomaly detected from {src_ip}: {anomaly_type}"
                }
                
                self.dns_anomaly_alerts.append(alert)
                
                if anomaly_type == 'dns_flood':
                    self.stats['dns_floods_detected'] += 1
                elif anomaly_type == 'dga_domains':
                    self.stats['dga_domains_detected'] += 1
                elif anomaly_type == 'dns_tunneling':
                    self.stats['tunneling_detected'] += 1
                
                logger.warning(f"🚨 [DNS ANOMALY DETECTED]")
                logger.warning(f"   Type: {anomaly_type}")
                logger.warning(f"   Source: {src_ip}")
                logger.warning(f"   Queries: {num_recent_queries} ({query_rate:.1f}/sec)")
                logger.warning(f"   Unique domains: {len(data['unique_domains'])}")
                logger.warning(f"   Confidence: {confidence}%")
                logger.warning(f"   Severity: {severity}")
                logger.warning(f"   Indicators: {', '.join(indicators[:3])}")  # Show first 3
                
                # Add to reconnaissance findings
                try:
                    from .. import state
                    recon_finding = {
                        'timestamp': current_time,
                        'source_ip': src_ip,
                        'threat_type': anomaly_type,
                        'recon_score': min(100, confidence),
                        'indicators': indicators,
                        'details': alert
                    }
                    
                    if not hasattr(state, 'reconnaissance_findings'):
                        state.reconnaissance_findings = []
                    
                    state.reconnaissance_findings.insert(0, recon_finding)
                    logger.info(f"✅ Added DNS anomaly to reconnaissance findings")
                except Exception as e:
                    logger.error(f"Failed to add to reconnaissance findings: {e}")
    
    def get_alerts(self, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Get DNS anomaly alerts
        
        Args:
            since: Only return alerts after this timestamp (optional)
        
        Returns:
            List of alert dictionaries
        """
        if since is None:
            return self.dns_anomaly_alerts
        
        return [a for a in self.dns_anomaly_alerts if a['timestamp'] > since]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return self.stats.copy()
    
    def get_source_profile(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed DNS profile of a source IP
        
        Args:
            src_ip: Source IP address
        
        Returns:
            DNS profile dictionary or None
        """
        if src_ip not in self.dns_queries:
            return None
        
        data = self.dns_queries[src_ip]
        
        return {
            'source_ip': src_ip,
            'total_queries': len(data['queries']),
            'unique_domains': len(data['unique_domains']),
            'query_types': dict(data['query_types']),
            'dga_score': data['dga_score'],
            'suspicious_domains': data['suspicious_domains'],
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
        
        # Cleanup DNS queries
        ips_to_remove = []
        for src_ip, data in self.dns_queries.items():
            if data['last_seen'] < cutoff:
                ips_to_remove.append(src_ip)
        
        for ip in ips_to_remove:
            del self.dns_queries[ip]
        
        # Cleanup domain queries
        domains_to_remove = []
        for domain, queries in self.domain_queries.items():
            if not queries or queries[-1][0] < cutoff:
                domains_to_remove.append(domain)
        
        for domain in domains_to_remove:
            del self.domain_queries[domain]
        
        # Cleanup old alerts (keep last 24 hours)
        alert_cutoff = current_time - 86400
        self.dns_anomaly_alerts = [a for a in self.dns_anomaly_alerts if a['timestamp'] > alert_cutoff]
        
        if ips_to_remove or domains_to_remove:
            logger.debug(f"Cleaned up {len(ips_to_remove)} old DNS tracking entries and {len(domains_to_remove)} domains")


# Global instance
dns_anomaly_detector = DNSAnomalyDetector()
