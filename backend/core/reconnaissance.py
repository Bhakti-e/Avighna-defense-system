"""
Reconnaissance Detection Engine
================================
Detects pre-attack scanning and probing activities
(The "thief observing the building" before the robbery)

Monitors:
- Port scan patterns
- Multiple connection attempts to different ports
- Failed authentication attempts (brute force setup)
- Unusual network topology changes
- Sudden increase in network queries (DNS, ARP)
- Service enumeration attempts
"""

import time
from typing import Dict, List, Any, Tuple
from collections import defaultdict

class ReconnaissanceDetector:
    """
    Detects reconnaissance activities that indicate preparation for attacks.
    
    Threat indicators:
    1. Port scanning (SYN scans, connection attempts to many ports)
    2. Service enumeration (probing known service ports)
    3. Credential testing (multiple failed logins = brute force setup)
    4. Network mapping (ARP requests to unusual IPs)
    5. DNS queries to suspicious domains
    6. Sudden behavioral changes (baseline deviation)
    """
    
    def __init__(self, time_window_hours=24):
        self.time_window = time_window_hours * 60 * 60  # Convert to seconds
        
        # Track reconnaissance activities
        self.failed_connections = defaultdict(list)      # device -> [(ts, ip, port)]
        self.port_probes = defaultdict(list)             # device -> [(ts, target_ip, port)]
        self.arp_requests = defaultdict(list)            # device -> [(ts, target_ip)]
        self.dns_queries = defaultdict(list)             # device -> [(ts, domain)]
        self.auth_failures = defaultdict(list)           # device -> [(ts, attempts)]
        
    def detect_port_scanning(self, device_id: str, connections: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
        """
        Detect port scanning activity.
        
        Indicators:
        - Many connections to different ports on same target
        - Sequential port numbers being probed
        - High rate of connection attempts
        - Failed connections (closed ports)
        """
        reasons = []
        risk = 0.0
        
        # Handle case where connections is just a count (int) instead of list
        if isinstance(connections, int):
            # If only a count and it's high, flag as suspicious but not conclusive
            if connections > 15:
                reasons.append(f"Unusual high connection count: {connections}")
                risk = 15.0  # Moderate risk, not high (needs more evidence)
            return (risk, reasons)
        
        # If connections is not iterable or None, return early
        if not connections or not isinstance(connections, list):
            return (0.0, [])
        
        now = time.time()
        
        # Track connection attempts
        connection_targets = defaultdict(list)  # target_ip -> [ports]
        
        for conn in connections:
            try:
                target_ip = conn.get("target_ip") or conn.get("remote_ip")
                port = conn.get("port")
                status = conn.get("status", "unknown")  # "open", "closed", "filtered"
                
                if target_ip and port:
                    connection_targets[target_ip].append({
                        "port": port,
                        "status": status,
                        "ts": conn.get("ts", now)
                    })
            except:
                continue
        
        # Analyze for scanning patterns
        for target_ip, ports_data in connection_targets.items():
            ports = [p["port"] for p in ports_data]
            num_ports = len(ports)
            
            # More than 20 ports to single target = likely port scan
            if num_ports > 20:
                reasons.append(f"Port scan detected: {num_ports} ports probed on {target_ip}")
                risk = max(risk, 30.0)
            
            # Check for sequential port probing (common scan pattern)
            if num_ports > 5:
                sorted_ports = sorted(ports)
                sequential_count = sum(1 for i in range(len(sorted_ports)-1) 
                                      if sorted_ports[i+1] - sorted_ports[i] <= 5)
                if sequential_count >= 3:
                    reasons.append(f"Sequential port probing: {sequential_count} sequential ports on {target_ip}")
                    risk = max(risk, 25.0)
            
            # Check failed connection rate
            failed = sum(1 for p in ports_data if p["status"] == "closed")
            total = len(ports_data)
            if total > 5 and failed / total > 0.6:  # 60% failed = typical port scan
                reasons.append(f"High failed connection rate: {failed}/{total} to {target_ip}")
                risk = max(risk, 20.0)
        
        return risk, reasons
    
    def detect_brute_force_setup(self, device_id: str, failed_logins: int, 
                                 auth_attempts: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
        """
        Detect brute force attack preparation.
        
        Indicators:
        - Sudden spike in failed logins
        - Multiple attempts to different accounts
        - Failed logins followed by period of quiet
        - Consistent timing patterns (bot behavior)
        """
        reasons = []
        risk = 0.0
        
        now = time.time()
        recent_failures = [a for a in auth_attempts 
                          if now - a.get("ts", now) < 300]  # Last 5 minutes
        
        # 1. Check for rapid failed login spike
        if len(recent_failures) >= 5:
            reasons.append(f"Rapid auth failure spike: {len(recent_failures)} failures in 5 min")
            risk = max(risk, 25.0)
        
        # 2. Check for multi-account targeting
        accounts_targeted = set()
        for failure in auth_attempts:
            account = failure.get("account")
            if account:
                accounts_targeted.add(account)
        
        if len(accounts_targeted) > 5:
            reasons.append(f"Multiple accounts targeted: {len(accounts_targeted)} different accounts")
            risk = max(risk, 20.0)
        
        # 3. Check for consistent timing (bot behavior)
        if len(recent_failures) >= 3:
            time_gaps = []
            sorted_failures = sorted(recent_failures, key=lambda x: x.get("ts", 0))
            for i in range(len(sorted_failures) - 1):
                gap = sorted_failures[i+1].get("ts", 0) - sorted_failures[i].get("ts", 0)
                time_gaps.append(gap)
            
            # Very consistent gaps = bot behavior
            if time_gaps and all(abs(g - time_gaps[0]) < 1 for g in time_gaps):
                reasons.append(f"Consistent failure timing (likely automated brute force)")
                risk = max(risk, 30.0)
        
        return risk, reasons
    
    def detect_network_mapping(self, device_id: str, 
                              arp_requests: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
        """
        Detect ARP probing and network mapping.
        
        Indicators:
        - Rapid ARP requests to many IPs
        - ARP requests to IPs outside normal subnet
        - Sequential IP address probing (network scan)
        """
        reasons = []
        risk = 0.0
        
        if not arp_requests:
            return risk, reasons
        
        now = time.time()
        recent_arps = [a for a in arp_requests 
                      if now - a.get("ts", now) < 60]  # Last minute
        
        # More than 20 ARP requests per minute = network scan
        if len(recent_arps) > 20:
            unique_ips = set(a.get("target_ip") for a in recent_arps)
            reasons.append(f"Network scan detected: {len(unique_ips)} ARP probes in 60 seconds")
            risk = max(risk, 25.0)
        
        # Check for sequential IP probing
        target_ips = [a.get("target_ip") for a in arp_requests 
                     if a.get("target_ip")]
        if len(target_ips) > 10:
            ip_nums = []
            for ip in target_ips[-10:]:  # Last 10
                try:
                    last_octet = int(ip.split(".")[-1])
                    ip_nums.append(last_octet)
                except:
                    continue
            
            if ip_nums:
                ip_nums.sort()
                sequential = sum(1 for i in range(len(ip_nums)-1) 
                               if ip_nums[i+1] - ip_nums[i] <= 2)
                if sequential >= 3:
                    reasons.append(f"Sequential IP probing: likely network enumeration")
                    risk = max(risk, 20.0)
        
        return risk, reasons
    
    def detect_dns_reconnaissance(self, device_id: str,
                                 dns_queries: List[Dict[str, Any]],
                                 suspicious_domains: List[str] = None) -> Tuple[float, List[str]]:
        """
        Detect DNS queries indicating reconnaissance.
        
        Indicators:
        - Queries to suspicious domains (malware C2, exploit kits)
        - Rapid DNS queries (DNS enumeration)
        - Queries to domains matching known attack infrastructure
        """
        reasons = []
        risk = 0.0
        
        if suspicious_domains is None:
            suspicious_domains = [
                "c2", "malware", "botnet", "exploit", "phishing",
                "ransomware", "cryptominer", "proxy", "vpn"
            ]
        
        if not dns_queries:
            return risk, reasons
        
        for query in dns_queries:
            domain = query.get("domain", "").lower()
            
            # Check for suspicious keywords in domain
            for suspicious in suspicious_domains:
                if suspicious in domain:
                    reasons.append(f"Suspicious DNS query: {domain}")
                    risk = max(risk, 15.0)
                    break
        
        # Check query rate (DNS flood)
        now = time.time()
        recent_queries = [q for q in dns_queries 
                         if now - q.get("ts", now) < 60]
        
        if len(recent_queries) > 50:  # > 50 DNS queries per minute
            reasons.append(f"DNS enumeration detected: {len(recent_queries)} queries in 60 seconds")
            risk = max(risk, 20.0)
        
        return risk, reasons
    
    def detect_service_enumeration(self, device_id: str,
                                  nmap_results: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        Detect service scanning and enumeration.
        
        When a device suddenly tries to identify services on target:
        - Version detection
        - Script scanning
        - OS detection
        """
        reasons = []
        risk = 0.0
        
        if not nmap_results:
            return risk, reasons
        
        # Check for recent aggressive scanning
        scan_type = nmap_results.get("scan_type", "").lower()
        if any(aggressive in scan_type for aggressive in ["-sV", "-O", "-A", "-sC"]):
            reasons.append(f"Aggressive service enumeration scan detected: {scan_type}")
            risk = max(risk, 25.0)
        
        # Check for scanning against multiple hosts
        hosts_scanned = nmap_results.get("hosts_count", 0)
        if hosts_scanned > 50:
            reasons.append(f"Mass service scanning: {hosts_scanned} hosts enumerated")
            risk = max(risk, 20.0)
        
        return risk, reasons
    
    def compute_reconnaissance_score(self, device_id: str,
                                    device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute overall reconnaissance threat score.
        
        Returns:
        {
            "recon_risk": float (0-100),
            "recon_level": str ("CLEAR", "SUSPICIOUS", "CRITICAL"),
            "indicators": [list of detected patterns],
            "confidence": float (0-1),
            "estimated_next_phase": str
        }
        """
        
        all_reasons = []
        total_risk = 0.0
        
        # 1. Port scanning
        port_risk, port_reasons = self.detect_port_scanning(
            device_id, 
            device_data.get("connections", [])
        )
        all_reasons.extend(port_reasons)
        total_risk += port_risk * 0.70
        
        # 2. Brute force setup
        brute_risk, brute_reasons = self.detect_brute_force_setup(
            device_id,
            device_data.get("failed_logins", 0),
            device_data.get("auth_attempts", [])
        )
        all_reasons.extend(brute_reasons)
        total_risk += brute_risk * 0.70
        
        # 3. Network mapping
        map_risk, map_reasons = self.detect_network_mapping(
            device_id,
            device_data.get("arp_requests", [])
        )
        all_reasons.extend(map_reasons)
        total_risk += map_risk * 0.80
        
        # 4. DNS reconnaissance
        dns_risk, dns_reasons = self.detect_dns_reconnaissance(
            device_id,
            device_data.get("dns_queries", [])
        )
        all_reasons.extend(dns_reasons)
        total_risk += dns_risk * 0.60
        
        # 5. Service enumeration
        enum_risk, enum_reasons = self.detect_service_enumeration(
            device_id,
            device_data.get("nmap_results", {})
        )
        all_reasons.extend(enum_reasons)
        total_risk += enum_risk * 0.60
        
        # Clamp to 0-100
        total_risk = min(100.0, max(0.0, total_risk))
        
        # Determine recon level
        if total_risk < 30:
            recon_level = "CLEAR"
        elif total_risk < 60:
            recon_level = "SUSPICIOUS"
        else:
            recon_level = "CRITICAL"
        
        # Estimate next attack phase
        estimated_next = "Unknown"
        if "port" in " ".join(all_reasons).lower():
            estimated_next = "Exploitation (using discovered open ports)"
        elif "brute" in " ".join(all_reasons).lower():
            estimated_next = "Account compromise (using tested credentials)"
        elif "network" in " ".join(all_reasons).lower():
            estimated_next = "Lateral movement (spreading to other hosts)"
        
        return {
            "recon_risk": round(total_risk, 2),
            "recon_level": recon_level,
            "indicators": all_reasons,
            "indicator_count": len(all_reasons),
            "confidence": round(len(all_reasons) / 5.0, 2),  # Max 5 indicators
            "estimated_next_phase": estimated_next,
            "timestamp": time.time()
        }


def predict_attack_phase(recon_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Based on reconnaissance patterns, predict what phase of attack is coming.
    
    Phases:
    1. RECONNAISSANCE (gathering info) ← We detect this
    2. WEAPONIZATION (preparing payload)
    3. DELIVERY (sending malware)
    4. EXPLOITATION (activating malware)
    5. INSTALLATION (establishing persistence)
    6. COMMAND & CONTROL (taking control)
    7. ACTIONS ON OBJECTIVES (data theft/destruction)
    
    This function helps us intervene BEFORE actual attack begins.
    """
    
    indicators = recon_data.get("indicators", [])
    risk = recon_data.get("recon_risk", 0)
    
    prediction = {
        "current_phase": "RECONNAISSANCE",
        "likelihood_of_attack": 0.0,
        "estimated_hours_until_attack": None,
        "recommended_actions": [],
        "confidence": recon_data.get("confidence", 0)
    }
    
    # Analyze patterns to estimate timeline
    if "port scan" in str(indicators).lower():
        prediction["likelihood_of_attack"] = 0.85
        prediction["estimated_hours_until_attack"] = 24  # Typically within 24 hours
        prediction["recommended_actions"].append("Harden target services")
    
    if "brute force" in str(indicators).lower():
        prediction["likelihood_of_attack"] = 0.90
        prediction["estimated_hours_until_attack"] = 6   # Soon!
        prediction["recommended_actions"].append("Force password change")
        prediction["recommended_actions"].append("Enable MFA")
    
    if "network enumeration" in str(indicators).lower():
        prediction["likelihood_of_attack"] = 0.75
        prediction["estimated_hours_until_attack"] = 48
        prediction["recommended_actions"].append("Review network segmentation")
    
    if risk >= 70:
        prediction["likelihood_of_attack"] = 0.95
        prediction["estimated_hours_until_attack"] = 12
    
    return prediction
