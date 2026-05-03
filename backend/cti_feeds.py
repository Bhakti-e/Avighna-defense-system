"""
Cyber Threat Intelligence (CTI) Feed Manager
============================================
Integrates external threat intelligence feeds to enhance detection:
- Abuse.ch (URLhaus, ThreatFox, Feodo Tracker)
- AlienVault OTX (Open Threat Exchange)
- VirusTotal API
- Custom threat lists

Updates threat data periodically and checks IPs/hashes against known threats.
"""

import requests
import logging
import time
import hashlib
from typing import Dict, Any, List, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os

logger = logging.getLogger(__name__)

class CTIFeedManager:
    """
    Manages multiple threat intelligence feeds and provides lookup services
    """
    
    def __init__(self, vt_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key or os.environ.get("VIRUSTOTAL_API_KEY", "demo_key")
        
        # Threat intelligence feeds (free, no API key required)
        self.feeds = {
            "urlhaus": "https://urlhaus.abuse.ch/downloads/json/",
            "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
            "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        }
        
        # Threat data storage
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.malware_hashes: Set[str] = set()
        self.c2_servers: Dict[str, Dict[str, Any]] = {}
        
        # Metadata
        self.last_update: Optional[datetime] = None
        self.update_count = 0
        self.feed_stats = defaultdict(int)
        
        logger.info("CTI Feed Manager initialized")
    
    def update_feeds(self) -> Dict[str, Any]:
        """
        Update all threat intelligence feeds
        Returns statistics about the update
        """
        start_time = time.time()
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "feeds_updated": [],
            "feeds_failed": [],
            "new_ips": 0,
            "new_domains": 0,
            "new_hashes": 0,
            "total_time": 0
        }
        
        logger.info("Starting CTI feed update...")
        
        # Update URLhaus (malicious URLs and IPs)
        try:
            self._update_urlhaus()
            stats["feeds_updated"].append("urlhaus")
            logger.info("✓ URLhaus feed updated")
        except Exception as e:
            stats["feeds_failed"].append({"feed": "urlhaus", "error": str(e)})
            logger.error(f"✗ URLhaus update failed: {e}")
        
        # Update ThreatFox (malware IOCs)
        try:
            self._update_threatfox()
            stats["feeds_updated"].append("threatfox")
            logger.info("✓ ThreatFox feed updated")
        except Exception as e:
            stats["feeds_failed"].append({"feed": "threatfox", "error": str(e)})
            logger.error(f"✗ ThreatFox update failed: {e}")
        
        # Update Feodo Tracker (botnet C2 servers)
        try:
            self._update_feodo_tracker()
            stats["feeds_updated"].append("feodo_tracker")
            logger.info("✓ Feodo Tracker feed updated")
        except Exception as e:
            stats["feeds_failed"].append({"feed": "feodo_tracker", "error": str(e)})
            logger.error(f"✗ Feodo Tracker update failed: {e}")
        
        # Calculate statistics
        stats["new_ips"] = len(self.malicious_ips)
        stats["new_domains"] = len(self.malicious_domains)
        stats["new_hashes"] = len(self.malware_hashes)
        stats["total_time"] = round(time.time() - start_time, 2)
        
        self.last_update = datetime.utcnow()
        self.update_count += 1
        
        logger.info(f"CTI feed update complete: {stats['new_ips']} IPs, "
                   f"{stats['new_domains']} domains, {stats['new_hashes']} hashes "
                   f"in {stats['total_time']}s")
        
        return stats
    
    def _update_urlhaus(self):
        """Update URLhaus feed (malicious URLs and hosting IPs)"""
        try:
            response = requests.get(self.feeds["urlhaus"], timeout=30)
            response.raise_for_status()
            
            # Try to parse JSON
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                logger.warning(f"URLhaus JSON parsing failed: {e}. Skipping feed.")
                return
            
            # Handle both list and dict responses
            if isinstance(data, dict):
                data = data.get("data", [])
            
            if not isinstance(data, list):
                logger.warning(f"URLhaus returned unexpected format: {type(data)}. Skipping.")
                return
            
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                    
                # Only process online threats
                if entry.get("url_status") == "online":
                    # Add malicious IP
                    host = entry.get("host")
                    if host and self._is_valid_ip(host):
                        self.malicious_ips.add(host)
                        self.feed_stats["urlhaus_ips"] += 1
                    
                    # Add malicious domain
                    url = entry.get("url", "")
                    if url:
                        domain = self._extract_domain(url)
                        if domain:
                            self.malicious_domains.add(domain)
                            self.feed_stats["urlhaus_domains"] += 1
                    
                    # Add malware hashes
                    for hash_type in ["md5_hash", "sha256_hash"]:
                        hash_value = entry.get(hash_type)
                        if hash_value:
                            self.malware_hashes.add(hash_value.lower())
                            self.feed_stats["urlhaus_hashes"] += 1
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"URLhaus feed unavailable: {e}. Skipping.")
        except Exception as e:
            logger.error(f"URLhaus update error: {e}. Skipping.")
            # Don't raise - allow other feeds to continue
    
    def _update_threatfox(self):
        """Update ThreatFox feed (malware IOCs)"""
        try:
            response = requests.get(self.feeds["threatfox"], timeout=30)
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                logger.warning(f"ThreatFox JSON parsing failed: {e}. Skipping feed.")
                return
            
            for entry in data.get("data", []):
                if not isinstance(entry, dict):
                    continue
                    
                ioc_type = entry.get("ioc_type", "")
                ioc_value = entry.get("ioc", "")
                
                # IP addresses (with or without port)
                if ioc_type in ["ip:port", "ip"]:
                    ip = ioc_value.split(":")[0] if ":" in ioc_value else ioc_value
                    if self._is_valid_ip(ip):
                        self.malicious_ips.add(ip)
                        self.feed_stats["threatfox_ips"] += 1
                        
                        # Store C2 server details
                        self.c2_servers[ip] = {
                            "malware": entry.get("malware"),
                            "threat_type": entry.get("threat_type"),
                            "confidence": entry.get("confidence_level"),
                            "first_seen": entry.get("first_seen"),
                            "tags": entry.get("tags", [])
                        }
                
                # Domain names
                elif ioc_type == "domain":
                    self.malicious_domains.add(ioc_value.lower())
                    self.feed_stats["threatfox_domains"] += 1
                
                # File hashes
                elif ioc_type in ["md5_hash", "sha256_hash", "sha1_hash"]:
                    self.malware_hashes.add(ioc_value.lower())
                    self.feed_stats["threatfox_hashes"] += 1
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"ThreatFox feed unavailable: {e}. Skipping.")
        except Exception as e:
            logger.error(f"ThreatFox update error: {e}. Skipping.")
            # Don't raise - allow other feeds to continue
    
    def _update_feodo_tracker(self):
        """Update Feodo Tracker feed (botnet C2 servers)"""
        try:
            response = requests.get(self.feeds["feodo_tracker"], timeout=30)
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                logger.warning(f"Feodo Tracker JSON parsing failed: {e}. Skipping feed.")
                return
            
            if not isinstance(data, list):
                logger.warning(f"Feodo Tracker returned unexpected format: {type(data)}. Skipping.")
                return
            
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                    
                ip = entry.get("ip_address")
                if ip and self._is_valid_ip(ip):
                    self.malicious_ips.add(ip)
                    self.feed_stats["feodo_ips"] += 1
                    
                    # Store botnet details
                    self.c2_servers[ip] = {
                        "malware": entry.get("malware", "Feodo/Emotet"),
                        "threat_type": "Botnet C2",
                        "confidence": "high",
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen"),
                        "port": entry.get("port")
                    }
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"Feodo Tracker feed unavailable: {e}. Skipping.")
        except Exception as e:
            logger.error(f"Feodo Tracker update error: {e}. Skipping.")
            # Don't raise - allow other feeds to continue
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check if IP address is in threat intelligence feeds
        
        Returns:
            dict with is_malicious, threat_type, confidence, details
        """
        if not ip or not self._is_valid_ip(ip):
            return {"is_malicious": False, "reason": "Invalid IP"}
        
        if ip in self.malicious_ips:
            # Get C2 server details if available
            c2_info = self.c2_servers.get(ip, {})
            
            return {
                "is_malicious": True,
                "source": "CTI Feed",
                "threat_type": c2_info.get("threat_type", "Malicious IP"),
                "malware_family": c2_info.get("malware", "Unknown"),
                "confidence": c2_info.get("confidence", "medium"),
                "first_seen": c2_info.get("first_seen"),
                "tags": c2_info.get("tags", []),
                "recommendation": "Block immediately - Known C2 server"
            }
        
        return {"is_malicious": False}
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check if domain is in threat intelligence feeds
        """
        if not domain:
            return {"is_malicious": False, "reason": "Invalid domain"}
        
        domain_lower = domain.lower()
        
        if domain_lower in self.malicious_domains:
            return {
                "is_malicious": True,
                "source": "CTI Feed",
                "threat_type": "Malicious Domain",
                "recommendation": "Block DNS resolution"
            }
        
        return {"is_malicious": False}
    
    def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check if file hash is known malware
        """
        if not file_hash:
            return {"is_malicious": False, "reason": "Invalid hash"}
        
        hash_lower = file_hash.lower()
        
        if hash_lower in self.malware_hashes:
            return {
                "is_malicious": True,
                "source": "CTI Feed",
                "threat_type": "Known Malware Sample",
                "recommendation": "Quarantine and delete immediately"
            }
        
        return {"is_malicious": False}
    
    def check_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against VirusTotal API
        Requires valid API key
        """
        if self.vt_api_key == "demo_key":
            logger.warning("VirusTotal API key not configured")
            return {
                "error": "VirusTotal API key not configured",
                "is_malicious": False
            }
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.vt_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return {
                    "is_malicious": False,
                    "reason": "File not found in VirusTotal database"
                }
            
            response.raise_for_status()
            data = response.json()
            
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)
            total_count = sum(stats.values())
            
            # Get threat names from engines that detected it
            threat_names = []
            for engine, result in data["data"]["attributes"]["last_analysis_results"].items():
                if result.get("category") == "malicious" and result.get("result"):
                    threat_names.append(result["result"])
            
            is_malicious = malicious_count > 0
            
            return {
                "is_malicious": is_malicious,
                "source": "VirusTotal",
                "malicious_count": malicious_count,
                "total_engines": total_count,
                "detection_ratio": f"{malicious_count}/{total_count}",
                "threat_names": threat_names[:5],  # Top 5 detections
                "confidence": "high" if malicious_count > 10 else "medium" if malicious_count > 3 else "low",
                "recommendation": "Quarantine immediately" if malicious_count > 10 else "Investigate further"
            }
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.warning("VirusTotal API rate limit exceeded")
                return {"error": "Rate limit exceeded", "is_malicious": False}
            raise
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return {"error": str(e), "is_malicious": False}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get CTI feed statistics"""
        return {
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "update_count": self.update_count,
            "malicious_ips": len(self.malicious_ips),
            "malicious_domains": len(self.malicious_domains),
            "malware_hashes": len(self.malware_hashes),
            "c2_servers": len(self.c2_servers),
            "feed_stats": dict(self.feed_stats)
        }
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            # Remove protocol
            if "://" in url:
                url = url.split("://")[1]
            # Remove path
            domain = url.split("/")[0]
            # Remove port
            domain = domain.split(":")[0]
            return domain.lower()
        except:
            return None


# Global CTI manager instance
cti_manager = CTIFeedManager()
