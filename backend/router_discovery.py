"""
Router-Based Device Discovery for AVIGHNA Defense
==================================================
PRIMARY device discovery source - uses router client table
Supports TP-Link and generic routers

Architecture:
1. Router client table (PRIMARY)
2. DHCP lease table (FALLBACK)
3. ARP table (LAST RESORT)
"""

import logging
import requests
import base64
import re
from typing import List, Dict, Optional, Any
from bs4 import BeautifulSoup
import subprocess
import urllib3

# Disable SSL warnings for self-signed router certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class RouterDiscovery:
    """
    Router-based device discovery
    Attempts multiple methods to get connected devices from router
    """
    
    def __init__(
        self,
        router_ip: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        # Load from config if not provided
        from .config import settings
        
        self.router_ip = router_ip or settings.router_ip
        self.username = username or settings.router_username
        self.password = password or settings.router_password
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Detection results
        self.router_type = None
        self.discovery_method = None
    
    def discover_devices(self) -> List[Dict[str, Any]]:
        """
        Discover devices using multiple methods in priority order
        Returns list of devices with: name, ip, mac, hostname, status, vendor
        """
        logger.info(f"Starting router-based discovery on {self.router_ip}")
        
        # Try methods in priority order
        methods = [
            ("TP-Link API", self._try_tplink_api),
            ("TP-Link Web Scraping", self._try_tplink_web_scraping),
            ("Generic Router Web", self._try_generic_router_web),
            ("DHCP Leases", self._try_dhcp_leases),
            ("ARP Table", self._try_arp_table),
        ]
        
        for method_name, method_func in methods:
            try:
                logger.info(f"Trying: {method_name}")
                devices = method_func()
                
                if devices and len(devices) > 0:
                    self.discovery_method = method_name
                    logger.info(f"✅ SUCCESS: {method_name} found {len(devices)} device(s)")
                    return devices
                else:
                    logger.debug(f"❌ {method_name} returned no devices")
            
            except Exception as e:
                logger.debug(f"❌ {method_name} failed: {e}")
                continue
        
        logger.warning("All router discovery methods failed - no devices found")
        return []
    
    def _try_tplink_api(self) -> List[Dict[str, Any]]:
        """
        Try TP-Link router API endpoints
        Some TP-Link routers expose JSON APIs
        """
        # Common TP-Link API endpoints
        api_endpoints = [
            f"http://{self.router_ip}/cgi-bin/luci/admin/status/overview",
            f"http://{self.router_ip}/cgi-bin/luci/rpc/sys",
            f"http://{self.router_ip}/userRpm/WlanStationRpm.htm",
            f"http://{self.router_ip}/userRpm/AssignedIpAddrListRpm.htm",
        ]
        
        auth = (self.username, self.password)
        
        for endpoint in api_endpoints:
            try:
                response = self.session.get(
                    endpoint,
                    auth=auth,
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Try to parse as JSON
                    try:
                        data = response.json()
                        devices = self._parse_tplink_json(data)
                        if devices:
                            return devices
                    except:
                        # Try to parse as HTML
                        devices = self._parse_tplink_html(response.text)
                        if devices:
                            return devices
            
            except Exception as e:
                logger.debug(f"API endpoint {endpoint} failed: {e}")
                continue
        
        return []
    
    def _try_tplink_web_scraping(self) -> List[Dict[str, Any]]:
        """
        Scrape TP-Link router web interface for connected clients
        Uses session-based authentication for modern TP-Link routers
        """
        try:
            logger.info("Attempting TP-Link session-based login...")
            
            # Step 1: Get encryption parameters from router
            try:
                response = self.session.post(
                    f"http://{self.router_ip}/cgi/getParm",
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Parse JavaScript response to get encryption key
                    # Response format: var nn="..."; var ee="..."; var ss="...";
                    import re
                    
                    # Try to extract encryption parameters
                    nn_match = re.search(r'nn="([^"]+)"', response.text)
                    ee_match = re.search(r'ee="([^"]+)"', response.text)
                    ss_match = re.search(r'ss="([^"]+)"', response.text)
                    
                    use_rsa = nn_match and ee_match
                    use_md5 = ss_match
                    
                    logger.debug(f"Encryption method: {'RSA' if use_rsa else 'MD5' if use_md5 else 'Unknown'}")
                    
                    # Step 2: Encode credentials
                    import base64
                    import hashlib
                    
                    # Base64 encode password
                    pwd_b64 = base64.b64encode(self.password.encode()).decode()
                    user_b64 = base64.b64encode(self.username.encode()).decode()
                    
                    # For simplicity, use MD5 hash (RSA would require additional crypto library)
                    if use_md5 and ss_match:
                        salt = ss_match.group(1)
                        # MD5(Base64(password) + salt)
                        passwd_hash = hashlib.md5((pwd_b64 + salt).encode()).hexdigest()
                        username_hash = hashlib.md5((user_b64 + salt).encode()).hexdigest()
                    else:
                        # Fallback: try simple Base64
                        passwd_hash = pwd_b64
                        username_hash = user_b64
                    
                    # Step 3: Login
                    login_url = f"http://{self.router_ip}/cgi/login"
                    login_params = {
                        'UserName': username_hash,
                        'Passwd': passwd_hash,
                        'Action': '1',
                        'LoginStatus': '0'
                    }
                    
                    login_response = self.session.post(
                        login_url,
                        params=login_params,
                        timeout=5,
                        verify=False
                    )
                    
                    logger.debug(f"Login response status: {login_response.status_code}")
                    
                    if login_response.status_code == 200:
                        logger.info("✅ TP-Link login successful")
                        
                        # Step 4: Try to access device list pages
                        device_pages = [
                            "/userRpm/AssignedIpAddrListRpm.htm",
                            "/userRpm/WlanStationRpm.htm",
                            "/cgi-bin/luci/admin/status/overview",
                            "/data/map_access_wireless_client.json",
                            "/data/wireless.json",
                        ]
                        
                        for page in device_pages:
                            try:
                                page_response = self.session.get(
                                    f"http://{self.router_ip}{page}",
                                    timeout=5,
                                    verify=False
                                )
                                
                                if page_response.status_code == 200:
                                    logger.debug(f"Accessing {page}: SUCCESS")
                                    
                                    # Try to parse devices
                                    devices = self._parse_tplink_html(page_response.text)
                                    
                                    if devices:
                                        self.router_type = "TP-Link"
                                        logger.info(f"✅ Found {len(devices)} devices from {page}")
                                        return devices
                                else:
                                    logger.debug(f"Accessing {page}: {page_response.status_code}")
                            
                            except Exception as e:
                                logger.debug(f"Failed to access {page}: {e}")
                                continue
            
            except Exception as e:
                logger.debug(f"Session login failed: {e}")
            
            # Fallback: Try old Basic Auth method
            logger.debug("Trying Basic Auth fallback...")
            auth_str = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {auth_str}'
            })
            
            urls_to_try = [
                f"http://{self.router_ip}/userRpm/AssignedIpAddrListRpm.htm",
                f"http://{self.router_ip}/userRpm/WlanStationRpm.htm",
                f"http://{self.router_ip}/",
            ]
            
            for url in urls_to_try:
                try:
                    response = self.session.get(url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        devices = self._parse_tplink_html(response.text)
                        if devices:
                            self.router_type = "TP-Link"
                            return devices
                
                except Exception:
                    continue
            
            return []
        
        except Exception as e:
            logger.debug(f"TP-Link web scraping failed: {e}")
            return []
    
    def _parse_tplink_html(self, html: str) -> List[Dict[str, Any]]:
        """
        Parse TP-Link HTML to extract device information
        """
        devices = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Look for device tables
            tables = soup.find_all('table')
            
            for table in tables:
                rows = table.find_all('tr')
                
                for row in rows:
                    cols = row.find_all('td')
                    
                    if len(cols) >= 3:
                        # Try to extract IP, MAC, name
                        text_cols = [col.get_text(strip=True) for col in cols]
                        
                        # Look for IP pattern
                        ip = None
                        mac = None
                        name = None
                        
                        for text in text_cols:
                            # IP pattern
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text):
                                ip = text
                            # MAC pattern
                            elif re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', text):
                                mac = text.lower().replace(':', '-')
                            # Name (not IP or MAC)
                            elif text and not re.match(r'^[0-9A-Fa-f:-]+$', text):
                                if len(text) > 2 and len(text) < 50:
                                    name = text
                        
                        if ip and mac:
                            devices.append({
                                'name': name or 'Unknown Device',
                                'ip': ip,
                                'mac': mac,
                                'hostname': name,
                                'status': 'ACTIVE',
                                'vendor': 'Unknown',
                                'source': 'router'
                            })
            
            # Also try JavaScript data extraction
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Look for device arrays in JavaScript
                    js_devices = self._extract_devices_from_js(script.string)
                    devices.extend(js_devices)
            
            # Remove duplicates based on MAC
            seen_macs = set()
            unique_devices = []
            for device in devices:
                if device['mac'] not in seen_macs:
                    seen_macs.add(device['mac'])
                    unique_devices.append(device)
            
            return unique_devices
        
        except Exception as e:
            logger.debug(f"HTML parsing failed: {e}")
            return []
    
    def _extract_devices_from_js(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Extract device data from JavaScript code in router pages
        """
        devices = []
        
        try:
            # Look for common patterns in TP-Link JavaScript
            # Pattern: ["name", "ip", "mac", ...]
            array_pattern = r'\["([^"]+)",\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",\s*"([0-9A-Fa-f:-]+)"'
            matches = re.findall(array_pattern, js_code)
            
            for match in matches:
                name, ip, mac = match
                devices.append({
                    'name': name or 'Unknown Device',
                    'ip': ip,
                    'mac': mac.lower().replace(':', '-'),
                    'hostname': name,
                    'status': 'ACTIVE',
                    'vendor': 'Unknown',
                    'source': 'router'
                })
        
        except Exception as e:
            logger.debug(f"JS extraction failed: {e}")
        
        return devices
    
    def _parse_tplink_json(self, data: Dict) -> List[Dict[str, Any]]:
        """
        Parse TP-Link JSON API response
        """
        devices = []
        
        try:
            # Try different JSON structures
            if 'clients' in data:
                for client in data['clients']:
                    devices.append({
                        'name': client.get('name', 'Unknown Device'),
                        'ip': client.get('ip', ''),
                        'mac': client.get('mac', '').lower().replace(':', '-'),
                        'hostname': client.get('hostname', client.get('name')),
                        'status': 'ACTIVE' if client.get('online') else 'OFFLINE',
                        'vendor': 'Unknown',
                        'source': 'router'
                    })
            
            elif 'devices' in data:
                for device in data['devices']:
                    devices.append({
                        'name': device.get('name', 'Unknown Device'),
                        'ip': device.get('ip', ''),
                        'mac': device.get('mac', '').lower().replace(':', '-'),
                        'hostname': device.get('hostname', device.get('name')),
                        'status': 'ACTIVE',
                        'vendor': 'Unknown',
                        'source': 'router'
                    })
        
        except Exception as e:
            logger.debug(f"JSON parsing failed: {e}")
        
        return devices
    
    def _try_generic_router_web(self) -> List[Dict[str, Any]]:
        """
        Try generic router web interface patterns
        Works with many consumer routers
        """
        try:
            # Try common router URLs
            urls = [
                f"http://{self.router_ip}/status.html",
                f"http://{self.router_ip}/dhcp.html",
                f"http://{self.router_ip}/clients.html",
                f"http://{self.router_ip}/devices.html",
            ]
            
            auth = (self.username, self.password)
            
            for url in urls:
                try:
                    response = self.session.get(url, auth=auth, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        devices = self._parse_generic_html(response.text)
                        if devices:
                            return devices
                
                except Exception:
                    continue
            
            return []
        
        except Exception as e:
            logger.debug(f"Generic router web failed: {e}")
            return []
    
    def _parse_generic_html(self, html: str) -> List[Dict[str, Any]]:
        """
        Parse generic router HTML for device information
        """
        # Similar to TP-Link parsing but more generic
        return self._parse_tplink_html(html)
    
    def _try_dhcp_leases(self) -> List[Dict[str, Any]]:
        """
        Try to read DHCP lease table
        Works on some routers with accessible lease files
        """
        devices = []
        
        try:
            # Try to access DHCP leases via HTTP
            urls = [
                f"http://{self.router_ip}/dhcp_leases.txt",
                f"http://{self.router_ip}/tmp/dhcp.leases",
            ]
            
            auth = (self.username, self.password)
            
            for url in urls:
                try:
                    response = self.session.get(url, auth=auth, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        devices = self._parse_dhcp_leases(response.text)
                        if devices:
                            return devices
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"DHCP leases failed: {e}")
        
        return devices
    
    def _parse_dhcp_leases(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse DHCP lease file format
        """
        devices = []
        
        try:
            for line in content.splitlines():
                # Common format: timestamp mac ip hostname
                parts = line.split()
                
                if len(parts) >= 3:
                    # Try to identify IP and MAC
                    ip = None
                    mac = None
                    hostname = None
                    
                    for part in parts:
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
                            ip = part
                        elif re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                            mac = part.lower().replace(':', '-')
                        elif not part.isdigit() and len(part) > 2:
                            hostname = part
                    
                    if ip and mac:
                        devices.append({
                            'name': hostname or 'Unknown Device',
                            'ip': ip,
                            'mac': mac,
                            'hostname': hostname,
                            'status': 'ACTIVE',
                            'vendor': 'Unknown',
                            'source': 'dhcp'
                        })
        
        except Exception as e:
            logger.debug(f"DHCP parsing failed: {e}")
        
        return devices
    
    def _try_arp_table(self) -> List[Dict[str, Any]]:
        """
        Fallback: Use local ARP table
        LAST RESORT - less reliable than router data
        """
        devices = []
        
        try:
            # Run arp -a command
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
                errors="ignore"
            )
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    # Parse ARP output
                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?([0-9a-fA-F:-]{11,17})', line)
                    
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).lower().replace(':', '-')
                        
                        # Filter out invalid entries
                        if (not ip.startswith('224.') and 
                            not ip.startswith('239.') and
                            not ip.endswith('.255') and
                            mac != 'ff-ff-ff-ff-ff-ff'):
                            
                            devices.append({
                                'name': 'Unknown Device',
                                'ip': ip,
                                'mac': mac,
                                'hostname': None,
                                'status': 'ACTIVE',
                                'vendor': 'Unknown',
                                'source': 'arp'
                            })
        
        except Exception as e:
            logger.debug(f"ARP table failed: {e}")
        
        return devices


# Global instance
router_discovery = RouterDiscovery()
