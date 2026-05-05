"""
Unified Device Manager for AVIGHNA Defense
==========================================
Single source of truth for all device discovery and tracking
Coordinates Nmap (active) and Scapy (passive) discovery
"""

import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from . import models
from .database import SessionLocal

logger = logging.getLogger(__name__)

# Initialize MAC vendor lookup
try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    mac_lookup.update_vendors()  # Download latest OUI database
    MAC_LOOKUP_AVAILABLE = True
    logger.info("MAC vendor lookup initialized with IEEE OUI database")
except Exception as e:
    MAC_LOOKUP_AVAILABLE = False
    logger.warning(f"MAC vendor lookup not available: {e}")


class DeviceManager:
    """
    Unified device manager - single source of truth
    All device operations go through this manager
    """
    
    # Device status thresholds (seconds)
    ACTIVE_THRESHOLD = 120      # 2 minutes
    RECENT_THRESHOLD = 600      # 10 minutes
    # Devices older than RECENT_THRESHOLD are marked OFFLINE
    
    def __init__(self):
        self.local_ip = self._get_local_ip()
        logger.info(f"Device Manager initialized - Local IP: {self.local_ip}")
    
    def _get_local_ip(self) -> str:
        """Get local machine IP to exclude from discovery"""
        import socket
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"
    
    def is_local_ip(self, ip: str) -> bool:
        """Check if IP is local machine"""
        return ip == self.local_ip or ip.startswith('127.')
    
    def _lookup_vendor(self, mac: str) -> str:
        """
        Lookup vendor from MAC address using IEEE OUI database
        Returns vendor name or "Unknown"
        """
        if not MAC_LOOKUP_AVAILABLE:
            return "Unknown"
        
        try:
            vendor = mac_lookup.lookup(mac)
            return vendor if vendor else "Unknown"
        except Exception:
            return "Unknown"
    
    def _classify_device_type(self, ip: str, mac: str, hostname: Optional[str], vendor: str) -> str:
        """
        Classify device type using heuristics
        Returns: router, phone, laptop, tablet, iot, server, unknown
        """
        # Check if router (common gateway IPs)
        if ip and (ip.endswith('.1') or ip.endswith('.254')):
            return "router"
        
        # Check hostname for clues
        if hostname:
            hostname_lower = hostname.lower()
            
            # Phone detection
            if any(x in hostname_lower for x in ['iphone', 'android', 'phone', 'mobile', 'galaxy', 'pixel', 'oppo', 'vivo', 'xiaomi']):
                return "phone"
            
            # Tablet detection
            if any(x in hostname_lower for x in ['ipad', 'tablet']):
                return "tablet"
            
            # Laptop/Desktop detection
            if any(x in hostname_lower for x in ['laptop', 'desktop', 'pc', 'macbook', 'thinkpad', 'dell', 'hp', 'lenovo']):
                return "laptop"
            
            # Server detection
            if any(x in hostname_lower for x in ['server', 'nas', 'storage']):
                return "server"
        
        # Check vendor for clues
        if vendor and vendor != "Unknown":
            vendor_lower = vendor.lower()
            
            # Phone vendors
            if any(x in vendor_lower for x in ['apple', 'samsung', 'xiaomi', 'huawei', 'oppo', 'vivo', 'oneplus', 'motorola', 'lg', 'sony']):
                return "phone"
            
            # Router vendors
            if any(x in vendor_lower for x in ['tp-link', 'netgear', 'linksys', 'asus', 'd-link', 'cisco', 'ubiquiti']):
                return "router"
            
            # Laptop vendors
            if any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'acer', 'asus', 'msi', 'microsoft']):
                return "laptop"
            
            # IoT vendors
            if any(x in vendor_lower for x in ['raspberry', 'arduino', 'espressif', 'tuya', 'philips hue', 'nest']):
                return "iot"
        
        return "unknown"
    
    def _is_randomized_mac(self, mac: str) -> bool:
        """
        Detect if MAC address is randomized (privacy feature)
        Randomized MACs have locally administered bit set
        """
        if not mac or len(mac) < 2:
            return False
        
        # Get second character (first octet, second hex digit)
        clean_mac = mac.replace(':', '').replace('-', '')
        if len(clean_mac) < 2:
            return False
        
        second_char = clean_mac[1].upper()
        
        # Check if locally administered bit is set
        return second_char in ['2', '3', '6', '7', 'A', 'B', 'E', 'F']
    
    def _compute_confidence_score(self, mac: str, hostname: Optional[str], vendor: str, source: str) -> str:
        """
        Compute confidence score for device identification
        Returns: high, medium, low
        """
        # High confidence: Router source + hostname + vendor
        if source == "router" and hostname and vendor != "Unknown":
            return "high"
        
        # High confidence: Non-randomized MAC + hostname + vendor
        if not self._is_randomized_mac(mac) and hostname and vendor != "Unknown":
            return "high"
        
        # Medium confidence: Non-randomized MAC + (hostname OR vendor)
        if not self._is_randomized_mac(mac) and (hostname or vendor != "Unknown"):
            return "medium"
        
        # Medium confidence: Randomized MAC + hostname
        if self._is_randomized_mac(mac) and hostname:
            return "medium"
        
        # Low confidence: Everything else
        return "low"
    
    def _compute_device_status(self, last_seen: datetime) -> str:
        """
        Compute device status based on last_seen timestamp
        ACTIVE: seen within 2 minutes
        RECENTLY_SEEN: seen within 10 minutes
        OFFLINE: not seen for 10+ minutes
        """
        if not last_seen:
            return "OFFLINE"
        
        now = datetime.utcnow()
        seconds_since = (now - last_seen).total_seconds()
        
        if seconds_since <= self.ACTIVE_THRESHOLD:
            return "ACTIVE"
        elif seconds_since <= self.RECENT_THRESHOLD:
            return "RECENTLY_SEEN"
        else:
            return "OFFLINE"
    
    def register_device(
        self,
        ip: str,
        mac: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        source: str = "router",
        device_name: Optional[str] = None
    ) -> Optional[models.Device]:
        """
        Register or update a device in database
        IMPROVED: Handles randomized MACs, confidence scoring, intelligent deduplication
        
        device_name: Device name from router (PRIMARY - most accurate)
        hostname: Hostname from network discovery
        vendor: Vendor from MAC lookup or router
        """
        # Exclude local machine
        if self.is_local_ip(ip):
            logger.debug(f"Skipping local IP: {ip}")
            return None
        
        # Exclude invalid MACs
        if mac in ['unknown', 'ff-ff-ff-ff-ff-ff', 'ff:ff:ff:ff:ff:ff']:
            logger.debug(f"Skipping invalid MAC: {mac}")
            return None
        
        # Check if randomized MAC
        is_random_mac = self._is_randomized_mac(mac)
        
        # Device ID strategy:
        # - Non-randomized MAC: Use MAC as device_id (stable)
        # - Randomized MAC: Use IP as device_id (changes frequently)
        if is_random_mac:
            device_id = f"random-{ip}"  # Prefix to indicate randomized MAC
            logger.debug(f"Detected randomized MAC: {mac} at {ip}")
        else:
            device_id = mac
        
        # Lookup vendor from IEEE OUI database if not provided
        if not vendor or vendor == "Unknown":
            vendor = self._lookup_vendor(mac)
        
        # Determine best device name
        # Priority: device_name (from router) > hostname > vendor
        best_name = device_name or hostname or vendor
        
        # Handle randomized MAC naming
        if is_random_mac and not device_name:
            best_name = f"Private MAC Device"
        
        # Compute confidence score
        confidence = self._compute_confidence_score(mac, hostname, vendor, source)
        
        db = SessionLocal()
        try:
            # Check if device exists
            device = db.query(models.Device).filter(
                models.Device.device_id == device_id
            ).first()
            
            now = datetime.utcnow()
            
            if device:
                # Update existing device
                device.last_seen = now
                device.ip_address = ip
                device.mac_address = mac  # Update MAC (may change for randomized MACs)
                
                # Update name if we have better information
                if device_name:
                    device.hostname = device_name
                elif hostname and not device.hostname:
                    device.hostname = hostname
                elif is_random_mac and not device.hostname:
                    device.hostname = best_name
                
                if vendor and vendor != "Unknown":
                    device.vendor = vendor
                
                # Update status based on last_seen
                device.status = self._compute_device_status(device.last_seen)
                
                db.commit()
                db.refresh(device)
                logger.debug(f"Updated device: {device_id} ({ip}) - Status: {device.status} - Confidence: {confidence}")
            else:
                # Classify device type
                device_type = self._classify_device_type(ip, mac, best_name, vendor)
                
                # Create new device
                device = models.Device(
                    device_id=device_id,
                    ip_address=ip,
                    mac_address=mac,
                    hostname=best_name,
                    vendor=vendor,
                    source=source,
                    status="ACTIVE",
                    risk_score=0.0,
                    risk_level="GREEN",
                    first_seen=now,
                    last_seen=now,
                    quarantined=0
                )
                db.add(device)
                db.commit()
                db.refresh(device)
                
                # Display name priority: device_name > hostname > vendor > device_type > IP
                display_name = best_name or device_type.title() or ip
                mac_label = f"(randomized)" if is_random_mac else f"({mac})"
                logger.info(f"NEW DEVICE: {display_name} {mac_label} at {ip} - Type: {device_type} - Confidence: {confidence} - Source: {source}")
            
            return device
            
        except Exception as e:
            logger.error(f"Failed to register device {device_id}: {e}")
            db.rollback()
            return None
        finally:
            db.close()
    
    def update_device_from_traffic(self, ip: str, mac: str, packet_count: int = 1):
        """
        Update device last_seen from passive traffic monitoring (Scapy)
        Only updates existing devices - does NOT create new ones
        """
        # Exclude local machine
        if self.is_local_ip(ip):
            return
        
        device_id = mac if mac != "unknown" else ip
        
        db = SessionLocal()
        try:
            device = db.query(models.Device).filter(
                models.Device.device_id == device_id
            ).first()
            
            if device:
                # Update existing device
                device.last_seen = datetime.utcnow()
                device.status = "ACTIVE"
                db.commit()
                logger.debug(f"Traffic update: {device_id} ({ip}) - {packet_count} packets")
            else:
                # Device not in database yet - will be discovered by nmap
                logger.debug(f"Traffic from unknown device: {ip} ({mac}) - waiting for nmap discovery")
        
        except Exception as e:
            logger.error(f"Failed to update device from traffic: {e}")
            db.rollback()
        finally:
            db.close()
    
    def update_all_device_statuses(self):
        """
        Update status for all devices based on last_seen
        Called periodically to mark devices as OFFLINE
        """
        db = SessionLocal()
        try:
            devices = db.query(models.Device).all()
            updated_count = 0
            
            for device in devices:
                old_status = device.status
                new_status = self._compute_device_status(device.last_seen)
                
                if old_status != new_status:
                    device.status = new_status
                    updated_count += 1
                    logger.info(f"Device {device.device_id} status: {old_status} → {new_status}")
            
            if updated_count > 0:
                db.commit()
                logger.info(f"Updated status for {updated_count} device(s)")
        
        except Exception as e:
            logger.error(f"Failed to update device statuses: {e}")
            db.rollback()
        finally:
            db.close()
    
    def get_all_devices(self, include_offline: bool = False) -> List[Dict[str, Any]]:
        """
        Get all devices from database as dictionaries
        By default excludes OFFLINE devices
        IMPROVED: Includes confidence scoring and randomized MAC detection
        """
        db = SessionLocal()
        try:
            query = db.query(models.Device)
            
            if not include_offline:
                query = query.filter(models.Device.status != "OFFLINE")
            
            devices = query.order_by(models.Device.last_seen.desc()).all()
            
            # Convert to dictionaries to avoid detached instance errors
            device_dicts = []
            for device in devices:
                # Classify device type
                device_type = self._classify_device_type(
                    device.ip_address,
                    device.mac_address,
                    device.hostname,
                    device.vendor
                )
                
                # Check if randomized MAC
                is_random_mac = self._is_randomized_mac(device.mac_address)
                
                # Compute confidence
                confidence = self._compute_confidence_score(
                    device.mac_address,
                    device.hostname,
                    device.vendor,
                    device.source
                )
                
                device_dicts.append({
                    'id': device.id,
                    'device_id': device.device_id,
                    'ip_address': device.ip_address,
                    'mac_address': device.mac_address,
                    'hostname': device.hostname,
                    'vendor': device.vendor,
                    'device_type': device_type,
                    'source': device.source,
                    'status': device.status,
                    'risk_score': device.risk_score,
                    'risk_level': device.risk_level,
                    'first_seen': device.first_seen,
                    'last_seen': device.last_seen,
                    'quarantined': device.quarantined,
                    'baseline_profile': device.baseline_profile,
                    'is_randomized_mac': is_random_mac,
                    'confidence': confidence
                })
            
            return device_dicts
        finally:
            db.close()
    
    def get_device_count(self, status: Optional[str] = None) -> int:
        """
        Get device count
        If status specified, count only devices with that status
        """
        db = SessionLocal()
        try:
            query = db.query(models.Device)
            
            if status:
                query = query.filter(models.Device.status == status)
            else:
                # By default, count only ACTIVE and RECENTLY_SEEN
                query = query.filter(models.Device.status.in_(["ACTIVE", "RECENTLY_SEEN"]))
            
            return query.count()
        finally:
            db.close()
    
    def cleanup_offline_devices(self, max_age_days: int = 7):
        """
        Remove devices that have been offline for too long
        Default: 7 days
        """
        db = SessionLocal()
        try:
            cutoff = datetime.utcnow() - timedelta(days=max_age_days)
            
            deleted = db.query(models.Device).filter(
                models.Device.last_seen < cutoff,
                models.Device.status == "OFFLINE"
            ).delete()
            
            db.commit()
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} offline device(s) older than {max_age_days} days")
            
            return deleted
        
        except Exception as e:
            logger.error(f"Failed to cleanup offline devices: {e}")
            db.rollback()
            return 0
        finally:
            db.close()


# Global device manager instance
device_manager = DeviceManager()
