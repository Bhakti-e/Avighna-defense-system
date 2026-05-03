"""
SQLAlchemy ORM Models for DOME/AVIGHNA
All fields are updated only from real events - NO FAKE DATA
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Index, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user")  # user/admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)


class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(255), unique=True, nullable=False, index=True)
    
    # Status updated only after risk decision
    status = Column(String(50), default="OK")  # OK/UNDER_OBSERVATION/ISOLATED
    
    # Risk updated only from compute_risk output
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="GREEN")  # GREEN/YELLOW/RED
    
    # Timestamps - real only
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Baseline profile - computed from telemetry_history after N samples, else NULL
    baseline_profile = Column(JSON, nullable=True)
    
    # Network info - only if truly obtained
    mac_address = Column(String(17), nullable=True)
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)  # Device vendor from MAC OUI
    
    # Quarantine info - set only when isolation happens
    quarantined = Column(Integer, default=0)  # 0=false, 1=true (for SQLite compatibility)
    quarantine_time = Column(DateTime, nullable=True)
    isolation_details = Column(JSON, nullable=True)
    
    # Observation info - set only when observation happens
    observation_details = Column(JSON, nullable=True)
    
    # Source tracking
    source = Column(String(50), nullable=True)  # discovery/arp/nmap/agent/manual
    
    # Relationships
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    telemetry_history = relationship("TelemetryHistory", back_populates="device", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="device", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_device_last_seen', 'last_seen'),
        Index('idx_device_risk', 'risk_score'),
    )


class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Foreign key to device
    device_id = Column(String(255), ForeignKey("devices.device_id"), nullable=False, index=True)
    
    # Alert metadata
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Risk info - from compute_risk output
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)  # GREEN/YELLOW/RED
    
    # Detection info - from real pipeline
    detection_type = Column(String(100), nullable=False)  # Rules/ML/Recon/Forensics/YARA/Ensemble
    severity = Column(Integer, default=1)  # 1=low, 2=medium, 3=high
    
    # Response info - from response module
    response_action = Column(String(50), nullable=True)  # OBSERVE/ISOLATE/AUTO_FIX/NONE
    
    # Details - store real telemetry snapshot + reasons + model outputs
    details_json = Column(JSON, nullable=False)
    
    # Human-readable reason
    reason = Column(Text, nullable=True)
    
    # Relationship
    device = relationship("Device", back_populates="alerts")
    reports = relationship("Report", back_populates="alert", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_alert_timestamp', 'timestamp'),
        Index('idx_alert_device_time', 'device_id', 'timestamp'),
    )


class TelemetryHistory(Base):
    __tablename__ = "telemetry_history"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Foreign key to device
    device_id = Column(String(255), ForeignKey("devices.device_id"), nullable=False, index=True)
    
    # Timestamp
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Telemetry fields - from real agent payload
    failed_logins = Column(Integer, default=0)
    connections_count = Column(Integer, default=0)  # Always int
    bytes_out = Column(Integer, default=0)
    
    # JSON fields
    outbound_ips = Column(JSON, nullable=True)  # Array of IPs
    suspicious_file = Column(String(500), nullable=True)
    recon_indicators = Column(JSON, nullable=True)
    
    # Store original validated payload for audit
    raw_payload = Column(JSON, nullable=True)
    
    # Relationship
    device = relationship("Device", back_populates="telemetry_history")
    
    # Indexes
    __table_args__ = (
        Index('idx_telemetry_device_time', 'device_id', 'timestamp'),
    )


class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Foreign keys
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    device_id = Column(String(255), ForeignKey("devices.device_id"), nullable=False, index=True)
    
    # Report metadata
    report_type = Column(String(50), nullable=False)  # INCIDENT/ISOLATION
    file_path = Column(String(500), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Relationships
    alert = relationship("Alert", back_populates="reports")
    device = relationship("Device", back_populates="reports")
    
    # Indexes
    __table_args__ = (
        Index('idx_report_created', 'created_at'),
    )
