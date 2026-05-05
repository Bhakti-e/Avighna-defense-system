"""
AVIGHNA Configuration Management
=================================
Centralized configuration using Pydantic Settings
All hardcoded values moved here for production-grade configuration
"""

from pydantic_settings import BaseSettings
from typing import Optional, List
from functools import lru_cache
import os


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables
    Supports .env file and system environment variables
    """
    
    # ============================================================================
    # APPLICATION
    # ============================================================================
    app_name: str = "AVIGHNA"
    app_version: str = "3.0.0"
    app_description: str = "Network Defense & Threat Detection Platform"
    edition: str = "defense"  # defense, startup, ot
    environment: str = "development"  # development, staging, production
    debug: bool = False
    
    # ============================================================================
    # SERVER
    # ============================================================================
    server_host: str = "0.0.0.0"
    server_port: int = 8000
    server_workers: int = 4
    server_reload: bool = False
    
    # ============================================================================
    # DATABASE
    # ============================================================================
    # Supports both SQLite (development) and PostgreSQL (production)
    # SQLite: sqlite:///./dome.db
    # PostgreSQL: postgresql://user:password@host:5432/avighna
    # TimescaleDB: postgresql://user:password@host:5432/avighna?options=-c%20timescaledb.telemetry_level=off
    database_url: str = "sqlite:///./avighna_defense.db"
    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_echo: bool = False  # SQL query logging
    
    # TimescaleDB support for time-series telemetry
    use_timescaledb: bool = False  # Enable hypertables for telemetry_history
    
    # ============================================================================
    # NETWORK SCANNING
    # ============================================================================
    # Scapy passive monitoring
    enable_scapy_monitor: bool = True  # Enable real-time ARP/WiFi monitoring
    scapy_interface: Optional[str] = None  # Network interface (None = auto-detect)
    scapy_require_admin: bool = True  # Require admin/root privileges
    
    # ============================================================================
    # SECURITY
    # ============================================================================
    # Enforcement mode
    safe_mode: bool = False  # false = attempt real enforcement (requires admin/root)
    gateway_mode: bool = True  # true = backend acts as network gateway
    
    # API Security
    api_key_enabled: bool = False
    api_key: Optional[str] = None
    jwt_secret_key: str = "change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 60
    
    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]
    
    # ============================================================================
    # RISK SCORING
    # ============================================================================
    risk_threshold_yellow: int = 40  # Observation threshold
    risk_threshold_red: int = 70     # Isolation threshold
    
    # Risk weights
    risk_weight_failed_logins: float = 2.5
    risk_weight_connections: float = 1.0
    risk_weight_bytes_out: float = 1.0
    risk_weight_suspicious_file: float = 15.0
    risk_weight_risky_outbound: float = 20.0
    risk_weight_anomaly_score: float = 30.0
    risk_weight_recon_score: float = 10.0
    risk_weight_telemetry_health: float = 15.0
    
    # ============================================================================
    # TELEMETRY HEALTH
    # ============================================================================
    telemetry_timeout: int = 60  # seconds - mark as stale
    telemetry_lost_timeout: int = 180  # seconds - mark as lost
    
    # ============================================================================
    # CYBER THREAT INTELLIGENCE (CTI)
    # ============================================================================
    cti_enabled: bool = True
    cti_update_interval: int = 3600  # seconds (1 hour)
    
    # Threat feeds
    cti_urlhaus_enabled: bool = True
    cti_threatfox_enabled: bool = True
    cti_feodo_enabled: bool = True
    
    # VirusTotal
    virustotal_enabled: bool = False
    virustotal_api_key: str = "demo_key"
    virustotal_rate_limit: int = 4  # requests per minute (free tier)
    
    # MISP (Malware Information Sharing Platform)
    misp_enabled: bool = False
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    misp_verify_ssl: bool = True
    
    # CTI Risk Boosting
    cti_boost_ip_high: int = 30
    cti_boost_ip_medium: int = 20
    cti_boost_ip_low: int = 10
    cti_boost_hash: int = 40
    cti_boost_virustotal_high: int = 50  # >10 detections
    cti_boost_virustotal_medium: int = 30  # 3-10 detections
    cti_boost_virustotal_low: int = 15  # 1-3 detections
    
    # ============================================================================
    # MACHINE LEARNING
    # ============================================================================
    ml_enabled: bool = True
    ml_model_path_if: str = "backend/enhanced_if_model.joblib"
    ml_model_path_autoencoder: str = "backend/autoencoder_model.h5"
    ml_model_path_lstm: str = "backend/lstm_model.h5"
    
    # ML weights for ensemble
    ml_weight_isolation_forest: float = 0.3
    ml_weight_autoencoder: float = 0.4
    ml_weight_lstm: float = 0.3
    
    # ML training
    ml_retrain_enabled: bool = False
    ml_retrain_interval: int = 604800  # seconds (7 days)
    ml_min_samples_for_training: int = 1000
    
    # ============================================================================
    # FORENSICS
    # ============================================================================
    forensics_enabled: bool = True
    forensics_yara_enabled: bool = True
    forensics_yara_rules_path: str = "backend/yara_rules"
    forensics_pe_analysis_enabled: bool = True
    
    # Directories
    reports_dir: str = "reports"
    pdf_reports_dir: str = "reports/pdf"
    backups_dir: str = "backups"
    
    # ============================================================================
    # RECONNAISSANCE DETECTION
    # ============================================================================
    recon_enabled: bool = True
    recon_port_scan_threshold: int = 20  # ports scanned to trigger alert
    recon_time_window: int = 300  # seconds (5 minutes)
    
    # ============================================================================
    # ACTIVE SCANNING
    # ============================================================================
    active_scan_enabled: bool = True
    active_scan_interval: int = 300  # seconds (5 minutes)
    arp_scan_interval: int = 8  # seconds
    
    # ============================================================================
    # RESPONSE ACTIONS
    # ============================================================================
    response_auto_fix_enabled: bool = True
    response_observation_enabled: bool = True
    response_isolation_enabled: bool = True
    
    # Observation settings
    observation_bandwidth_limit_kbps: int = 100
    observation_allowed_outbound: List[str] = []
    
    # ============================================================================
    # ALERTING
    # ============================================================================
    alerts_max_in_memory: int = 1000
    alerts_retention_days: int = 90
    
    # Email notifications
    email_enabled: bool = False
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    alert_email_to: Optional[str] = None
    
    # Slack notifications
    slack_enabled: bool = False
    slack_webhook_url: Optional[str] = None
    
    # Webhook notifications
    webhook_enabled: bool = False
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    
    # ============================================================================
    # LOGGING
    # ============================================================================
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_file: str = "backend.log"
    log_max_bytes: int = 10485760  # 10 MB
    log_backup_count: int = 5
    log_format: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    
    # ============================================================================
    # PERFORMANCE
    # ============================================================================
    max_telemetry_batch_size: int = 100
    max_concurrent_requests: int = 100
    request_timeout: int = 30  # seconds
    
    # ============================================================================
    # MITRE ATT&CK MAPPING
    # ============================================================================
    mitre_attack_enabled: bool = False
    mitre_attack_version: str = "v13"
    
    # ============================================================================
    # NETWORK MONITORING
    # ============================================================================
    network_monitoring_enabled: bool = False
    network_cidr: str = "192.168.1.0/24"  # Your network range
    network_interface: str = "eth0"  # Network interface to monitor
    network_scan_interval: int = 60  # Seconds between scans
    auto_block_rogue_devices: bool = False  # Auto-block unauthorized devices
    device_whitelist_mode: bool = True  # Only allow whitelisted devices
    
    # ============================================================================
    # ROUTER DISCOVERY (PRIMARY)
    # ============================================================================
    router_discovery_enabled: bool = True  # Use router as primary device source
    router_ip: str = "192.168.0.1"  # Router admin IP
    router_username: str = "admin"  # Router admin username
    router_password: str = "admin"  # Router admin password
    router_type: str = "tplink"  # Router type: tplink, generic, netgear, asus
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        # Allow environment variables to override .env file
        env_prefix = ""


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance
    Use this function to access settings throughout the application
    """
    return Settings()


# Global settings instance
settings = get_settings()


# Helper functions for common checks
def is_production() -> bool:
    """Check if running in production environment"""
    return settings.environment == "production"


def is_development() -> bool:
    """Check if running in development environment"""
    return settings.environment == "development"


def is_safe_mode() -> bool:
    """Check if running in safe mode (simulated enforcement)"""
    return settings.safe_mode


def can_enforce() -> bool:
    """Check if real enforcement is allowed"""
    return not settings.safe_mode and settings.gateway_mode
