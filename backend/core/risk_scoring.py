# backend/risk_score.py
import time
import math
from typing import Dict, Any, Optional
from ..config import settings

# thresholds for color mapping
def score_to_level(score: float):
    if score >= settings.risk_threshold_red:
        return "RED"
    if score >= settings.risk_threshold_yellow:
        return "YELLOW"
    return "GREEN"

def _bytes_score(bytes_out: int):
    if bytes_out <= 0:
        return 0.0
    return min(20.0, math.log10(bytes_out + 1) * 4.0)

def _connections_score(connections):
    # connections may be an int count or a list/dict of connection details
    try:
        if isinstance(connections, int):
            count = connections
        elif isinstance(connections, (list, tuple)):
            count = len(connections)
        elif isinstance(connections, dict):
            # sum lengths of lists in dict values if present
            count = sum(len(v) if hasattr(v, '__len__') else 1 for v in connections.values())
        else:
            count = int(connections)
    except Exception:
        count = 0
    return min(15.0, count * 0.8)

def _failed_logins_score(failed_logins: int):
    return min(15.0, failed_logins * 3.0)

def _risky_outbound_score(outbound_ips):
    if not outbound_ips:
        return 0.0
    for ip in outbound_ips:
        if isinstance(ip, str) and ip.startswith(("45.", "89.", "185.", "103.", "91.")):
            return 20.0
    return 0.0

def compute_recon_score(history):
    """
    history: list of (ts, event_type, extra)
    Heuristic: count scan/probe events in 24-hour window
    """
    if not history:
        return 0.0
    now = time.time()
    window = 60 * 60 * 24  # 24 hours window
    cnt = 0
    for ts, etype, extra in history:
        if now - ts <= window:
            if etype in ("scan_probe", "port_probe", "suspicious_connection"):
                cnt += 1
    if cnt == 0:
        return 0.0
    return min(30.0, cnt * 3.0)

def compute_risk(payload: Dict[str, Any],
                 anomaly_score: Optional[float] = None,
                 forensics_score: Optional[float] = None,
                 enhanced_ml_result: Optional[Dict[str, Any]] = None,
                 history: Optional[list] = None,
                 telemetry_health_score: Optional[float] = None) -> Dict[str, Any]:
    """
    Enhanced risk computation: 60% ML + 40% Forensics + Rules
    payload: TelemetryIn dict
    anomaly_score: float (0..1) where 1 = highly anomalous
    forensics_score: float (0..100) from forensics engine
    enhanced_ml_result: dict with ensemble ML predictions
    history: per-device recent events for recon detection
    """
    # Base rule-based scoring (traditional approach)
    rule_score = 0.0
    rule_score += settings.risk_weight_failed_logins * (_failed_logins_score(payload.get("failed_logins", 0)) / 15.0)
    rule_score += settings.risk_weight_connections * (_connections_score(payload.get("connections", 0)) / 15.0)
    rule_score += settings.risk_weight_bytes_out * (_bytes_score(payload.get("bytes_out", 0)) / 20.0)
    if payload.get("suspicious_file"):
        rule_score += settings.risk_weight_suspicious_file
    rule_score += _risky_outbound_score(payload.get("outbound_ips", []))
    
    # Reconnaissance scoring
    recon = compute_recon_score(history or [])
    rule_score += settings.risk_weight_recon_score * (recon / 30.0)
    
    # Telemetry health penalty - higher penalty for lost telemetry
    telemetry_penalty = 0.0
    if telemetry_health_score is not None:
        # Convert health score (100=good, 0=bad) to penalty (0=no penalty, high=penalty)
        # Healthy telemetry (90-100) = no penalty
        # Degrading telemetry (50-89) = moderate penalty
        # Lost telemetry (0-49) = high penalty
        if telemetry_health_score >= 90:
            telemetry_penalty = 0.0
        elif telemetry_health_score >= 50:
            # Linear penalty from 0 to 15 points
            telemetry_penalty = settings.risk_weight_telemetry_health * (90 - telemetry_health_score) / 40.0
        else:
            # High penalty for lost telemetry
            telemetry_penalty = settings.risk_weight_telemetry_health
    
    rule_score += telemetry_penalty
    
    # ENTERPRISE SCORING: 60% ML + 40% Forensics
    ml_score = 0.0
    forensics_contribution = 0.0
    
    # ML Component (60% weight)
    if enhanced_ml_result and enhanced_ml_result.get('anomaly_score') is not None:
        ml_score = enhanced_ml_result['anomaly_score'] * 100.0  # Convert to 0-100 scale
        ml_confidence = enhanced_ml_result.get('ensemble_confidence', 0.5)
        ml_agreement = enhanced_ml_result.get('model_agreement', 0.5)
        
        # Boost ML score based on model confidence and agreement
        ml_score *= (0.7 + 0.3 * ml_confidence * ml_agreement)
    elif anomaly_score is not None:
        # Fallback to basic anomaly score
        ml_score = anomaly_score * 100.0
    
    # Forensics Component (40% weight)
    if forensics_score is not None:
        forensics_contribution = forensics_score  # Already 0-100 scale
    
    # Combine scores: 60% ML + 40% Forensics + Rules boost
    enterprise_score = (ml_score * 0.6) + (forensics_contribution * 0.4)
    
    # Add rule-based boost (max 20 points)
    final_score = min(100.0, enterprise_score + min(20.0, rule_score))
    
    level = score_to_level(final_score)
    
    return {
        "risk_score": round(final_score, 2), 
        "risk_level": level, 
        "recon_score": round(recon, 2),
        "ml_score": round(ml_score, 2),
        "forensics_score": round(forensics_contribution, 2),
        "rule_score": round(rule_score, 2),
        "telemetry_health_score": telemetry_health_score or 100.0,
        "telemetry_penalty": round(telemetry_penalty, 2),
        "enterprise_mode": True
    }
