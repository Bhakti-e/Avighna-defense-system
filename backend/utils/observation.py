"""
Observation helpers
-------------------
Simulate placing a device "under observation":
- limit_bandwidth(device_id, params)
- restrict_outbound(device_id, ips)

These functions are demo-safe: they do not change system settings, just return an action report
and print what's been (simulated) applied.
"""
import time
from typing import Dict, Any, List


def limit_bandwidth(device_id: str, limit_kbps: int = 100) -> Dict[str, Any]:
    print(f"🔍 OBSERVATION: Limiting bandwidth for {device_id} to {limit_kbps} kbps (simulated)")
    return {"device": device_id, "action": "limit_bandwidth", "limit_kbps": limit_kbps, "ts": time.time()}


def restrict_outbound(device_id: str, allowed_ips: List[str] = None) -> Dict[str, Any]:
    allowed_ips = allowed_ips or []
    print(f"🔍 OBSERVATION: Restricting outbound traffic for {device_id}. Allowed: {allowed_ips} (simulated)")
    return {"device": device_id, "action": "restrict_outbound", "allowed_ips": allowed_ips, "ts": time.time()}


def apply_observation(device_id: str, ip: str = None, params: Dict[str, Any] = None) -> Dict[str, Any]:
    params = params or {}
    bw = params.get("limit_kbps", 100)
    allowed = params.get("allowed_ips", [])
    res_bw = limit_bandwidth(device_id, bw)
    res_out = restrict_outbound(device_id, allowed)
    return {"bandwidth": res_bw, "outbound": res_out}
