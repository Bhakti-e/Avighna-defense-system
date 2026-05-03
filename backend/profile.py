# backend/profile.py
"""
Device Behavioral Baseline & Deviation Modeling
------------------------------------------------
This module learns a simple statistical baseline for each device and
computes how far the current behavior deviates from the device's learned norm.

Baseline model stored in:
state.device_profile = {
    device_id: {
        "count": int,
        "avg_failed": float,
        "avg_conn": float,
        "avg_bytes": float
    }
}
"""

import math
from typing import Dict, Any


# ---------------------------
# 1) Update baseline profile
# ---------------------------
def update_profile(state, device_id: str, payload: Dict[str, Any]):
    """
    Incrementally update the per-device baseline profile.
    payload must contain: failed_logins, connections, bytes_out
    """

    failed = float(payload.get("failed_logins", 0))
    conns = float(payload.get("connections", 0))
    bytes_out = float(payload.get("bytes_out", 0))

    # ensure dict exists
    prof = state.device_profile.setdefault(device_id, {
        "count": 0,
        "avg_failed": 0.0,
        "avg_conn": 0.0,
        "avg_bytes": 0.0,
    })

    c = prof["count"]

    # incremental average update
    prof["avg_failed"] = (prof["avg_failed"] * c + failed) / (c + 1)
    prof["avg_conn"] = (prof["avg_conn"] * c + conns) / (c + 1)
    prof["avg_bytes"] = (prof["avg_bytes"] * c + bytes_out) / (c + 1)

    prof["count"] = c + 1


# -----------------------------------
# 2) Compute deviation score (0–100)
# -----------------------------------
def compute_deviation_score(state, device_id: str, payload: Dict[str, Any]) -> float:
    """
    Returns a deviation score representing how different the current
    payload is from the baseline profile.

    score range:
       0  => normal
     100  => extremely unusual
    """

    profile = state.device_profile.get(device_id)
    if not profile or profile["count"] < 5:
        # not enough data yet to judge deviation
        return 0.0

    failed = float(payload.get("failed_logins", 0))
    conns = float(payload.get("connections", 0))
    bytes_out = float(payload.get("bytes_out", 0))

    # baseline values
    bf = profile["avg_failed"]
    bc = profile["avg_conn"]
    bb = profile["avg_bytes"]

    # safe guard zeros
    def safe_div(a, b):
        return abs(a - b) / max(1.0, b)

    # compute relative deviation
    df = safe_div(failed, bf + 1e-5)
    dc = safe_div(conns, bc + 1e-5)
    db = safe_div(bytes_out, bb + 1e-5)

    # combine into overall deviation
    dev = (df * 0.35 + dc * 0.35 + db * 0.30) * 100.0

    # clamp range
    dev = min(100.0, max(0.0, dev))

    return float(round(dev, 2))
