"""Read-only discovery status. Collection starts only through the local CLI."""
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import DiscoverySession

router = APIRouter()


def collection_status(db, now=None):
    now = now or datetime.utcnow()
    session = db.get(DiscoverySession, 1)
    if session is None:
        return {"active": False, "state": "offline", "scope": None,
                "last_scan": None, "observed_count": None, "error": None}
    active = bool(not session.stop_requested and session.lease_expires and
                  session.lease_expires > now and session.status in {"starting", "scanning", "running"})
    state = session.status
    if not active and state in {"starting", "scanning", "running"}:
        state = "stale"
    return {
        "active": active, "state": state, "scope": session.scope,
        "last_scan": session.last_success.isoformat() + "Z" if session.last_success else None,
        "observed_count": session.observed_count if session.last_success else None,
        "interval_seconds": session.interval_seconds, "error": session.error,
        "limitations": "Observed hosts, not a complete router client list. Missing names/MACs stay unknown. No endpoint verdict or containment.",
    }


@router.get("/status")
def status(db: Session = Depends(get_db)):
    return collection_status(db)
