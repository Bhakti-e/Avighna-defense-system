"""Lazy exports: importing core must not load/train models or initialize sensors."""
from importlib import import_module

_EXPORTS = {
    "compute_risk": "risk_scoring", "score_to_level": "risk_scoring",
    "ReconnaissanceDetector": "reconnaissance",
    "predict_attack_phase": "reconnaissance",
    "enhanced_ml_engine": "ml_detection",
    "forensics_engine": "forensics", "cti_manager": "cti",
}
__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    value = getattr(import_module(f".{_EXPORTS[name]}", __name__), name)
    globals()[name] = value
    return value
