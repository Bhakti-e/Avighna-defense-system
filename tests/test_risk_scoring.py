"""Offline regression tests; no server, database, models, or network required.

Run: python -B -m unittest discover -s tests -p test_risk_scoring.py -v
The config boundary is stubbed to avoid loading local secrets. Loading this
module directly also avoids core/__init__.py's model-loading side effects.
"""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


class TelemetryHealthReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = ModuleType("backend.config")
        config.settings = SimpleNamespace(
            risk_threshold_red=70, risk_threshold_yellow=40,
            risk_weight_failed_logins=2.5, risk_weight_connections=1.0,
            risk_weight_bytes_out=1.0, risk_weight_suspicious_file=15.0,
            risk_weight_recon_score=10.0, risk_weight_telemetry_health=15.0,
        )
        source = Path(__file__).resolve().parents[1] / "backend/core/risk_scoring.py"
        spec = importlib.util.spec_from_file_location("backend.core.risk_scoring", source)
        cls.risk_module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"backend.config": config}):
            spec.loader.exec_module(cls.risk_module)

    def test_lost_health_is_not_reported_as_healthy(self):
        result = self.risk_module.compute_risk({}, telemetry_health_score=0.0)
        self.assertEqual(result["telemetry_health_score"], 0.0)

    def test_explicit_unknown_health_remains_unknown(self):
        result = self.risk_module.compute_risk({}, telemetry_health_score=None)
        self.assertIsNone(result["telemetry_health_score"])

    def test_omitted_health_remains_unknown(self):
        result = self.risk_module.compute_risk({})
        self.assertIsNone(result["telemetry_health_score"])

    def test_known_health_scores_are_preserved(self):
        for score in (20.0, 75.0, 100.0):
            with self.subTest(score=score):
                result = self.risk_module.compute_risk({}, telemetry_health_score=score)
                self.assertEqual(result["telemetry_health_score"], score)


if __name__ == "__main__":
    unittest.main()
