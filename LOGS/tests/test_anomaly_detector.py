import json

from core import anomaly_detector as anomaly_module
from core.anomaly_detector import AnomalyDetector


def test_detect_bootstraps_baseline_when_missing(tmp_path, monkeypatch):
    baseline_path = tmp_path / "baseline.json"
    monkeypatch.setattr(anomaly_module, "_BASELINE_PATH", str(baseline_path))

    detector = AnomalyDetector()
    scan = {
        "ports": [
            {"port": 80, "state": "open", "proto": "tcp", "is_risky": True, "is_critical": False}
        ]
    }

    anomalies = detector.detect(scan)

    assert anomalies == []
    assert baseline_path.exists()
    saved = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert saved["ports"][0]["port"] == 80


def test_detect_reports_new_and_closed_ports(tmp_path, monkeypatch):
    baseline_path = tmp_path / "baseline.json"
    monkeypatch.setattr(anomaly_module, "_BASELINE_PATH", str(baseline_path))

    baseline = {
        "ports": [
            {"port": 80, "state": "open", "proto": "tcp"},
            {"port": 22, "state": "open", "proto": "tcp"},
        ]
    }
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

    detector = AnomalyDetector()
    monkeypatch.setattr(detector, "_ml_detect", lambda *_args, **_kwargs: [])
    current = {
        "ports": [
            {"port": 80, "state": "open", "proto": "tcp"},
            {"port": 443, "state": "open", "proto": "tcp"},
        ]
    }

    anomalies = detector.detect(current)

    assert "New open port detected: 443" in anomalies
    assert "Port no longer open (was in baseline): 22" in anomalies

