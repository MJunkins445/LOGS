"""
L.O.G.S. — Anomaly Detector Module
Compares current scan results against a saved baseline.
Uses rule-based comparison plus optional Isolation Forest (scikit-learn).
"""

import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger("logs.anomaly_detector")

_BASELINE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "baseline.json"
)


class AnomalyDetector:
    """
    Detects network anomalies by comparing the current scan to a saved baseline.

    Rule-based checks:
    - New open ports (not in baseline)
    - Ports that closed (were open in baseline)

    ML-based checks (optional, requires scikit-learn):
    - Isolation Forest on feature vectors derived from scan metrics
    """

    def detect(self, current_scan: Dict) -> List[str]:
        """
        Run anomaly detection against the baseline.

        Args:
            current_scan: Results from NetworkScanner.scan_localhost()

        Returns:
            List of human-readable anomaly description strings.
            Empty list if no anomalies or no baseline exists.
        """
        anomalies: List[str] = []

        baseline = self._load_baseline()
        if not baseline:
            logger.info("No baseline found - saving current scan as new baseline.")
            self._save_baseline(current_scan)
            return []

        # --- Rule-based port comparison ---
        baseline_open = {
            p["port"]
            for p in baseline.get("ports", [])
            if p.get("state") == "open"
        }
        current_open = {
            p["port"]
            for p in current_scan.get("ports", [])
            if p.get("state") == "open"
        }

        for port in sorted(current_open - baseline_open):
            msg = f"New open port detected: {port}"
            anomalies.append(msg)
            logger.warning(f"ANOMALY: {msg}")

        for port in sorted(baseline_open - current_open):
            msg = f"Port no longer open (was in baseline): {port}"
            anomalies.append(msg)
            logger.info(f"Change: {msg}")

        # --- ML-based anomaly detection (optional) ---
        ml_anomalies = self._ml_detect(current_scan, baseline)
        anomalies.extend(ml_anomalies)

        # Update baseline with the current scan so it stays fresh
        self._save_baseline(current_scan)

        return anomalies

    def _build_feature_vector(self, scan: Dict) -> List[float]:
        """Build a numeric feature vector from a scan result."""
        ports = scan.get("ports", [])
        open_ports  = [p for p in ports if p.get("state") == "open"]
        risky       = [p for p in open_ports if p.get("is_risky", False)]
        critical    = [p for p in open_ports if p.get("is_critical", False)]
        protocols   = {p.get("proto", "tcp") for p in open_ports}

        return [
            float(len(open_ports)),
            float(len(risky)),
            float(len(critical)),
            float(len(protocols)),
        ]

    def _ml_detect(self, current: Dict, baseline: Dict) -> List[str]:
        """Use Isolation Forest for ML-based anomaly detection."""
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
        except ImportError:
            logger.debug("scikit-learn not available; skipping ML anomaly detection.")
            return []

        try:
            base_vec = self._build_feature_vector(baseline)
            curr_vec = self._build_feature_vector(current)

            base_arr = np.array(base_vec)
            training_data = np.array([
                base_arr,
                np.maximum(0, base_arr + 1),
                np.maximum(0, base_arr - 1),
                np.maximum(0, base_arr + [1, 0, 0, 0]),
                np.maximum(0, base_arr + [0, 1, 0, 0]),
            ])

            clf = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
            )
            clf.fit(training_data)

            prediction = clf.predict([curr_vec])
            score      = clf.score_samples([curr_vec])[0]

            logger.debug(f"IsolationForest prediction={prediction[0]}, score={score:.4f}")

            if prediction[0] == -1:
                msg = (
                    f"ML Detection (Isolation Forest): Network state is anomalous "
                    f"compared to baseline (anomaly score: {score:.3f})"
                )
                logger.warning(f"ANOMALY: {msg}")
                return [msg]

            return []

        except Exception as exc:
            logger.warning(f"ML anomaly detection failed: {exc}")
            return []

    def _load_baseline(self) -> Optional[Dict]:
        """Load the baseline JSON from disk."""
        try:
            if os.path.exists(_BASELINE_PATH) and os.path.getsize(_BASELINE_PATH) > 5:
                with open(_BASELINE_PATH, "r", encoding="utf-8") as fh:
                    return json.load(fh)
        except Exception as exc:
            logger.error(f"Could not load baseline: {exc}")
        return None

    def _save_baseline(self, scan: Dict):
        """Persist scan results as the new baseline."""
        try:
            os.makedirs(os.path.dirname(_BASELINE_PATH), exist_ok=True)
            with open(_BASELINE_PATH, "w", encoding="utf-8") as fh:
                json.dump(scan, fh, indent=2)
            logger.info("Baseline updated.")
        except Exception as exc:
            logger.error(f"Could not save baseline: {exc}")

    def reset_baseline(self):
        """Delete the existing baseline so the next scan creates a fresh one."""
        try:
            if os.path.exists(_BASELINE_PATH):
                os.remove(_BASELINE_PATH)
                logger.info("Baseline reset successfully.")
        except Exception as exc:
            logger.error(f"Could not reset baseline: {exc}")
