from core.risk_engine import RiskEngine


def test_calculate_risk_caps_at_100():
    engine = RiskEngine()
    scan_results = {
        "ports": [
            {"port": 21, "state": "open", "is_risky": True, "is_critical": True},
            {"port": 22, "state": "open", "is_risky": True, "is_critical": True},
            {"port": 23, "state": "open", "is_risky": True, "is_critical": True},
            {"port": 445, "state": "open", "is_risky": True, "is_critical": True},
            {"port": 3389, "state": "open", "is_risky": True, "is_critical": True},
            {"port": 80, "state": "open", "is_risky": True, "is_critical": False},
        ]
    }
    firewall_results = {
        "issues": [
            {"severity": "Critical", "rule_name": "A"},
            {"severity": "High", "rule_name": "B"},
            {"severity": "Medium", "rule_name": "C"},
            {"severity": "Low", "rule_name": "D"},
        ]
    }

    assert engine.calculate_risk(scan_results, firewall_results) == 100


def test_risk_level_and_color_mappings():
    engine = RiskEngine()
    assert engine.get_risk_level(10) == "Low"
    assert engine.get_risk_level(50) == "Medium"
    assert engine.get_risk_level(90) == "High"

    assert engine.get_risk_color(10) == "#00ff88"
    assert engine.get_risk_color(50) == "#ffaa00"
    assert engine.get_risk_color(90) == "#ff4444"


def test_remediation_hints_include_ports_and_firewall():
    engine = RiskEngine()
    scan_results = {
        "ports": [
            {"port": 445, "state": "open"},
            {"port": 22, "state": "open"},
        ]
    }
    firewall_results = {
        "issues": [
            {"severity": "High", "suggested_fix": "Restrict Any profile rule."},
            {"severity": "Low", "suggested_fix": "Document rule purpose."},
        ]
    }

    hints = engine.get_remediation_hints(scan_results, firewall_results)

    assert any("port 445" in hint for hint in hints)
    assert any("port 22" in hint for hint in hints)
    assert any("Firewall: Restrict Any profile rule." == hint for hint in hints)
    assert all("Document rule purpose." not in hint for hint in hints)

