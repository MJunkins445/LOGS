import json

from core.firewall import FirewallAnalyzer


def test_get_firewall_rules_parses_json_list(monkeypatch):
    analyzer = FirewallAnalyzer()
    payload = [
        {"DisplayName": "Rule A", "Enabled": True},
        {"DisplayName": "Rule B", "Enabled": False},
    ]
    monkeypatch.setattr(
        analyzer, "_run_powershell", lambda *_args, **_kwargs: json.dumps(payload)
    )

    rules = analyzer.get_firewall_rules()
    assert len(rules) == 2
    assert rules[0]["DisplayName"] == "Rule A"
    assert rules[1]["DisplayName"] == "Rule B"


def test_get_firewall_rules_parses_single_json_dict(monkeypatch):
    analyzer = FirewallAnalyzer()
    payload = {"DisplayName": "Only Rule", "Enabled": True}
    monkeypatch.setattr(
        analyzer, "_run_powershell", lambda *_args, **_kwargs: json.dumps(payload)
    )

    rules = analyzer.get_firewall_rules()
    assert len(rules) == 1
    assert rules[0]["DisplayName"] == "Only Rule"


def test_analyze_detects_disabled_duplicate_and_permissive_rules(monkeypatch):
    analyzer = FirewallAnalyzer()
    rules = [
        {
            "DisplayName": "Shared Name",
            "Enabled": False,
            "Action": "Block",
            "Direction": "Inbound",
            "Profile": "Private",
        },
        {
            "DisplayName": "Shared Name",
            "Enabled": True,
            "Action": "Allow",
            "Direction": "Inbound",
            "Profile": "Any",
        },
        {
            "DisplayName": "Numeric Any Profile",
            "Enabled": True,
            "Action": "2",
            "Direction": "1",
            "Profile": "2147483647",
        },
    ]
    monkeypatch.setattr(analyzer, "get_firewall_rules", lambda: rules)

    result = analyzer.analyze()
    issue_types = [issue["issue_type"] for issue in result["issues"]]

    assert result["total_rules"] == 3
    assert "Disabled Rule" in issue_types
    assert "Duplicate Rule" in issue_types
    assert issue_types.count("Overly Permissive (Any Profile)") == 2

