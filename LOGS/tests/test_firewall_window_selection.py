from PyQt5.QtCore import Qt

from gui.firewall_window import FirewallDemoWindow


def test_selected_rule_name_uses_sorted_issues_table_row(qapp):
    window = FirewallDemoWindow()
    try:
        issues = [
            {
                "rule_name": "Zulu Rule",
                "issue_type": "Disabled Rule",
                "severity": "Low",
                "suggested_fix": "Review rule.",
            },
            {
                "rule_name": "Alpha Rule",
                "issue_type": "Duplicate Rule",
                "severity": "Medium",
                "suggested_fix": "Remove duplicate.",
            },
        ]
        window._populate_issues(issues)
        window._tabs.setCurrentIndex(0)
        window._table.sortItems(0, Qt.AscendingOrder)
        window._table.selectRow(0)
        window._table.setCurrentCell(0, 0)

        expected_name = window._table.item(0, 0).text()
        assert window._selected_rule_name() == expected_name
    finally:
        window.close()


def test_selected_rule_name_uses_sorted_all_rules_table_row(qapp):
    window = FirewallDemoWindow()
    try:
        rules = [
            {
                "DisplayName": "Zulu Rule",
                "Enabled": True,
                "Direction": "Inbound",
                "Action": "Allow",
                "Profile": "Private",
            },
            {
                "DisplayName": "Alpha Rule",
                "Enabled": True,
                "Direction": "Inbound",
                "Action": "Block",
                "Profile": "Any",
            },
        ]
        window._populate_all_rules(rules)
        window._tabs.setCurrentIndex(1)
        window._all_table.sortItems(0, Qt.AscendingOrder)
        window._all_table.selectRow(0)
        window._all_table.setCurrentCell(0, 0)

        expected_name = window._all_table.item(0, 0).text()
        assert window._selected_rule_name() == expected_name
    finally:
        window.close()

