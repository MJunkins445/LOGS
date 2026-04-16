"""
L.O.G.S. — Windows Firewall Analyzer
Uses PowerShell via subprocess to query, analyze, and manage firewall rules.
Requires Administrator privileges for full functionality.
"""

import json
import logging
import subprocess
import sys
from typing import Dict, List, Optional

logger = logging.getLogger("logs.firewall")

_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class FirewallAnalyzer:
    """
    Queries and analyzes Windows Firewall rules via PowerShell.

    Detects:
    - Disabled rules that should be reviewed
    - Duplicate rules (same display name)
    - Overly permissive inbound Allow/Any rules
    """

    def _run_powershell(self, command: str, timeout: int = 45) -> Optional[str]:
        """Run a PowerShell command and return stdout, or None on failure."""
        try:
            proc = subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", command,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=_CREATE_NO_WINDOW,
            )
            if proc.returncode != 0:
                if proc.stderr.strip():
                    logger.warning(f"PowerShell stderr: {proc.stderr.strip()[:200]}")
                return None
            return proc.stdout.strip() if proc.stdout else ""
        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out.")
            return None
        except FileNotFoundError:
            raise RuntimeError(
                "PowerShell not found. This tool requires Windows with PowerShell."
            )
        except Exception as exc:
            logger.error(f"PowerShell error: {exc}")
            return None

    def get_firewall_rules(self) -> List[Dict]:
        """Retrieve all Windows Firewall rules as a list of dicts."""
        cmd = (
            "Get-NetFirewallRule | "
            "Select-Object DisplayName, Enabled, Direction, Action, Profile, "
            "DisplayGroup, Description, PolicyStoreSourceType | "
            "ConvertTo-Json -Depth 2 -Compress"
        )
        output = self._run_powershell(cmd)
        if not output:
            return []
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            logger.info(f"Retrieved {len(data)} firewall rules.")
            return data
        except json.JSONDecodeError as exc:
            logger.error(f"Failed to parse firewall JSON: {exc}")
            return []

    def analyze(self) -> Dict:
        """
        Detect firewall misconfigurations.

        Returns:
            Dict with 'rules', 'issues', and 'total_rules'.
        """
        logger.info("Starting firewall analysis")
        rules = self.get_firewall_rules()
        issues: List[Dict] = []
        seen_names: Dict[str, int] = {}

        for rule in rules:
            name      = rule.get("DisplayName", "Unknown")
            enabled   = rule.get("Enabled", True)
            action    = str(rule.get("Action", ""))
            direction = str(rule.get("Direction", ""))
            profile   = str(rule.get("Profile", ""))

            # Check 1: Disabled rules
            if str(enabled).lower() in ("false", "0"):
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Disabled Rule",
                    "severity":      "Low",
                    "suggested_fix": f"Review and remove '{name}' if no longer needed.",
                })

            # Check 2: Duplicate names
            if name in seen_names:
                seen_names[name] += 1
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Duplicate Rule",
                    "severity":      "Medium",
                    "suggested_fix": f"Remove duplicate entry for '{name}' to avoid rule shadowing.",
                })
            else:
                seen_names[name] = 1

            # Check 3: Overly permissive inbound Allow on Any profile
            is_allow    = action in ("Allow", "2")
            is_inbound  = direction in ("Inbound", "1")
            is_any_prof = profile in ("Any", "4", "2147483647", "-1")

            if is_allow and is_inbound and is_any_prof:
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Overly Permissive (Any Profile)",
                    "severity":      "High",
                    "suggested_fix": f"Restrict '{name}' to Domain or Private profile only.",
                })

        logger.info(f"Analysis complete. {len(issues)} issue(s) in {len(rules)} rule(s).")
        return {"rules": rules, "issues": issues, "total_rules": len(rules)}

    def disable_rule(self, rule_name: str) -> bool:
        """Disable a firewall rule by display name."""
        safe_name = rule_name.replace("'", "''")
        result = self._run_powershell(f"Disable-NetFirewallRule -DisplayName '{safe_name}'")
        if result is None:
            logger.error(f"Failed to disable '{rule_name}'")
            return False
        logger.info(f"Disabled rule: '{rule_name}'")
        return True

    def remove_rule(self, rule_name: str) -> bool:
        """Permanently remove a firewall rule by display name."""
        safe_name = rule_name.replace("'", "''")
        result = self._run_powershell(f"Remove-NetFirewallRule -DisplayName '{safe_name}'")
        if result is None:
            logger.error(f"Failed to remove '{rule_name}'")
            return False
        logger.info(f"Removed rule: '{rule_name}'")
        return True

    def enable_rule(self, rule_name: str) -> bool:
        """Enable a firewall rule by display name."""
        safe_name = rule_name.replace("'", "''")
        result = self._run_powershell(f"Enable-NetFirewallRule -DisplayName '{safe_name}'")
        if result is None:
            logger.error(f"Failed to enable '{rule_name}'")
            return False
        logger.info(f"Enabled rule: '{rule_name}'")
        return True

    def create_rule(
        self,
        name: str,
        direction: str = "Inbound",
        action: str = "Block",
        protocol: str = "TCP",
        port: str = "Any",
        profile: str = "Any",
        description: str = "",
    ) -> bool:
        """Create a new Windows Firewall rule via New-NetFirewallRule."""
        safe_name = name.replace("'", "''")
        parts = [
            "New-NetFirewallRule",
            f"-DisplayName '{safe_name}'",
            f"-Direction {direction}",
            f"-Action {action}",
            "-Enabled True",
            f"-Profile {profile}",
        ]
        if protocol.lower() != "any":
            parts.append(f"-Protocol {protocol}")
            if port.lower() not in ("any", ""):
                parts.append(f"-LocalPort '{port}'")
        if description:
            safe_desc = description.replace("'", "''")
            parts.append(f"-Description '{safe_desc}'")
        cmd = " ".join(parts)
        result = self._run_powershell(cmd)
        if result is None:
            logger.error(f"Failed to create '{name}'")
            return False
        logger.info(f"Created rule: '{name}'")
        return True
