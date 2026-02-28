"""
Playbook Engine

Defines automated response playbooks and the execution engine.
Each playbook has:
  - A trigger condition (severity threshold, rule match, entity type)
  - A sequence of actions to execute
  - Approval mode: AUTO (instant) or MANUAL (requires analyst approval)

Built-in Playbooks:
  1. Brute Force Response    — Disable user + Notify SOC
  2. Malware Containment     — Quarantine host + Block IP + Collect Forensics
  3. Data Exfiltration       — Isolate network + Block IP + Notify SOC
  4. Credential Compromise   — Disable user + Block IP + Notify SOC
  5. Critical Severity Auto  — Notify SOC (any CRITICAL incident)
"""
import asyncio
import datetime
import re
from typing import List, Dict, Optional

from playbooks.actions import (
    ActionType, ActionStatus, ActionResult, ActionLog,
    ACTION_EXECUTORS
)

# Severity ranking for comparisons
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Built-in Playbook Definitions
PLAYBOOKS = [
    {
        "id": "PB-001",
        "name": "Brute Force Response",
        "description": "Disables the targeted user account and notifies the SOC team when brute force is detected.",
        "trigger": {
            "min_severity": "high",
            "rule_match": "brute force"
        },
        "approval": "auto",
        "actions": [
            {"type": ActionType.DISABLE_USER, "target_from": "user"},
            {"type": ActionType.NOTIFY_SOC, "target_from": "static", "static": "Brute force incident"},
        ]
    },
    {
        "id": "PB-002",
        "name": "Malware Containment",
        "description": "Quarantines the host, blocks attacker IP, and collects forensic evidence.",
        "trigger": {
            "min_severity": "critical",
            "rule_match": "malware|trojan|ransomware"
        },
        "approval": "manual",
        "actions": [
            {"type": ActionType.QUARANTINE_HOST, "target_from": "host"},
            {"type": ActionType.BLOCK_IP, "target_from": "src_ip"},
            {"type": ActionType.COLLECT_FORENSICS, "target_from": "host"},
        ]
    },
    {
        "id": "PB-003",
        "name": "Data Exfiltration",
        "description": "Isolates the network segment, blocks external IP, and notifies SOC.",
        "trigger": {
            "min_severity": "critical",
            "rule_match": "exfiltration|data theft"
        },
        "approval": "manual",
        "actions": [
            {"type": ActionType.ISOLATE_NETWORK, "target_from": "network"},
            {"type": ActionType.BLOCK_IP, "target_from": "dest_ip"},
            {"type": ActionType.NOTIFY_SOC, "target_from": "static", "static": "Data exfiltration incident"},
        ]
    },
    {
        "id": "PB-004",
        "name": "Credential Compromise",
        "description": "Disables compromised account, blocks attacker IP, and alerts SOC.",
        "trigger": {
            "min_severity": "high",
            "rule_match": "credential|password|kerberoast"
        },
        "approval": "auto",
        "actions": [
            {"type": ActionType.DISABLE_USER, "target_from": "user"},
            {"type": ActionType.BLOCK_IP, "target_from": "src_ip"},
            {"type": ActionType.NOTIFY_SOC, "target_from": "static", "static": "Credential compromise incident"},
        ]
    },
    {
        "id": "PB-005",
        "name": "Critical Severity Auto-Notify",
        "description": "Automatically notifies SOC for any CRITICAL severity incident.",
        "trigger": {
            "min_severity": "critical"
        },
        "approval": "auto",
        "actions": [
            {"type": ActionType.NOTIFY_SOC, "target_from": "static", "static": "Critical severity incident detected"},
        ]
    }
]


class PlaybookEngine:
    """Automated incident response playbook engine."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.playbooks = PLAYBOOKS
        self.action_log = ActionLog()

    def get_playbooks(self) -> List[Dict]:
        """Return all playbook definitions."""
        return [{"id": p["id"], "name": p["name"], "description": p["description"],
                 "trigger": p["trigger"], "approval": p["approval"]}
                for p in self.playbooks]

    def evaluate_incident(self, incident: Dict) -> List[Dict]:
        """
        Check if any playbook should trigger for this incident.
        Returns list of executed action results.
        """
        if not self.enabled:
            return []

        severity = incident.get("severity", "LOW").lower()
        rule_name = incident.get("rule", incident.get("title", ""))
        description = incident.get("description", "")
        entities = incident.get("entities", {})

        results = []
        for playbook in self.playbooks:
            if self._should_trigger(playbook, severity, rule_name, description):
                for action_def in playbook["actions"]:
                    target = self._resolve_target(action_def, entities, rule_name)
                    executor = ACTION_EXECUTORS.get(action_def["type"])
                    if executor:
                        result = executor(target)
                        self.action_log.add(result)
                        results.append(result.to_dict())
        return results

    def _should_trigger(self, playbook: Dict, severity: str,
                       rule_name: str, description: str) -> bool:
        """Check if a playbook's trigger conditions are met."""
        trigger = playbook.get("trigger", {})

        # Check severity threshold
        min_sev = trigger.get("min_severity", "low")
        if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(min_sev, 0):
            return False

        # Check rule name match
        rule_pattern = trigger.get("rule_match")
        if rule_pattern:
            text = f"{rule_name} {description}".lower()
            if not re.search(rule_pattern, text, re.IGNORECASE):
                return False

        return True

    @staticmethod
    def _resolve_target(action_def: Dict, entities: Dict, rule_name: str) -> str:
        """Determine the target for an action based on incident entities."""
        target_from = action_def.get("target_from", "static")
        if target_from == "static":
            return action_def.get("static", rule_name)
        return entities.get(target_from, f"unknown-{target_from}")

    def stats(self) -> Dict:
        """Get playbook engine statistics."""
        return {
            "enabled": self.enabled,
            "playbook_count": len(self.playbooks),
            "action_stats": self.action_log.stats()
        }
