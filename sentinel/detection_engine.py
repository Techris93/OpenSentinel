"""
Detection Engine
Real-time threat detection using predefined rules against SIEM data.
"""
import time
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from sentinel.rules import DETECTION_RULES


class DetectionEngine:
    """Automated threat detection engine."""

    def __init__(self, agent=None):
        self.agent = agent
        self.rules = DETECTION_RULES
        self.alerts: List[Dict[str, Any]] = []
        self.running = False
        self._last_scan = None

    def start(self):
        """Start the detection engine."""
        self.running = True
        self._last_scan = datetime.utcnow()

    def stop(self):
        """Stop the detection engine."""
        self.running = False

    def scan(self) -> List[Dict[str, Any]]:
        """Run all detection rules and return new alerts."""
        if not self.agent:
            return []

        new_alerts = []
        for rule in self.rules:
            try:
                results = self.agent.process_query(rule["spl"])
                if results and len(results) >= rule.get("threshold", 1):
                    alert = {
                        "id": f"ALERT-{len(self.alerts) + len(new_alerts) + 1}",
                        "rule_id": rule["id"],
                        "rule": rule["name"],
                        "title": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "mitre": rule.get("mitre", ""),
                        "event_count": len(results),
                        "sample_events": results[:5],
                        "timestamp": datetime.utcnow().isoformat(),
                        "status": "new"
                    }
                    new_alerts.append(alert)
            except Exception as e:
                print(f"[DetectionEngine] Rule {rule['id']} error: {e}")

        self.alerts.extend(new_alerts)
        self._last_scan = datetime.utcnow()
        return new_alerts

    def get_alerts(self, status: str = None, severity: str = None) -> List[Dict]:
        """Get alerts, optionally filtered by status or severity."""
        filtered = self.alerts
        if status:
            filtered = [a for a in filtered if a.get("status") == status]
        if severity:
            filtered = [a for a in filtered if a.get("severity") == severity]
        return filtered

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        for alert in self.alerts:
            if alert["id"] == alert_id:
                alert["status"] = "acknowledged"
                return True
        return False

    def close_alert(self, alert_id: str) -> bool:
        """Close an alert."""
        for alert in self.alerts:
            if alert["id"] == alert_id:
                alert["status"] = "closed"
                alert["closed_at"] = datetime.utcnow().isoformat()
                return True
        return False

    def stats(self) -> Dict[str, Any]:
        """Get detection engine statistics."""
        return {
            "total_alerts": len(self.alerts),
            "new": len([a for a in self.alerts if a["status"] == "new"]),
            "acknowledged": len([a for a in self.alerts if a["status"] == "acknowledged"]),
            "closed": len([a for a in self.alerts if a["status"] == "closed"]),
            "rules_loaded": len(self.rules),
            "running": self.running,
            "last_scan": self._last_scan.isoformat() if self._last_scan else None
        }
