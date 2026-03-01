"""
Detection Engine
Real-time threat detection using predefined rules against SIEM data.
Alerts are persisted to SQLite via the database module.
"""
import json
import time
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from sentinel.rules import DETECTION_RULES


class DetectionEngine:
    """Automated threat detection engine with SQLite persistence."""

    def __init__(self, agent=None, db=None):
        self.agent = agent
        self.db = db
        self.rules = DETECTION_RULES
        self.running = False
        self._last_scan = None
        # In-memory fallback counter for alert IDs when no DB
        self._memory_alerts: List[Dict[str, Any]] = []

    def set_db(self, db):
        """Set or update the database connection."""
        self.db = db

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
                    alert = self._create_alert(rule, results)
                    new_alerts.append(alert)
            except Exception as e:
                print(f"[DetectionEngine] Rule {rule['id']} error: {e}")

        self._last_scan = datetime.utcnow()
        return new_alerts

    def _create_alert(self, rule: Dict, results: List) -> Dict[str, Any]:
        """Create and persist a new alert."""
        alert_id = self._next_alert_id()
        now = datetime.utcnow().isoformat()
        sample = results[:5]

        alert = {
            "id": alert_id,
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "title": rule["name"],
            "description": rule["description"],
            "severity": rule["severity"],
            "mitre": rule.get("mitre", ""),
            "event_count": len(results),
            "sample_events": sample,
            "timestamp": now,
            "status": "new"
        }

        if self.db:
            self.db.execute(
                """INSERT INTO alerts
                   (id, rule_id, rule_name, title, description, severity,
                    mitre, event_count, sample_events, timestamp, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert_id, rule["id"], rule["name"], rule["name"],
                 rule["description"], rule["severity"],
                 rule.get("mitre", ""), len(results),
                 json.dumps(sample), now, "new")
            )
            self.db.commit()
        else:
            self._memory_alerts.append(alert)

        return alert

    def _next_alert_id(self) -> str:
        """Generate the next sequential alert ID."""
        if self.db:
            row = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()
            count = row[0] if row else 0
        else:
            count = len(self._memory_alerts)
        return f"ALERT-{count + 1}"

    def get_alerts(self, status: str = None, severity: str = None) -> List[Dict]:
        """Get alerts, optionally filtered by status or severity."""
        if self.db:
            query = "SELECT * FROM alerts"
            conditions = []
            params = []

            if status:
                conditions.append("status = ?")
                params.append(status)
            if severity:
                conditions.append("severity = ?")
                params.append(severity)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY timestamp DESC"

            rows = self.db.execute(query, params).fetchall()
            return [self._row_to_dict(row) for row in rows]
        else:
            filtered = self._memory_alerts
            if status:
                filtered = [a for a in filtered if a.get("status") == status]
            if severity:
                filtered = [a for a in filtered if a.get("severity") == severity]
            return filtered

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        if self.db:
            cursor = self.db.execute(
                "UPDATE alerts SET status = 'acknowledged' WHERE id = ? AND status = 'new'",
                (alert_id,)
            )
            self.db.commit()
            return cursor.rowcount > 0
        else:
            for alert in self._memory_alerts:
                if alert["id"] == alert_id:
                    alert["status"] = "acknowledged"
                    return True
            return False

    def close_alert(self, alert_id: str) -> bool:
        """Close an alert."""
        now = datetime.utcnow().isoformat()
        if self.db:
            cursor = self.db.execute(
                "UPDATE alerts SET status = 'closed', closed_at = ? WHERE id = ?",
                (now, alert_id)
            )
            self.db.commit()
            return cursor.rowcount > 0
        else:
            for alert in self._memory_alerts:
                if alert["id"] == alert_id:
                    alert["status"] = "closed"
                    alert["closed_at"] = now
                    return True
            return False

    def stats(self) -> Dict[str, Any]:
        """Get detection engine statistics."""
        if self.db:
            total = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            new = self.db.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'new'"
            ).fetchone()[0]
            ack = self.db.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'acknowledged'"
            ).fetchone()[0]
            closed = self.db.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'closed'"
            ).fetchone()[0]
        else:
            total = len(self._memory_alerts)
            new = len([a for a in self._memory_alerts if a["status"] == "new"])
            ack = len([a for a in self._memory_alerts if a["status"] == "acknowledged"])
            closed = len([a for a in self._memory_alerts if a["status"] == "closed"])

        return {
            "total_alerts": total,
            "new": new,
            "acknowledged": ack,
            "closed": closed,
            "rules_loaded": len(self.rules),
            "running": self.running,
            "last_scan": self._last_scan.isoformat() if self._last_scan else None
        }

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        """Convert a database row to a dict."""
        sample_events = []
        try:
            sample_events = json.loads(row["sample_events"]) if row["sample_events"] else []
        except (json.JSONDecodeError, TypeError):
            pass

        return {
            "id": row["id"],
            "rule_id": row["rule_id"],
            "rule_name": row["rule_name"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "mitre": row["mitre"],
            "event_count": row["event_count"],
            "sample_events": sample_events,
            "timestamp": row["timestamp"],
            "status": row["status"],
            "closed_at": row["closed_at"]
        }
