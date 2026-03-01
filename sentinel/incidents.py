"""
Incident Manager
Tracks, manages, and enriches security incidents.
Persisted to SQLite via the database module.
"""
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime


class Incident:
    """Represents a security incident."""

    def __init__(self, title: str, severity: str, description: str = "",
                 source: str = "manual", entities: Dict = None,
                 owner_id: str = "system"):
        self.id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        self.title = title
        self.severity = severity
        self.description = description
        self.source = source
        self.entities = entities or {}
        self.status = "open"
        self.owner_id = owner_id
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = self.created_at
        self.closed_at = None
        self.alerts: List[str] = []
        self.notes: List[Dict] = []
        self.timeline: List[Dict] = []

        self.timeline.append({
            "timestamp": self.created_at,
            "action": "created",
            "detail": f"Incident created: {title}"
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "source": self.source,
            "entities": self.entities,
            "status": self.status,
            "owner_id": self.owner_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
            "alerts": self.alerts,
            "notes": self.notes,
            "timeline": self.timeline
        }


class IncidentManager:
    """Manages security incidents with SQLite persistence."""

    def __init__(self, db=None):
        self.db = db
        # In-memory fallback when no database is configured
        self._memory: Dict[str, Incident] = {}

    def set_db(self, db):
        """Set or update the database connection."""
        self.db = db

    # ── Create ───────────────────────────────────────────────────────────────

    def create(self, title: str, severity: str, description: str = "",
               source: str = "detection", entities: Dict = None,
               owner_id: str = "system") -> Incident:
        """Create a new incident and persist it."""
        incident = Incident(title, severity, description, source, entities, owner_id)

        if self.db:
            self.db.execute(
                """INSERT INTO incidents
                   (id, title, severity, description, source, entities,
                    status, owner_id, created_at, updated_at, closed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (incident.id, incident.title, incident.severity,
                 incident.description, incident.source,
                 json.dumps(incident.entities), incident.status,
                 incident.owner_id, incident.created_at,
                 incident.updated_at, incident.closed_at)
            )
            # Insert initial timeline entry
            for entry in incident.timeline:
                self.db.execute(
                    """INSERT INTO incident_timeline
                       (incident_id, timestamp, action, detail)
                       VALUES (?, ?, ?, ?)""",
                    (incident.id, entry["timestamp"], entry["action"], entry["detail"])
                )
            self.db.commit()
        else:
            self._memory[incident.id] = incident

        return incident

    # ── Read ─────────────────────────────────────────────────────────────────

    def get(self, incident_id: str) -> Optional[Dict]:
        """Get an incident by ID."""
        if self.db:
            row = self.db.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_dict(row, incident_id)
        else:
            incident = self._memory.get(incident_id)
            return incident.to_dict() if incident else None

    def list_all(self, status: str = None) -> List[Dict]:
        """List all incidents, optionally filtered by status."""
        if self.db:
            if status:
                rows = self.db.execute(
                    "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC",
                    (status,)
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM incidents ORDER BY created_at DESC"
                ).fetchall()
            return [self._row_to_dict(row, row["id"]) for row in rows]
        else:
            incidents = list(self._memory.values())
            if status:
                incidents = [i for i in incidents if i.status == status]
            return [i.to_dict() for i in incidents]

    # ── Update ───────────────────────────────────────────────────────────────

    def update_status(self, incident_id: str, status: str) -> bool:
        """Update incident status."""
        now = datetime.utcnow().isoformat()

        if self.db:
            row = self.db.execute(
                "SELECT id FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return False

            closed_at = now if status == "closed" else None
            self.db.execute(
                """UPDATE incidents
                   SET status = ?, updated_at = ?, closed_at = COALESCE(?, closed_at)
                   WHERE id = ?""",
                (status, now, closed_at, incident_id)
            )
            self.db.execute(
                """INSERT INTO incident_timeline
                   (incident_id, timestamp, action, detail)
                   VALUES (?, ?, ?, ?)""",
                (incident_id, now, "status_change", f"Status changed to {status}")
            )
            self.db.commit()
            return True
        else:
            incident = self._memory.get(incident_id)
            if not incident:
                return False
            incident.status = status
            incident.updated_at = now
            if status == "closed":
                incident.closed_at = now
            incident.timeline.append({
                "timestamp": now,
                "action": "status_change",
                "detail": f"Status changed to {status}"
            })
            return True

    def add_note(self, incident_id: str, note: str, author: str = "system") -> bool:
        """Add a note to an incident."""
        now = datetime.utcnow().isoformat()

        if self.db:
            row = self.db.execute(
                "SELECT id FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return False
            self.db.execute(
                """INSERT INTO incident_notes
                   (incident_id, timestamp, author, text)
                   VALUES (?, ?, ?, ?)""",
                (incident_id, now, author, note)
            )
            self.db.commit()
            return True
        else:
            incident = self._memory.get(incident_id)
            if not incident:
                return False
            incident.notes.append({
                "timestamp": now,
                "author": author,
                "text": note
            })
            return True

    def link_alert(self, incident_id: str, alert_id: str) -> bool:
        """Link an alert to an incident."""
        if self.db:
            row = self.db.execute(
                "SELECT id FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return False
            self.db.execute(
                """INSERT OR IGNORE INTO incident_alerts
                   (incident_id, alert_id) VALUES (?, ?)""",
                (incident_id, alert_id)
            )
            self.db.commit()
            return True
        else:
            incident = self._memory.get(incident_id)
            if not incident:
                return False
            if alert_id not in incident.alerts:
                incident.alerts.append(alert_id)
            return True

    # ── Stats ────────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Get incident statistics."""
        if self.db:
            total = self.db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_count = self.db.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
            ).fetchone()[0]
            investigating = self.db.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'investigating'"
            ).fetchone()[0]
            closed = self.db.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'closed'"
            ).fetchone()[0]

            by_severity = {}
            for sev in ["critical", "high", "medium", "low"]:
                count = self.db.execute(
                    "SELECT COUNT(*) FROM incidents WHERE severity = ?", (sev,)
                ).fetchone()[0]
                by_severity[sev] = count

            return {
                "total": total,
                "open": open_count,
                "investigating": investigating,
                "closed": closed,
                "by_severity": by_severity
            }
        else:
            all_incidents = list(self._memory.values())
            return {
                "total": len(all_incidents),
                "open": len([i for i in all_incidents if i.status == "open"]),
                "investigating": len([i for i in all_incidents if i.status == "investigating"]),
                "closed": len([i for i in all_incidents if i.status == "closed"]),
                "by_severity": {
                    s: len([i for i in all_incidents if i.severity == s])
                    for s in ["critical", "high", "medium", "low"]
                }
            }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _row_to_dict(self, row, incident_id: str) -> Dict[str, Any]:
        """Convert a database row + related data into a dict."""
        # Fetch notes
        notes = []
        for n in self.db.execute(
            "SELECT timestamp, author, text FROM incident_notes WHERE incident_id = ? ORDER BY id",
            (incident_id,)
        ).fetchall():
            notes.append({"timestamp": n["timestamp"], "author": n["author"], "text": n["text"]})

        # Fetch timeline
        timeline = []
        for t in self.db.execute(
            "SELECT timestamp, action, detail FROM incident_timeline WHERE incident_id = ? ORDER BY id",
            (incident_id,)
        ).fetchall():
            timeline.append({"timestamp": t["timestamp"], "action": t["action"], "detail": t["detail"]})

        # Fetch linked alerts
        alerts = [
            a["alert_id"] for a in self.db.execute(
                "SELECT alert_id FROM incident_alerts WHERE incident_id = ?",
                (incident_id,)
            ).fetchall()
        ]

        entities = {}
        try:
            entities = json.loads(row["entities"]) if row["entities"] else {}
        except (json.JSONDecodeError, TypeError):
            pass

        return {
            "id": row["id"],
            "title": row["title"],
            "severity": row["severity"],
            "description": row["description"],
            "source": row["source"],
            "entities": entities,
            "status": row["status"],
            "owner_id": row["owner_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "closed_at": row["closed_at"],
            "alerts": alerts,
            "notes": notes,
            "timeline": timeline
        }
