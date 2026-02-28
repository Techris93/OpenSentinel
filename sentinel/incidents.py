"""
Incident Manager
Tracks, manages, and enriches security incidents.
"""
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime


class Incident:
    """Represents a security incident."""

    def __init__(self, title: str, severity: str, description: str = "",
                 source: str = "manual", entities: Dict = None):
        self.id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        self.title = title
        self.severity = severity
        self.description = description
        self.source = source
        self.entities = entities or {}
        self.status = "open"
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
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
            "alerts": self.alerts,
            "notes": self.notes,
            "timeline": self.timeline
        }


class IncidentManager:
    """Manages security incidents."""

    def __init__(self):
        self.incidents: Dict[str, Incident] = {}

    def create(self, title: str, severity: str, description: str = "",
               source: str = "detection", entities: Dict = None) -> Incident:
        """Create a new incident."""
        incident = Incident(title, severity, description, source, entities)
        self.incidents[incident.id] = incident
        return incident

    def get(self, incident_id: str) -> Optional[Dict]:
        """Get an incident by ID."""
        incident = self.incidents.get(incident_id)
        return incident.to_dict() if incident else None

    def list_all(self, status: str = None) -> List[Dict]:
        """List all incidents."""
        incidents = list(self.incidents.values())
        if status:
            incidents = [i for i in incidents if i.status == status]
        return [i.to_dict() for i in incidents]

    def update_status(self, incident_id: str, status: str) -> bool:
        """Update incident status."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        incident.status = status
        incident.updated_at = datetime.utcnow().isoformat()
        if status == "closed":
            incident.closed_at = incident.updated_at
        incident.timeline.append({
            "timestamp": incident.updated_at,
            "action": "status_change",
            "detail": f"Status changed to {status}"
        })
        return True

    def add_note(self, incident_id: str, note: str, author: str = "system") -> bool:
        """Add a note to an incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        incident.notes.append({
            "timestamp": datetime.utcnow().isoformat(),
            "author": author,
            "text": note
        })
        return True

    def link_alert(self, incident_id: str, alert_id: str) -> bool:
        """Link an alert to an incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        if alert_id not in incident.alerts:
            incident.alerts.append(alert_id)
        return True

    def stats(self) -> Dict[str, Any]:
        """Get incident statistics."""
        all_incidents = list(self.incidents.values())
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
