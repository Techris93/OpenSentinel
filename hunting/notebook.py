"""
Hunt Notebook
Interactive investigation notebook for tracking hunt sessions.
"""
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime


class HuntNotebook:
    """Interactive notebook for threat hunting investigations."""

    def __init__(self):
        self.sessions: Dict[str, Dict] = {}

    def create_session(self, title: str, description: str = "",
                      hypothesis: str = "") -> Dict:
        """Create a new hunt session."""
        session_id = f"SESSION-{uuid.uuid4().hex[:8].upper()}"
        session = {
            "id": session_id,
            "title": title,
            "description": description,
            "hypothesis": hypothesis,
            "status": "active",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "cells": [],
            "findings": [],
            "tags": []
        }
        self.sessions[session_id] = session
        return session

    def add_cell(self, session_id: str, cell_type: str = "query",
                content: str = "", result: Any = None) -> Optional[Dict]:
        """Add a cell to a hunt session."""
        session = self.sessions.get(session_id)
        if not session:
            return None

        cell = {
            "id": f"CELL-{len(session['cells']) + 1}",
            "type": cell_type,
            "content": content,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }
        session["cells"].append(cell)
        session["updated_at"] = datetime.utcnow().isoformat()
        return cell

    def add_finding(self, session_id: str, finding: str,
                   severity: str = "info", evidence: Any = None) -> bool:
        """Record a finding from a hunt session."""
        session = self.sessions.get(session_id)
        if not session:
            return False

        session["findings"].append({
            "text": finding,
            "severity": severity,
            "evidence": evidence,
            "timestamp": datetime.utcnow().isoformat()
        })
        return True

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get a hunt session by ID."""
        return self.sessions.get(session_id)

    def list_sessions(self, status: str = None) -> List[Dict]:
        """List all hunt sessions."""
        sessions = list(self.sessions.values())
        if status:
            sessions = [s for s in sessions if s.get("status") == status]
        return sessions

    def close_session(self, session_id: str, conclusion: str = "") -> bool:
        """Close a hunt session."""
        session = self.sessions.get(session_id)
        if not session:
            return False
        session["status"] = "closed"
        session["conclusion"] = conclusion
        session["closed_at"] = datetime.utcnow().isoformat()
        return True
