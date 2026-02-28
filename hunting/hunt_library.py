"""
Threat Hunt Library
Pre-built threat hunting queries based on MITRE ATT&CK techniques.
"""
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime


class HuntLibrary:
    """Library of pre-built threat hunting queries."""

    def __init__(self):
        self.hunts: List[Dict[str, Any]] = self._load_default_hunts()
        self.results_cache: Dict[str, Any] = {}

    def _load_default_hunts(self) -> List[Dict[str, Any]]:
        """Load built-in threat hunt definitions."""
        return [
            {
                "id": "HUNT-001",
                "name": "Credential Dumping",
                "description": "Hunt for evidence of credential dumping tools (Mimikatz, ProcDump, etc.)",
                "mitre": "T1003",
                "category": "credential_access",
                "query": "search index=* (mimikatz OR procdump OR lsass OR sekurlsa OR wce OR gsecdump)",
                "severity": "critical",
                "tags": ["credentials", "mimikatz", "lsass"]
            },
            {
                "id": "HUNT-002",
                "name": "Persistence via Scheduled Tasks",
                "description": "Hunt for newly created scheduled tasks that may indicate persistence.",
                "mitre": "T1053",
                "category": "persistence",
                "query": "search index=* (schtasks OR at.exe OR crontab) (create OR add OR register)",
                "severity": "high",
                "tags": ["persistence", "scheduled_task"]
            },
            {
                "id": "HUNT-003",
                "name": "Unusual Outbound Connections",
                "description": "Hunt for outbound connections to rare or suspicious destinations.",
                "mitre": "T1071",
                "category": "command_and_control",
                "query": "search index=* sourcetype=*firewall* direction=outbound | rare dest_ip",
                "severity": "medium",
                "tags": ["c2", "network", "outbound"]
            },
            {
                "id": "HUNT-004",
                "name": "Suspicious Process Creation",
                "description": "Hunt for processes spawned from unusual parent processes.",
                "mitre": "T1059",
                "category": "execution",
                "query": "search index=* sourcetype=*sysmon* EventCode=1 | stats count by ParentImage, Image",
                "severity": "high",
                "tags": ["process", "execution", "sysmon"]
            },
            {
                "id": "HUNT-005",
                "name": "Registry Modification",
                "description": "Hunt for suspicious registry modifications used for persistence.",
                "mitre": "T1547.001",
                "category": "persistence",
                "query": "search index=* sourcetype=*sysmon* EventCode=13 (Run OR RunOnce OR Services)",
                "severity": "high",
                "tags": ["registry", "persistence", "autorun"]
            },
            {
                "id": "HUNT-006",
                "name": "DNS Tunneling",
                "description": "Hunt for DNS queries with unusually high entropy or length.",
                "mitre": "T1071.004",
                "category": "command_and_control",
                "query": "search index=* sourcetype=*dns* | eval len=len(query) | where len > 50 | stats count by query",
                "severity": "critical",
                "tags": ["dns", "tunneling", "exfiltration"]
            },
            {
                "id": "HUNT-007",
                "name": "Kerberoasting",
                "description": "Hunt for Kerberoasting attacks against service accounts.",
                "mitre": "T1558.003",
                "category": "credential_access",
                "query": "search index=* EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Service_Name, Client_Address",
                "severity": "critical",
                "tags": ["kerberos", "kerberoasting", "credential_access"]
            },
            {
                "id": "HUNT-008",
                "name": "Lateral Movement via WMI",
                "description": "Hunt for WMI-based lateral movement.",
                "mitre": "T1047",
                "category": "lateral_movement",
                "query": "search index=* (wmic OR wmiprvse) (process call create OR node:)",
                "severity": "high",
                "tags": ["wmi", "lateral_movement"]
            }
        ]

    def list_hunts(self, category: str = None) -> List[Dict]:
        """List available threat hunts."""
        if category:
            return [h for h in self.hunts if h.get("category") == category]
        return self.hunts

    def get_hunt(self, hunt_id: str) -> Optional[Dict]:
        """Get a specific hunt by ID."""
        for hunt in self.hunts:
            if hunt["id"] == hunt_id:
                return hunt
        return None

    def add_custom_hunt(self, name: str, description: str, query: str,
                       mitre: str = "", severity: str = "medium",
                       category: str = "custom") -> Dict:
        """Add a custom threat hunt query."""
        hunt = {
            "id": f"HUNT-C{uuid.uuid4().hex[:6].upper()}",
            "name": name,
            "description": description,
            "mitre": mitre,
            "category": category,
            "query": query,
            "severity": severity,
            "tags": ["custom"],
            "created_at": datetime.utcnow().isoformat()
        }
        self.hunts.append(hunt)
        return hunt

    def search_hunts(self, keyword: str) -> List[Dict]:
        """Search hunts by keyword."""
        keyword = keyword.lower()
        return [
            h for h in self.hunts
            if keyword in h["name"].lower()
            or keyword in h.get("description", "").lower()
            or keyword in str(h.get("tags", [])).lower()
        ]

    def stats(self) -> Dict[str, Any]:
        """Get hunt library statistics."""
        categories = {}
        for hunt in self.hunts:
            cat = hunt.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        return {
            "total_hunts": len(self.hunts),
            "by_category": categories
        }
