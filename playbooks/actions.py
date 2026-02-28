"""
Playbook Actions
Defines action types, execution functions, and action logging.
"""
import uuid
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timezone
from enum import Enum


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    QUARANTINE_HOST = "quarantine_host"
    NOTIFY_SOC = "notify_soc"
    COLLECT_FORENSICS = "collect_forensics"
    ISOLATE_NETWORK = "isolate_network"


class ActionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ActionResult:
    """Result of a playbook action execution."""

    def __init__(self, action_type: str, target: str, status: ActionStatus,
                 message: str = "", details: Dict = None):
        self.id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        self.action_type = action_type
        self.target = target
        self.status = status
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action_type": self.action_type,
            "target": self.target,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp
        }


class ActionLog:
    """Log of all executed actions."""

    def __init__(self, max_actions: int = 1000):
        self.actions: List[ActionResult] = []
        self.max_actions = max_actions

    def add(self, action: ActionResult):
        """Add an action result to the log."""
        self.actions.append(action)
        if len(self.actions) > self.max_actions:
            self.actions = self.actions[-self.max_actions:]

    def list_all(self, incident_id: str = None) -> List[Dict]:
        """List all actions, optionally filtered by incident."""
        return [a.to_dict() for a in self.actions]

    def get(self, action_id: str) -> Optional[Dict]:
        """Get an action by ID."""
        for action in self.actions:
            if action.id == action_id:
                return action.to_dict()
        return None

    def count(self) -> int:
        """Get the total number of actions."""
        return len(self.actions)

    def stats(self) -> Dict[str, Any]:
        """Get action statistics."""
        total = len(self.actions)
        if total == 0:
            return {"total": 0}
        by_type = {}
        by_status = {}
        for a in self.actions:
            by_type[a.action_type] = by_type.get(a.action_type, 0) + 1
            by_status[a.status.value] = by_status.get(a.status.value, 0) + 1
        success_rate = by_status.get("completed", 0) / total
        return {
            "total": total,
            "by_type": by_type,
            "by_status": by_status,
            "success_rate": f"{success_rate:.0f}%"
        }


# ═══ Action Executors ════════════════════════════════════════════════════════
def execute_block_ip(target: str, **kwargs) -> ActionResult:
    """Simulate blocking an IP address."""
    print(f"[ACTION] Blocking IP: {target}")
    return ActionResult(ActionType.BLOCK_IP, target, ActionStatus.COMPLETED,
                       f"IP {target} blocked on firewall")


def execute_disable_user(target: str, **kwargs) -> ActionResult:
    """Simulate disabling a user account."""
    print(f"[ACTION] Disabling user: {target}")
    return ActionResult(ActionType.DISABLE_USER, target, ActionStatus.COMPLETED,
                       f"User {target} account disabled")


def execute_quarantine_host(target: str, **kwargs) -> ActionResult:
    """Simulate quarantining a host."""
    print(f"[ACTION] Quarantining host: {target}")
    return ActionResult(ActionType.QUARANTINE_HOST, target, ActionStatus.COMPLETED,
                       f"Host {target} quarantined from network")


def execute_notify_soc(target: str, **kwargs) -> ActionResult:
    """Simulate notifying SOC team."""
    print(f"[ACTION] Notifying SOC team about: {target}")
    return ActionResult(ActionType.NOTIFY_SOC, target, ActionStatus.COMPLETED,
                       f"SOC team notified about incident: {target}")


def execute_collect_forensics(target: str, **kwargs) -> ActionResult:
    """Simulate collecting forensic evidence."""
    print(f"[ACTION] Collecting forensics from: {target}")
    return ActionResult(ActionType.COLLECT_FORENSICS, target, ActionStatus.COMPLETED,
                       f"Forensic collection initiated for: {target}")


def execute_isolate_network(target: str, **kwargs) -> ActionResult:
    """Simulate isolating a network segment."""
    print(f"[ACTION] Isolating network segment: {target}")
    return ActionResult(ActionType.ISOLATE_NETWORK, target, ActionStatus.COMPLETED,
                       f"Network segment {target} isolated")


ACTION_EXECUTORS: Dict[str, Callable] = {
    ActionType.BLOCK_IP: execute_block_ip,
    ActionType.DISABLE_USER: execute_disable_user,
    ActionType.QUARANTINE_HOST: execute_quarantine_host,
    ActionType.NOTIFY_SOC: execute_notify_soc,
    ActionType.COLLECT_FORENSICS: execute_collect_forensics,
    ActionType.ISOLATE_NETWORK: execute_isolate_network,
}
