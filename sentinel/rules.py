"""
Detection Rules
Built-in SIEM detection rules based on MITRE ATT&CK framework.
"""
from typing import List, Dict, Any

DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "id": "RULE-001",
        "name": "Brute Force Detection",
        "description": "Detects multiple failed login attempts from a single source.",
        "severity": "high",
        "mitre": "T1110",
        "spl": 'search index=* sourcetype=*auth* action=failure | stats count by src_ip | where count > 5',
        "threshold": 5,
        "window": "5m"
    },
    {
        "id": "RULE-002",
        "name": "Suspicious PowerShell Execution",
        "description": "Detects encoded or obfuscated PowerShell commands.",
        "severity": "critical",
        "mitre": "T1059.001",
        "spl": 'search index=* (powershell OR pwsh) (EncodedCommand OR -enc OR bypass OR hidden)',
        "threshold": 1,
        "window": "1h"
    },
    {
        "id": "RULE-003",
        "name": "Data Exfiltration via DNS",
        "description": "Detects unusually long DNS queries indicating data exfiltration.",
        "severity": "critical",
        "mitre": "T1048.003",
        "spl": 'search index=* sourcetype=*dns* | eval query_len=len(query) | where query_len > 50',
        "threshold": 10,
        "window": "15m"
    },
    {
        "id": "RULE-004",
        "name": "Lateral Movement via SMB",
        "description": "Detects suspicious SMB connections between internal hosts.",
        "severity": "high",
        "mitre": "T1021.002",
        "spl": 'search index=* dest_port=445 | stats dc(dest_ip) as targets by src_ip | where targets > 3',
        "threshold": 3,
        "window": "10m"
    },
    {
        "id": "RULE-005",
        "name": "Privilege Escalation Attempt",
        "description": "Detects attempts to escalate privileges.",
        "severity": "critical",
        "mitre": "T1068",
        "spl": 'search index=* (sudo OR su OR runas OR UAC) NOT user=root',
        "threshold": 1,
        "window": "5m"
    },
    {
        "id": "RULE-006",
        "name": "C2 Beaconing Detection",
        "description": "Detects periodic outbound connections indicative of C2 beaconing.",
        "severity": "high",
        "mitre": "T1071",
        "spl": 'search index=* sourcetype=*firewall* action=allowed direction=outbound | timechart span=1m count by dest_ip',
        "threshold": 100,
        "window": "1h"
    }
]
