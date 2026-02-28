"""
Feature A: Incident Summarizer
Takes raw Splunk events and generates a plain-English incident summary
using Google Gemini.
"""
import json
from typing import List, Dict, Any, Optional
import gemini_client


SUMMARIZER_PROMPT = """You are an expert SOC (Security Operations Center) analyst writing an incident summary.

Given the following security events from a SIEM system, write a concise incident summary.

**Rules:**
- Write 3-5 sentences maximum
- Include: timeline (earliest to latest event), key actors (users, IPs, hostnames), attack classification
- Reference MITRE ATT&CK technique IDs where applicable (e.g., T1110.001)
- End with a severity assessment: LOW / MEDIUM / HIGH / CRITICAL
- Be factual — only state what the data shows, do not speculate

**User's Original Question:** "{query}"

**Number of Events:** {event_count}

**Sample Events (first 15):**
```json
{events_json}
```

Write the incident summary now:"""


async def summarize_incident(events: List[Dict], original_query: str = "",
                            max_events: int = 15) -> str:
    """Summarize security events into a plain-English incident report."""
    if not events:
        return "No events to summarize."

    sample = events[:max_events]
    events_json = json.dumps(sample, indent=2, default=str)

    prompt = SUMMARIZER_PROMPT.format(
        query=original_query,
        event_count=len(events),
        events_json=events_json
    )

    return await gemini_client.generate(prompt)
