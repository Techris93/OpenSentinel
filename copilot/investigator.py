"""
Feature C: Guided Investigator
Analyzes current findings and suggests 3 logical next investigation steps
using Google Gemini and the session context.
"""
import json
from typing import List, Dict, Any, Optional
import gemini_client


INVESTIGATOR_PROMPT = """You are a senior SOC analyst mentoring a junior analyst through an investigation.

The analyst asked: "{query}"
The search returned {result_count} events.
Key entities detected: {entities}
Previous context (if any): {context}

Based on these findings, suggest exactly 3 follow-up investigation steps.

**Rules:**
- Order by priority (most critical first)
- Each step must be a specific, actionable natural language query the analyst can type next
- Focus on: lateral movement, persistence mechanisms, data exfiltration, privilege escalation
- Reference the specific entities found (IPs, usernames, hostnames)
- Keep each suggestion to 1 sentence

**Format your response exactly like this:**
1. [Most critical follow-up query]
2. [Second priority query]
3. [Third priority query]"""


async def suggest_next_steps(query: str, result_count: int = 0,
                            entities: str = "", context: str = "") -> str:
    """Suggest investigation next steps based on current findings."""
    prompt = INVESTIGATOR_PROMPT.format(
        query=query,
        result_count=result_count,
        entities=entities,
        context=context
    )

    response = await gemini_client.generate(prompt)

    # Parse numbered items
    lines = [l.strip() for l in response.strip().split("\n") if l.strip()]
    steps = [l for l in lines if l and l[0].isdigit()]

    if steps:
        return "\n".join(steps)
    return response
