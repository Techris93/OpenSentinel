"""
Feature B: Script/Command Analyzer
Analyzes suspicious scripts (PowerShell, Bash, Python, etc.) using Gemini
and provides risk assessment, MITRE mapping, and IOC extraction.
"""
from typing import Optional
import gemini_client


ANALYZER_PROMPT = """You are an expert malware reverse engineer and threat hunter.

Analyze the following script/command and provide a structured security assessment.

**Script Content:**
```
{script_content}
```

**Provide your analysis in this exact format:**

**Language Detected:** [language]

**Risk Level:** [SAFE / SUSPICIOUS / MALICIOUS]

**Summary:** [1-2 sentence overview of what this script does]

**Line-by-Line Analysis:**
[Explain key actions, one bullet per significant line]

**MITRE ATT&CK Techniques:**
[List technique IDs and names, e.g., T1059.001 - PowerShell]

**Indicators of Compromise (IOCs):**
- IPs: [list or "None"]
- Domains: [list or "None"]
- File Paths: [list or "None"]
- Registry Keys: [list or "None"]
- Hashes: [list or "None"]

**Recommended Response:**
[2-3 actionable steps for the SOC team]"""


async def analyze_script(script_content: str) -> str:
    """Analyze a suspicious script using Gemini AI."""
    if not script_content or not script_content.strip():
        return "No script content provided."

    prompt = ANALYZER_PROMPT.format(script_content=script_content)
    return await gemini_client.generate(prompt)
