"""
SOC Agent Copilot — AI-Powered Security Analysis Suite

Modules:
    summarizer      — Incident summarization from raw events
    script_analyzer — Malicious script/command analysis
    investigator    — Guided investigation suggestions
    threat_intel    — VirusTotal + AbuseIPDB IOC enrichment
"""
from copilot.summarizer import summarize_incident
from copilot.script_analyzer import analyze_script
from copilot.investigator import suggest_next_steps
from copilot.threat_intel import enrich_iocs
