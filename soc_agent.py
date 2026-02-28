"""
SOC Agent — Core Intelligence Module
Natural Language → Splunk SPL query engine with NLP-based entity extraction.
"""
import spacy
import splunklib.client as client
import splunklib.results as results
from typing import List, Dict, Any, Optional
import re
import io
import datetime
import time

try:
    import spacy_transformers
except ImportError:
    pass

import os

# ═══ Model Loading ══════════════════════════════════════════════════════════
CUSTOM_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "model-best")

if os.path.exists(CUSTOM_MODEL_PATH):
    print("Loading Custom Fine-Tuned Model from: " + CUSTOM_MODEL_PATH)
    _NLP_MODEL = spacy.load(CUSTOM_MODEL_PATH)
else:
    try:
        print("Custom model not found. Loading standard spaCy model: en_core_web_sm")
        _NLP_MODEL = spacy.load("en_core_web_sm")
    except OSError:
        print("Standard model not found. Downloading spaCy model: en_core_web_sm...")
        from spacy.cli import download
        download("en_core_web_sm")
        _NLP_MODEL = spacy.load("en_core_web_sm")


class SOCAgent:
    """AI-powered SOC Analyst Agent with NLP query processing."""

    def __init__(self, host: str = "localhost", port: int = 8089,
                 username: str = "admin", password: str = "password",
                 token: str = None):
        """Initialize the SOC Agent with Splunk connection details."""
        connect_args = {
            "host": host,
            "port": port,
        }
        if token:
            connect_args["splunkToken"] = token
        else:
            connect_args["username"] = username
            connect_args["password"] = password

        self.service = client.connect(**connect_args)
        self.nlp = _NLP_MODEL
        self.context = {}

    def extract_keywords(self, query: str) -> Dict[str, Any]:
        """Extract security-relevant entities from natural language query."""
        doc = self.nlp(query)
        keywords = {
            "ips": [],
            "users": [],
            "domains": [],
            "actions": [],
            "raw_entities": [],
            "time_range": None
        }

        for ent in doc.ents:
            keywords["raw_entities"].append({
                "text": ent.text,
                "label": ent.label_
            })

        # IP Address extraction via regex
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        keywords["ips"] = ip_pattern.findall(query)

        # Keyword-based action extraction
        action_keywords = ["login", "failed", "attack", "brute", "scan", "malware",
                          "phishing", "alert", "block", "deny", "allow", "accept",
                          "drop", "reject", "suspicious", "anomaly", "threat"]
        for word in query.lower().split():
            if word in action_keywords:
                keywords["actions"].append(word)

        # Context update
        session_id = self.context.get("session_id", "default")
        print(f"[SOCAgent] Extracted keywords for session '{session_id}': {keywords}")

        return keywords

    def build_spl_query(self, keywords: Dict[str, Any]) -> str:
        """Build a Splunk SPL query from extracted keywords."""
        parts = ["search"]

        if keywords.get("ips"):
            ip_clause = " OR ".join([f'src_ip="{ip}" OR dest_ip="{ip}"' for ip in keywords["ips"]])
            parts.append(f"({ip_clause})")

        if keywords.get("users"):
            user_clause = " OR ".join([f'user="{u}"' for u in keywords["users"]])
            parts.append(f"({user_clause})")

        if keywords.get("actions"):
            action_clause = " OR ".join(keywords["actions"])
            parts.append(f"({action_clause})")

        if keywords.get("domains"):
            domain_clause = " OR ".join([f'domain="{d}"' for d in keywords["domains"]])
            parts.append(f"({domain_clause})")

        if len(parts) == 1:
            parts.append("*")

        return " ".join(parts)

    def process_query(self, query: str) -> List[Dict]:
        """Process a natural language query and return Splunk results."""
        print(f"[SOCAgent] Processing query: {query}")

        keywords = self.extract_keywords(query)
        spl = self.build_spl_query(keywords)

        print(f"[SOCAgent] Generated SPL: {spl}")

        try:
            job = self.service.jobs.create(spl, **{
                "earliest_time": "-24h",
                "latest_time": "now",
                "exec_mode": "blocking"
            })

            while not job.is_done():
                time.sleep(0.5)

            result_stream = job.results(output_mode="json")
            raw = result_stream.read().decode("utf-8")

            import json
            parsed = json.loads(raw)
            events = parsed.get("results", [])

            print(f"[SOCAgent] Found {len(events)} results")
            return events

        except Exception as e:
            print(f"[SOCAgent] Error processing query: {str(e)}")
            return [{"error": str(e)}]

    def list_indices(self) -> List[str]:
        """List available Splunk indexes."""
        return [idx.name for idx in self.service.indexes]

    def update_connection(self, host: str, port: int, username: str, password: str):
        """Update the Splunk connection with new credentials."""
        self.service = client.connect(
            host=host,
            port=port,
            username=username,
            password=password
        )
        print(f"[SOCAgent] Connection updated to {host}:{port}")

    def validate_connection(self) -> Dict[str, Any]:
        """Validate the current Splunk connection."""
        try:
            info = self.service.info
            return {
                "success": True,
                "server_name": info.get("server_name", "unknown"),
                "version": info.get("version", "unknown")
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
