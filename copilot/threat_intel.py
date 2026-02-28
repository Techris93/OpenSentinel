"""
Feature D: Threat Intelligence Enrichment
Queries VirusTotal and AbuseIPDB for IP/domain/hash reputation.
Includes local caching to respect API rate limits.
"""
import os
import re
import asyncio
import time
from typing import List, Dict, Any, Optional

from dotenv import load_dotenv
load_dotenv()

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Local cache: { ioc_string: { "data": ..., "timestamp": ... } }
_CACHE: Dict[str, Dict] = {}
CACHE_TTL = 3600  # 1 hour


def _is_ip(text: str) -> bool:
    """Check if string is an IPv4 address."""
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text))


def _is_hash(text: str) -> bool:
    """Check if string is an MD5/SHA1/SHA256 hash."""
    return bool(re.match(r'^[a-fA-F0-9]{32,64}$', text))


def _is_domain(text: str) -> bool:
    """Check if string is a domain name."""
    return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', text))


def _get_cached(ioc: str) -> Optional[Dict]:
    """Get cached IOC data if it exists and hasn't expired."""
    entry = _CACHE.get(ioc)
    if entry and (time.time() - entry["timestamp"]) < CACHE_TTL:
        return entry["data"]
    return None


def _set_cache(ioc: str, data: Dict):
    """Cache IOC enrichment data."""
    _CACHE[ioc] = {"data": data, "timestamp": time.time()}


async def _virustotal_lookup(ioc: str, ioc_type: str) -> Optional[Dict]:
    """Lookup an IOC on VirusTotal."""
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key or not REQUESTS_AVAILABLE:
        return None

    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif ioc_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        else:
            return None

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None, lambda: requests.get(url, headers={"x-apikey": vt_key}, timeout=10)
        )

        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "detections": stats.get("malicious", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "reputation": attrs.get("reputation", "unknown"),
                "tags": attrs.get("tags", [])
            }
    except Exception as e:
        print(f"[ThreatIntel] VirusTotal error for {ioc}: {e}")

    return None


async def _abuseipdb_lookup(ip: str) -> Optional[Dict]:
    """Lookup an IP on AbuseIPDB."""
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuse_key or not REQUESTS_AVAILABLE:
        return None

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": abuse_key, "Accept": "application/json"}

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None, lambda: requests.get(url, params=params, headers=headers, timeout=10)
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "source": "AbuseIPDB",
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "unknown"),
                "isp": data.get("isp", "unknown"),
                "is_tor": data.get("isTor", False)
            }
    except Exception as e:
        print(f"[ThreatIntel] AbuseIPDB error for {ip}: {e}")

    return None


async def enrich_single_ioc(ioc: str) -> Dict[str, Any]:
    """Enrich a single IOC with threat intelligence."""
    # Check cache
    cached = _get_cached(ioc)
    if cached:
        cached["cached"] = True
        return cached

    result = {
        "ioc": ioc,
        "type": "unknown",
        "sources": [],
        "risk_score": 0,
        "cached": False
    }

    if _is_ip(ioc):
        result["type"] = "ip"
        vt = await _virustotal_lookup(ioc, "ip")
        if vt:
            result["sources"].append(vt)
        abuse = await _abuseipdb_lookup(ioc)
        if abuse:
            result["sources"].append(abuse)
            result["risk_score"] = abuse.get("abuse_confidence", 0)
    elif _is_hash(ioc):
        result["type"] = "hash"
        vt = await _virustotal_lookup(ioc, "hash")
        if vt:
            result["sources"].append(vt)
            if vt.get("total_engines", 0) > 0:
                result["risk_score"] = int(vt["detections"] / vt["total_engines"] * 100)
    elif _is_domain(ioc):
        result["type"] = "domain"
        vt = await _virustotal_lookup(ioc, "domain")
        if vt:
            result["sources"].append(vt)

    _set_cache(ioc, result)
    return result


async def enrich_iocs(iocs: List[str]) -> List[Dict]:
    """Enrich multiple IOCs with threat intelligence."""
    return [await enrich_single_ioc(ioc) for ioc in iocs]
