"""
Anomaly Detector
Statistical anomaly detection for security metrics (login counts, traffic volumes, etc.).
Uses Z-score-based detection with configurable thresholds.
"""
import time
import math
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict


class AnomalyDetector:
    """Detects statistical anomalies in security metrics."""

    def __init__(self, agent=None, z_threshold: float = 2.5):
        self.agent = agent
        self.z_threshold = z_threshold
        self.baselines: Dict[str, Dict] = {}
        self.anomalies: List[Dict[str, Any]] = []
        self.running = False
        self._metrics_history: Dict[str, List[float]] = defaultdict(list)

    def start(self):
        """Start the anomaly detector."""
        self.running = True

    def stop(self):
        """Stop the anomaly detector."""
        self.running = False

    def add_metric(self, metric_name: str, value: float):
        """Add a metric value and check for anomalies."""
        self._metrics_history[metric_name].append(value)

        # Need at least 10 data points for baseline
        history = self._metrics_history[metric_name]
        if len(history) < 10:
            return None

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std_dev = math.sqrt(variance) if variance > 0 else 0.001

        z_score = (value - mean) / std_dev

        if abs(z_score) > self.z_threshold:
            anomaly = {
                "id": f"ANOMALY-{len(self.anomalies) + 1}",
                "metric": metric_name,
                "value": value,
                "mean": round(mean, 2),
                "std_dev": round(std_dev, 2),
                "z_score": round(z_score, 2),
                "direction": "spike" if z_score > 0 else "drop",
                "severity": "critical" if abs(z_score) > 4 else "high" if abs(z_score) > 3 else "medium",
                "timestamp": datetime.utcnow().isoformat(),
                "status": "new"
            }
            self.anomalies.append(anomaly)
            return anomaly

        return None

    def scan_metrics(self) -> List[Dict[str, Any]]:
        """Scan predefined metrics from SIEM data."""
        if not self.agent:
            return []

        metrics_queries = {
            "auth_failures": "search index=* sourcetype=*auth* action=failure | stats count",
            "outbound_bytes": "search index=* sourcetype=*firewall* direction=outbound | stats sum(bytes_out) as total",
            "unique_sources": "search index=* | stats dc(src_ip) as count",
            "dns_queries": "search index=* sourcetype=*dns* | stats count",
        }

        new_anomalies = []
        for metric_name, spl in metrics_queries.items():
            try:
                results = self.agent.process_query(spl)
                if results and isinstance(results[0], dict):
                    value = float(results[0].get("count", results[0].get("total", 0)))
                    anomaly = self.add_metric(metric_name, value)
                    if anomaly:
                        new_anomalies.append(anomaly)
            except Exception as e:
                print(f"[AnomalyDetector] Metric '{metric_name}' error: {e}")

        return new_anomalies

    def get_anomalies(self, status: str = None) -> List[Dict]:
        """Get detected anomalies."""
        if status:
            return [a for a in self.anomalies if a.get("status") == status]
        return self.anomalies

    def get_baselines(self) -> Dict[str, Dict]:
        """Get current metric baselines."""
        baselines = {}
        for metric, history in self._metrics_history.items():
            if len(history) >= 2:
                mean = sum(history) / len(history)
                variance = sum((x - mean) ** 2 for x in history) / len(history)
                baselines[metric] = {
                    "mean": round(mean, 2),
                    "std_dev": round(math.sqrt(variance), 2),
                    "samples": len(history)
                }
        return baselines

    def stats(self) -> Dict[str, Any]:
        """Get anomaly detector statistics."""
        return {
            "total_anomalies": len(self.anomalies),
            "metrics_tracked": len(self._metrics_history),
            "running": self.running,
            "z_threshold": self.z_threshold
        }
