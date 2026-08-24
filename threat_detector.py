import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from sqlalchemy import select, func
from sqlalchemy.engine import Connection
import models

class ThreatDetector:
    """
    Rule-Based & Statistical Anomaly Threat Detection Engine.
    """

    def __init__(self):
        # Sliding window in-memory state for statistical anomaly calculation per IP
        # Map: ip -> list of timestamps
        self.ip_traffic_history: Dict[str, List[datetime]] = {}
        # Map: ip -> list of destination ports scanned recently
        self.ip_port_scan_history: Dict[str, List[Tuple[datetime, int]]] = {}

    def is_blacklisted(self, ip_address: str, conn: Connection) -> bool:
        stmt = select(models.blacklisted_ips_table).where(models.blacklisted_ips_table.c.ip_address == ip_address)
        result = conn.execute(stmt).mappings().first()
        return result is not None

    def check_failed_logins(self, source_ip: str, conn: Connection) -> int:
        """Check count of failed logins in last 1 minute for this source IP."""
        one_min_ago = datetime.utcnow() - timedelta(minutes=1)
        stmt = select(func.count()).select_from(models.logs_table).where(
            models.logs_table.c.source_ip == source_ip,
            models.logs_table.c.event_type == 'failed_login',
            models.logs_table.c.timestamp >= one_min_ago
        )
        count = conn.execute(stmt).scalar() or 0
        return count

    def check_firewall_blocks(self, source_ip: str, conn: Connection) -> int:
        """Check count of firewall blocks in last 5 minutes for this source IP."""
        five_min_ago = datetime.utcnow() - timedelta(minutes=5)
        stmt = select(func.count()).select_from(models.logs_table).where(
            models.logs_table.c.source_ip == source_ip,
            models.logs_table.c.event_type == 'firewall_block',
            models.logs_table.c.timestamp >= five_min_ago
        )
        count = conn.execute(stmt).scalar() or 0
        return count

    def track_port_scan(self, source_ip: str, dest_port: Optional[int]) -> bool:
        """Track port scan pattern: 4 or more distinct ports scanned in 2 minutes."""
        if not dest_port:
            return False
        
        now = datetime.utcnow()
        if source_ip not in self.ip_port_scan_history:
            self.ip_port_scan_history[source_ip] = []
        
        # Keep entries from last 2 minutes
        cutoff = now - timedelta(minutes=2)
        self.ip_port_scan_history[source_ip] = [
            (ts, p) for ts, p in self.ip_port_scan_history[source_ip] if ts >= cutoff
        ]
        self.ip_port_scan_history[source_ip].append((now, dest_port))

        recent_ports = {p for _, p in self.ip_port_scan_history[source_ip]}
        return len(recent_ports) >= 4

    def check_statistical_anomaly(self, source_ip: str) -> Tuple[bool, float, float]:
        """
        Calculates rolling connection frequency moving average and standard deviation.
        Flags activity > 3 standard deviations above mean.
        Returns: (is_anomaly, current_rate, threshold)
        """
        now = datetime.utcnow()
        if source_ip not in self.ip_traffic_history:
            self.ip_traffic_history[source_ip] = []

        # Keep history for 10 minutes
        cutoff = now - timedelta(minutes=10)
        self.ip_traffic_history[source_ip] = [
            ts for ts in self.ip_traffic_history[source_ip] if ts >= cutoff
        ]
        self.ip_traffic_history[source_ip].append(now)

        timestamps = self.ip_traffic_history[source_ip]
        if len(timestamps) < 10:
            return False, float(len(timestamps)), 0.0

        # Bin connection timestamps into 1-minute intervals
        bins = {}
        for ts in timestamps:
            minute_bin = ts.replace(second=0, microsecond=0)
            bins[minute_bin] = bins.get(minute_bin, 0) + 1

        counts = list(bins.values())
        if len(counts) < 3:
            return False, float(counts[-1]), 0.0

        mean = float(np.mean(counts[:-1]))
        std = float(np.std(counts[:-1]))
        current_rate = float(counts[-1])

        # Default std dev fallback if std dev is zero
        std_threshold = std if std > 0.5 else 1.0
        anomaly_threshold = mean + (3.0 * std_threshold)

        is_anomaly = current_rate > anomaly_threshold and current_rate >= 8
        return is_anomaly, current_rate, anomaly_threshold

    def evaluate(self, log_entry: dict, conn: Connection) -> Optional[dict]:
        """
        Evaluates incoming parsed log and generates a Threat Alert dict if a threat is detected.
        """
        source_ip = log_entry.get('source_ip', '127.0.0.1')
        event_type = log_entry.get('event_type', '')
        parsed_data = log_entry.get('parsed_data', {}) or {}
        dest_port = parsed_data.get('destination_port')

        score = 0
        reasons = []
        threat_type = "Unusual Activity"

        # Rule 1: Blacklisted IP
        if self.is_blacklisted(source_ip, conn):
            score += 50
            reasons.append(f"Traffic originating from blacklisted IP {source_ip}")
            threat_type = "Blacklisted IP Access"

        # Rule 2: Multiple Failed Logins
        if event_type == 'failed_login':
            failed_count = self.check_failed_logins(source_ip, conn) + 1
            if failed_count >= 5:
                score += 30
                reasons.append(f"Brute-force pattern: {failed_count} failed logins in 1 minute")
                threat_type = "Brute Force Authentication Attempt"

        # Rule 3: Firewall Blocks
        if event_type == 'firewall_block':
            block_count = self.check_firewall_blocks(source_ip, conn) + 1
            if block_count >= 3:
                score += 20
                reasons.append(f"Repeated firewall blocks: {block_count} blocks in 5 minutes")
                threat_type = "Repeated Firewall Block Violation"

        # Rule 4: Port Scan Identification
        if self.track_port_scan(source_ip, dest_port):
            score += 40
            reasons.append(f"Port scan pattern detected from {source_ip}")
            threat_type = "Port Scanning Activity"

        # Rule 5: Statistical Anomaly Detection (> 3 Sigma)
        is_anomaly, rate, threshold = self.check_statistical_anomaly(source_ip)
        if is_anomaly:
            score += 35
            reasons.append(f"Statistical Anomaly: Traffic rate {rate:.1f} req/min exceeds 3-sigma threshold ({threshold:.1f})")
            threat_type = "Traffic Volume Anomaly (>3 Sigma)"

        # Cap score at 100
        score = min(score, 100)

        # Severity Classification
        if score == 0:
            return None

        if score <= 30:
            severity = "Low"
        elif score <= 60:
            severity = "Medium"
        elif score <= 80:
            severity = "High"
        else:
            severity = "Critical"

        description = "; ".join(reasons) if reasons else f"Suspicious event triggered from {source_ip}"

        return {
            "source_ip": source_ip,
            "threat_type": threat_type,
            "threat_score": score,
            "severity": severity,
            "description": description,
            "is_resolved": False
        }

threat_detector = ThreatDetector()
