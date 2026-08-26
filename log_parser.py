import re
from datetime import datetime

class LogParser:

    @staticmethod
    def parse_pfsense(raw_log: str) -> dict:
        raw_lower = raw_log.lower()
        action = "block" if ("block" in raw_lower or "deny" in raw_lower) else "pass"
        
        rule_match = re.search(r'filterlog:?\s*(\d+)', raw_log, re.IGNORECASE)
        rule_id = rule_match.group(1) if rule_match else "1000000101"

        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_log)
        source_ip = ip_matches[0] if len(ip_matches) >= 1 else "192.168.1.1"
        dest_ip = ip_matches[1] if len(ip_matches) >= 2 else "10.0.0.1"

        port_match = re.search(r',(\d{1,5}),(\d{1,5})', raw_log)
        dest_port = int(port_match.group(2)) if port_match else 80

        return { 
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "event_type": "firewall_block" if action == "block" else "firewall_pass",
            "severity": "Medium" if action == "block" else "Low",
            "parsed_data": {
                "action": action,
                "rule_id": rule_id,
                "destination_port": dest_port,
                "log_source": "pfSense"
            }
        }

    @staticmethod
    def parse_auth(raw_log: str) -> dict:
        raw_lower = raw_log.lower()
        is_failed = "failed" in raw_lower or "invalid" in raw_lower or "denied" in raw_lower
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_log)
        source_ip = ip_match.group(0) if ip_match else "127.0.0.1"

        port_match = re.search(r'port\s+(\d+)', raw_log, re.IGNORECASE)
        port = int(port_match.group(1)) if port_match else 22

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": source_ip,
            "destination_ip": "127.0.0.1",
            "event_type": "failed_login" if is_failed else "successful_login",
            "severity": "High" if is_failed else "Low",
            "parsed_data": {
                "auth_status": "FAILED" if is_failed else "SUCCESS",
                "destination_port": port,
                "service": "SSH"
            }
        }

    @staticmethod
    def parse_network(raw_log: str) -> dict:
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_log)
        source_ip = ip_matches[0] if len(ip_matches) >= 1 else "10.0.0.2"
        dest_ip = ip_matches[1] if len(ip_matches) >= 2 else "10.0.0.1"

        port_match = re.search(r'(?:PORT|DST_PORT|DPORT)[:=](\d+)', raw_log, re.IGNORECASE)
        dest_port = int(port_match.group(1)) if port_match else 80

        proto_match = re.search(r'PROTO[:=](\w+)', raw_log, re.IGNORECASE)
        protocol = proto_match.group(1).upper() if proto_match else "TCP"

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "event_type": "network_connection",
            "severity": "Low",
            "parsed_data": {
                "protocol": protocol,
                "destination_port": dest_port
            }
        }

    @classmethod
    def parse(cls, raw_log: str, log_format: str = "auto") -> dict:
        raw_lower = raw_log.lower()
        if log_format == "pfsense" or "filterlog" in raw_lower:
            return cls.parse_pfsense(raw_log)
        elif log_format == "auth" or "password" in raw_lower or "ssh" in raw_lower or "login" in raw_lower:
            return cls.parse_auth(raw_log)
        elif log_format == "network" or "traffic" in raw_lower or "src=" in raw_lower:
            return cls.parse_network(raw_log)
        else:
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_log)
            port_match = re.search(r'port[:=]?\s*(\d+)', raw_log, re.IGNORECASE)
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": ip_matches[0] if ip_matches else "127.0.0.1",
                "destination_ip": ip_matches[1] if len(ip_matches) > 1 else "127.0.0.1",
                "event_type": "custom_event",
                "severity": "Low",
                "parsed_data": {
                    "raw": raw_log,
                    "destination_port": int(port_match.group(1)) if port_match else 80
                }
            }
