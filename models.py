from datetime import datetime
from sqlalchemy import Table, Column, Integer, String, Text, DateTime, JSON, ForeignKey, Boolean
from database import metadata

logs_table = Table(
    "logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime, default=datetime.utcnow, index=True),
    Column("source_ip", String(45), index=True, nullable=True),
    Column("destination_ip", String(45), index=True, nullable=True),
    Column("event_type", String(50), index=True),
    Column("severity", String(20), default="Low"),
    Column("raw_message", Text, nullable=False),
    Column("parsed_data", JSON, nullable=True),
    Column("created_at", DateTime, default=datetime.utcnow),
)

threat_alerts_table = Table(
    "threat_alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("log_id", Integer, ForeignKey("logs.id"), nullable=True),
    Column("source_ip", String(45), index=True),
    Column("threat_type", String(100), nullable=False),
    Column("threat_score", Integer, default=0),
    Column("severity", String(20), default="Low"),
    Column("description", Text, nullable=False),
    Column("is_resolved", Boolean, default=False),
    Column("created_at", DateTime, default=datetime.utcnow, index=True),
)

blacklisted_ips_table = Table(
    "blacklisted_ips",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ip_address", String(45), unique=True, index=True, nullable=False),
    Column("reason", Text, nullable=True),
    Column("added_at", DateTime, default=datetime.utcnow),
)
