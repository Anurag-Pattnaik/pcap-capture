from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any


class IDSStorage:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS packet_logs (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT NOT NULL,
                    flow_id TEXT NOT NULL DEFAULT 'LEGACY',
                    flow_packet_count INTEGER NOT NULL DEFAULT 0,
                    flow_byte_count INTEGER NOT NULL DEFAULT 0,
                    flow_duration REAL NOT NULL DEFAULT 0,
                    length INTEGER NOT NULL,
                    time_diff REAL NOT NULL,
                    packet_rate REAL NOT NULL,
                    avg_length REAL NOT NULL,
                    encrypted_likely INTEGER NOT NULL,
                    prediction TEXT NOT NULL,
                    ml_confidence REAL,
                    binary_label TEXT,
                    attack_label TEXT,
                    severity TEXT NOT NULL DEFAULT 'info',
                    signature TEXT NOT NULL DEFAULT 'Metadata baseline',
                    rule_id TEXT NOT NULL DEFAULT 'META-0000',
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
                """
            )
            self._ensure_column("packet_logs", "flow_id", "TEXT NOT NULL DEFAULT 'LEGACY'")
            self._ensure_column("packet_logs", "flow_packet_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("packet_logs", "flow_byte_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column("packet_logs", "flow_duration", "REAL NOT NULL DEFAULT 0")
            self._ensure_column("packet_logs", "ml_confidence", "REAL")
            self._ensure_column("packet_logs", "binary_label", "TEXT")
            self._ensure_column("packet_logs", "attack_label", "TEXT")
            self._ensure_column("packet_logs", "severity", "TEXT NOT NULL DEFAULT 'info'")
            self._ensure_column("packet_logs", "signature", "TEXT NOT NULL DEFAULT 'Metadata baseline'")
            self._ensure_column("packet_logs", "rule_id", "TEXT NOT NULL DEFAULT 'META-0000'")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def _ensure_column(self, table_name: str, column_name: str, column_definition: str) -> None:
        columns = self._connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        if any(str(column["name"]) == column_name for column in columns):
            return

        self._connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")

    def save_packet_log(self, log: dict[str, Any]) -> None:
        values = dict(log)
        values["encrypted_likely"] = int(bool(values["encrypted_likely"]))
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO packet_logs (
                    id, timestamp, source_ip, destination_ip, source_port, destination_port,
                    protocol, flow_id, flow_packet_count, flow_byte_count, flow_duration,
                    length, time_diff, packet_rate, avg_length, encrypted_likely,
                    prediction, ml_confidence, binary_label, attack_label,
                    severity, signature, rule_id, action, reason
                )
                VALUES (
                    :id, :timestamp, :source_ip, :destination_ip, :source_port, :destination_port,
                    :protocol, :flow_id, :flow_packet_count, :flow_byte_count, :flow_duration,
                    :length, :time_diff, :packet_rate, :avg_length, :encrypted_likely,
                    :prediction, :ml_confidence, :binary_label, :attack_label,
                    :severity, :signature, :rule_id, :action, :reason
                )
                """,
                values,
            )

    def recent_logs(self, limit: int = 500) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(limit, 5000))
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM packet_logs ORDER BY id DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()

        logs = [dict(row) for row in reversed(rows)]
        for log in logs:
            log["encrypted_likely"] = bool(log["encrypted_likely"])
        return logs

    def save_blocked_ip(self, ip_address: str, reason: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO blocked_ips (ip, reason, created_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (ip_address, reason),
            )

    def remove_blocked_ip(self, ip_address: str) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip_address,))

    def list_blocked_ips(self) -> list[str]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT ip FROM blocked_ips ORDER BY ip"
            ).fetchall()
        return [str(row["ip"]) for row in rows]

    def summary(self) -> dict[str, int]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    COUNT(*) AS packets,
                    SUM(CASE WHEN severity IN ('critical', 'high', 'medium', 'low') THEN 1 ELSE 0 END) AS alerts,
                    SUM(CASE WHEN encrypted_likely = 1 THEN 1 ELSE 0 END) AS encrypted,
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked
                FROM packet_logs
                """
            ).fetchone()

        return {
            "packets": int(row["packets"] or 0),
            "alerts": int(row["alerts"] or 0),
            "encrypted": int(row["encrypted"] or 0),
            "blocked": int(row["blocked"] or 0),
        }
