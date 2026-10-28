"""
NetScope Database Module
Safe SQLite database operations for capture sessions and packet records.
"""

import os
import sqlite3
import json
from typing import List, Dict, Any, Optional

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(DB_DIR, "netscope.db")
SCHEMA_FILE = os.path.join(DB_DIR, "schema.sql")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    with open(SCHEMA_FILE, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def create_session(session_id: str, name: str, interface_name: str, start_time: int, bpf_filter: str = "") -> None:
    conn = get_connection()
    with conn:
        conn.execute(
            """
            INSERT INTO capture_sessions (id, name, interface_name, start_time, packet_count, total_bytes, bpf_filter, status)
            VALUES (?, ?, ?, ?, 0, 0, ?, 'running')
            """,
            (session_id, name, interface_name, start_time, bpf_filter),
        )
    conn.close()


def update_session_stop(session_id: str, end_time: int, packet_count: int, total_bytes: int) -> None:
    conn = get_connection()
    with conn:
        conn.execute(
            """
            UPDATE capture_sessions
            SET end_time = ?, packet_count = ?, total_bytes = ?, status = 'stopped'
            WHERE id = ?
            """,
            (end_time, packet_count, total_bytes, session_id),
        )
    conn.close()


def insert_packet(session_id: str, pkt: Dict[str, Any]) -> None:
    conn = get_connection()
    details_str = json.dumps(pkt.get("details", {}))
    with conn:
        conn.execute(
            """
            INSERT INTO packets (session_id, packet_number, timestamp, time_str, rel_time, src_ip, dst_ip, src_port, dst_port, protocol, length, info, direction, raw_hex, raw_ascii, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                pkt.get("id", 1),
                pkt.get("timestamp", 0),
                pkt.get("timeStr", ""),
                pkt.get("relTime", 0.0),
                pkt.get("srcIp", "0.0.0.0"),
                pkt.get("dstIp", "0.0.0.0"),
                pkt.get("srcPort"),
                pkt.get("dstPort"),
                pkt.get("protocol", "OTHER"),
                pkt.get("length", 0),
                pkt.get("info", ""),
                pkt.get("direction", "UNKNOWN"),
                pkt.get("rawHex", ""),
                pkt.get("rawAscii", ""),
                details_str,
            ),
        )
    conn.close()


def get_all_sessions() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM capture_sessions ORDER BY start_time DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_session_by_id(session_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM capture_sessions WHERE id = ?", (session_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    session_data = dict(row)
    cursor.execute("SELECT * FROM packets WHERE session_id = ? ORDER BY packet_number ASC LIMIT 2000", (session_id,))
    pkts = []
    for pr in cursor.fetchall():
        p_dict = dict(pr)
        if p_dict.get("details_json"):
            try:
                p_dict["details"] = json.loads(p_dict["details_json"])
            except Exception:
                p_dict["details"] = {}
        pkts.append(p_dict)
    session_data["packets"] = pkts
    conn.close()
    return session_data


def delete_session(session_id: str) -> bool:
    conn = get_connection()
    with conn:
        res = conn.execute("DELETE FROM capture_sessions WHERE id = ?", (session_id,))
        deleted = res.rowcount > 0
    conn.close()
    return deleted
