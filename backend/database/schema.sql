-- NetScope SQLite Schema
-- Computer Networks Project Database

CREATE TABLE IF NOT EXISTS capture_sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    interface_name TEXT NOT NULL,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    packet_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    bpf_filter TEXT,
    status TEXT NOT NULL CHECK(status IN ('running', 'stopped', 'imported'))
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    packet_number INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    time_str TEXT NOT NULL,
    rel_time REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    length INTEGER NOT NULL,
    info TEXT NOT NULL,
    direction TEXT,
    raw_hex TEXT,
    raw_ascii TEXT,
    details_json TEXT,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_packets_src_dst ON packets(src_ip, dst_ip);
