"""
Database Connection Manager & Schema Initialization
SQLite-based persistent storage for OpenSentinel.

Usage:
    from database import init_db, get_db

    init_db()                    # Call once at startup
    db = get_db()                # Get connection (thread-local)
    db.execute("SELECT ...")     # Use standard sqlite3 API
"""
import os
import sqlite3
import threading
from typing import Optional

# ═══ Configuration ═══════════════════════════════════════════════════════════

DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "opensentinel.db")

# ═══ Thread-Local Storage ════════════════════════════════════════════════════

_local = threading.local()
_db_path: Optional[str] = None


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Initialize the database: create the data directory, database file,
    and all tables if they don't exist.

    Call this once at application startup before any get_db() calls.
    """
    global _db_path
    _db_path = db_path

    # Ensure the data directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")       # Better concurrent read performance
    conn.execute("PRAGMA foreign_keys=ON")         # Enforce FK constraints
    conn.execute("PRAGMA busy_timeout=5000")       # Wait up to 5s on lock contention

    _create_tables(conn)
    conn.close()
    print(f"[Database] Initialized at {db_path}")


def get_db() -> sqlite3.Connection:
    """
    Return a thread-local database connection.
    Creates a new connection for each thread on first access.
    """
    if _db_path is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    conn = getattr(_local, "connection", None)
    if conn is None:
        conn = sqlite3.connect(_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.connection = conn
    return conn


def close_db() -> None:
    """Close the thread-local database connection (if open)."""
    conn = getattr(_local, "connection", None)
    if conn is not None:
        conn.close()
        _local.connection = None


# ═══ Schema ══════════════════════════════════════════════════════════════════

def _create_tables(conn: sqlite3.Connection) -> None:
    """Create all tables if they don't already exist."""

    conn.executescript("""
        -- ── Alerts (from DetectionEngine) ───────────────────────────────────
        CREATE TABLE IF NOT EXISTS alerts (
            id            TEXT PRIMARY KEY,
            rule_id       TEXT NOT NULL,
            rule_name     TEXT NOT NULL,
            title         TEXT NOT NULL,
            description   TEXT,
            severity      TEXT NOT NULL,
            mitre         TEXT,
            event_count   INTEGER DEFAULT 0,
            sample_events TEXT,
            timestamp     TEXT NOT NULL,
            status        TEXT DEFAULT 'new',
            closed_at     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

        -- ── Incidents ───────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS incidents (
            id          TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            severity    TEXT NOT NULL,
            description TEXT DEFAULT '',
            source      TEXT DEFAULT 'manual',
            entities    TEXT DEFAULT '{}',
            status      TEXT DEFAULT 'open',
            owner_id    TEXT DEFAULT 'system',
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            closed_at   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
        CREATE INDEX IF NOT EXISTS idx_incidents_owner ON incidents(owner_id);

        -- ── Incident Notes (1:N) ────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS incident_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            timestamp   TEXT NOT NULL,
            author      TEXT DEFAULT 'system',
            text        TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_notes_incident ON incident_notes(incident_id);

        -- ── Incident Timeline (1:N) ─────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS incident_timeline (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            timestamp   TEXT NOT NULL,
            action      TEXT NOT NULL,
            detail      TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id);

        -- ── Alert-Incident Links (M:N) ──────────────────────────────────────
        CREATE TABLE IF NOT EXISTS incident_alerts (
            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            alert_id    TEXT NOT NULL,
            PRIMARY KEY (incident_id, alert_id)
        );

        -- ── Audit Log ───────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            method      TEXT,
            path        TEXT,
            client_ip   TEXT,
            status_code INTEGER,
            key_hint    TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    """)

    conn.commit()
