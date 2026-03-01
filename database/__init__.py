"""
OpenSentinel Database Module
SQLite-based persistent storage for alerts, incidents, and audit logs.
"""
from database.db import init_db, get_db, close_db

__all__ = ["init_db", "get_db", "close_db"]
