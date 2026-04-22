"""
CyberDashboard - Database Layer
SQLite3 with FTS5 for full-text search performance.
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "database.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables on first run."""
    conn = get_connection()
    cur = conn.cursor()

    # Main vulnerabilities table
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id              TEXT PRIMARY KEY,
            source_id       TEXT NOT NULL,
            type            TEXT NOT NULL CHECK(type IN ('Vulnerability','Malware','Phishing')),
            title           TEXT NOT NULL,
            description     TEXT,
            cvss_score      REAL DEFAULT 0.0,
            poc_code        TEXT,
            remediation     TEXT,
            published_date  TEXT,
            created_at      TEXT DEFAULT (datetime('now')),
            title_fr        TEXT,
            description_fr  TEXT,
            remediation_fr  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_type       ON vulnerabilities(type);
        CREATE INDEX IF NOT EXISTS idx_vuln_cvss       ON vulnerabilities(cvss_score DESC);
        CREATE INDEX IF NOT EXISTS idx_vuln_published  ON vulnerabilities(published_date DESC);

        -- FTS5 virtual table for instant full-text search
        CREATE VIRTUAL TABLE IF NOT EXISTS vulnerabilities_fts USING fts5(
            id UNINDEXED,
            source_id,
            title,
            description,
            content='vulnerabilities',
            content_rowid='rowid'
        );

        -- Triggers to keep FTS in sync
        CREATE TRIGGER IF NOT EXISTS vuln_ai AFTER INSERT ON vulnerabilities BEGIN
            INSERT INTO vulnerabilities_fts(rowid, id, source_id, title, description)
            VALUES (new.rowid, new.id, new.source_id, new.title, new.description);
        END;

        CREATE TRIGGER IF NOT EXISTS vuln_ad AFTER DELETE ON vulnerabilities BEGIN
            INSERT INTO vulnerabilities_fts(vulnerabilities_fts, rowid, id, source_id, title, description)
            VALUES ('delete', old.rowid, old.id, old.source_id, old.title, old.description);
        END;

        CREATE TRIGGER IF NOT EXISTS vuln_au AFTER UPDATE ON vulnerabilities BEGIN
            INSERT INTO vulnerabilities_fts(vulnerabilities_fts, rowid, id, source_id, title, description)
            VALUES ('delete', old.rowid, old.id, old.source_id, old.title, old.description);
            INSERT INTO vulnerabilities_fts(rowid, id, source_id, title, description)
            VALUES (new.rowid, new.id, new.source_id, new.title, new.description);
        END;

        -- Metadata table for tracking last update timestamps per source
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)

    conn.commit()

    # Migration : ajoute les colonnes FR si elles n'existent pas encore
    # (pour les utilisateurs qui avaient une ancienne version de la DB)
    for col in ("title_fr", "description_fr", "remediation_fr"):
        try:
            conn.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col} TEXT")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Colonne déjà présente

    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")


def get_last_update(source: str) -> str | None:
    conn = get_connection()
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (f"last_update_{source}",)).fetchone()
    conn.close()
    return row["value"] if row else None


def set_last_update(source: str, timestamp: str):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        (f"last_update_{source}", timestamp)
    )
    conn.commit()
    conn.close()


def save_translation(vuln_id: str, title_fr: str | None, description_fr: str | None, remediation_fr: str | None):
    """Enregistre la traduction française d'une entrée existante."""
    conn = get_connection()
    conn.execute(
        """UPDATE vulnerabilities
           SET title_fr = ?, description_fr = ?, remediation_fr = ?
           WHERE id = ?""",
        (title_fr, description_fr, remediation_fr, vuln_id)
    )
    conn.commit()
    conn.close()


def get_untranslated(limit: int = 50) -> list:
    """Retourne les entrées sans traduction française (description_fr IS NULL)."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, title, description, remediation
           FROM vulnerabilities
           WHERE description_fr IS NULL
           LIMIT ?""",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def upsert_vulnerability(data: dict) -> bool:
    """Insert or update a vulnerability. Returns True if it was a new insert."""
    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM vulnerabilities WHERE source_id = ?",
        (data["source_id"],)
    ).fetchone()

    if existing:
        conn.close()
        return False

    conn.execute("""
        INSERT INTO vulnerabilities
            (id, source_id, type, title, description, cvss_score, poc_code, remediation, published_date)
        VALUES
            (:id, :source_id, :type, :title, :description, :cvss_score, :poc_code, :remediation, :published_date)
    """, data)
    conn.commit()
    conn.close()
    return True
