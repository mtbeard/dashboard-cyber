"""
CyberDashboard - FastAPI Backend
Expose REST endpoints consumed by the frontend.
"""

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from database import get_connection, init_db, save_translation, get_untranslated
from models import VulnerabilityOut, StatsResult, UpdateCheckResult, cvss_to_severity

# ---------------------------------------------------------------------------
# App Init
# ---------------------------------------------------------------------------
app = FastAPI(
    title="CyberDashboard API",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    init_db()
    print("[API] CyberDashboard backend ready.")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def row_to_vuln(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["severity"] = cvss_to_severity(d.get("cvss_score", 0.0))
    # Decode base64 poc_code for display, keep it safe
    if d.get("poc_code"):
        import base64, html
        try:
            decoded = base64.b64decode(d["poc_code"]).decode("utf-8")
            d["poc_code"] = html.escape(decoded)
        except Exception:
            d["poc_code"] = html.escape(d["poc_code"])
    return d


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/vulnerabilities", response_model=dict)
async def list_vulnerabilities(
    q: Optional[str] = Query(None, description="Full-text search query"),
    type: Optional[str] = Query(None, description="Filter by type: Vulnerability|Malware|Phishing"),
    min_cvss: float = Query(0.0, description="Minimum CVSS score"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    conn = get_connection()
    offset = (page - 1) * per_page
    params = []

    if q and q.strip():
        # FTS5 search
        base_sql = """
            SELECT v.* FROM vulnerabilities v
            JOIN vulnerabilities_fts fts ON v.rowid = fts.rowid
            WHERE fts.vulnerabilities_fts MATCH ?
        """
        params.append(q.strip() + "*")
    else:
        base_sql = "SELECT * FROM vulnerabilities v WHERE 1=1"

    if type:
        base_sql += " AND v.type = ?"
        params.append(type)

    if min_cvss > 0:
        base_sql += " AND v.cvss_score >= ?"
        params.append(min_cvss)

    # Count
    count_sql = f"SELECT COUNT(*) as cnt FROM ({base_sql})"
    total = conn.execute(count_sql, params).fetchone()["cnt"]

    # Data
    data_sql = base_sql + " ORDER BY v.published_date DESC, v.cvss_score DESC LIMIT ? OFFSET ?"
    rows = conn.execute(data_sql, params + [per_page, offset]).fetchall()
    conn.close()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [row_to_vuln(r) for r in rows],
    }


@app.get("/vulnerabilities/{vuln_id}", response_model=dict)
async def get_vulnerability(vuln_id: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return row_to_vuln(row)


@app.get("/stats", response_model=StatsResult)
async def get_stats():
    conn = get_connection()

    total = conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities").fetchone()["cnt"]

    by_type_rows = conn.execute(
        "SELECT type, COUNT(*) as cnt FROM vulnerabilities GROUP BY type"
    ).fetchall()
    by_type = {r["type"]: r["cnt"] for r in by_type_rows}

    all_rows = conn.execute("SELECT cvss_score FROM vulnerabilities").fetchall()
    by_severity: dict = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in all_rows:
        sev = cvss_to_severity(r["cvss_score"])
        by_severity[sev] = by_severity.get(sev, 0) + 1

    latest = conn.execute(
        "SELECT published_date FROM vulnerabilities ORDER BY published_date DESC LIMIT 1"
    ).fetchone()
    conn.close()

    return StatsResult(
        total=total,
        by_type=by_type,
        by_severity=by_severity,
        latest_date=latest["published_date"] if latest else None,
    )


@app.get("/recent-alerts", response_model=list)
async def recent_alerts(limit: int = Query(10, ge=1, le=50)):
    """Return the most recently added entries for the live ticker."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, source_id, type, title, cvss_score, published_date
           FROM vulnerabilities
           ORDER BY created_at DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {**dict(r), "severity": cvss_to_severity(r["cvss_score"])}
        for r in rows
    ]


@app.get("/update-check")
async def update_check():
    """
    Trigger a delta update from all configured sources.
    Returns how many new entries were added.
    """
    from updater import run_delta_update
    result = await run_delta_update()
    return result


@app.get("/translation-status")
async def translation_status():
    """Retourne le statut de la traduction française dans la base."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities").fetchone()["cnt"]
    translated = conn.execute(
        "SELECT COUNT(*) as cnt FROM vulnerabilities WHERE description_fr IS NOT NULL"
    ).fetchone()["cnt"]
    conn.close()
    from translator import is_available
    return {
        "total": total,
        "translated": translated,
        "pending": total - translated,
        "engine_available": is_available(),
    }


@app.get("/translate/{vuln_id}")
async def translate_one(vuln_id: str):
    """Traduit une seule entrée et enregistre la traduction en base."""
    from translator import translate_entry, is_available
    if not is_available():
        raise HTTPException(
            status_code=503,
            detail="deep-translator non installé. Lance : python -m pip install deep-translator"
        )
    conn = get_connection()
    row = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Entrée introuvable")

    entry = dict(row)
    translations = await translate_entry(entry)
    save_translation(
        vuln_id,
        translations["title_fr"],
        translations["description_fr"],
        translations["remediation_fr"],
    )
    return {"id": vuln_id, "status": "translated", **translations}


@app.get("/translate-all")
async def translate_all(batch: int = Query(20, ge=1, le=100)):
    """
    Traduit le prochain batch d'entrées sans traduction française.
    Appelle plusieurs fois cet endpoint pour traduire toute la base.
    """
    from translator import translate_entry, is_available
    if not is_available():
        raise HTTPException(
            status_code=503,
            detail="deep-translator non installé. Lance : python -m pip install deep-translator"
        )

    pending = get_untranslated(limit=batch)
    if not pending:
        return {"translated": 0, "message": "Tout est déjà traduit !"}

    count = 0
    for entry in pending:
        try:
            translations = await translate_entry(entry)
            save_translation(
                entry["id"],
                translations["title_fr"],
                translations["description_fr"],
                translations["remediation_fr"],
            )
            count += 1
        except Exception as e:
            print(f"[Traduction] Erreur sur {entry['id']}: {e}")

    conn = get_connection()
    remaining = conn.execute(
        "SELECT COUNT(*) as cnt FROM vulnerabilities WHERE description_fr IS NULL"
    ).fetchone()["cnt"]
    conn.close()

    return {
        "translated": count,
        "remaining": remaining,
        "message": f"{count} entrée(s) traduite(s). {remaining} restante(s).",
    }


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
