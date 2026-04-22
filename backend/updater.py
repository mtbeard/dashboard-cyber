"""
CyberDashboard - Delta Updater
Called by GET /update-check to fetch only what's new since the last run.

Sources :
  - NVD         : CVE publiées (NIST)
  - PhishTank   : URLs de phishing actives
  - CISA KEV    : CVE activement exploitées (gouvernement US)
  - URLhaus     : URLs malveillantes (abuse.ch)
  - MalwareBazaar: Samples malware récents (abuse.ch)
"""

import asyncio
import base64
import os
import uuid
import httpx
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass

from database import get_connection, upsert_vulnerability, get_last_update, set_last_update
from models import UpdateCheckResult, cvss_to_severity

NVD_API_KEY      = os.getenv("NVD_API_KEY", "")
PHISHTANK_API_KEY= os.getenv("PHISHTANK_API_KEY", "")
CVSS_MIN         = float(os.getenv("CVSS_MIN", "7.0"))

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URLHAUS_URL      = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
MALWAREBAZAAR_URL= "https://mb-api.abuse.ch/api/v1/"


def encode_poc(code: str) -> str:
    return base64.b64encode(code.encode("utf-8")).decode("ascii")


# ──────────────────────────────────────────────────────────────────────────────
# NVD — CVE publiées (NIST)
# ──────────────────────────────────────────────────────────────────────────────

async def delta_nvd(client: httpx.AsyncClient) -> int:
    """Fetch CVEs published since last NVD update."""
    last = get_last_update("nvd")
    now  = datetime.now(timezone.utc)
    count = 0

    params = {"resultsPerPage": 100, "startIndex": 0}
    if last:
        params["pubStartDate"] = last[:19]
        params["pubEndDate"]   = now.strftime("%Y-%m-%dT%H:%M:%S")
    else:
        from datetime import timedelta
        week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
        params["pubStartDate"] = week_ago
        params["pubEndDate"]   = now.strftime("%Y-%m-%dT%H:%M:%S")

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    try:
        resp = await client.get(NVD_BASE, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[DELTA NVD] Error: {e}")
        return 0

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        metrics = cve.get("metrics", {})
        score, vector = 0.0, ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score  = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                vector = metrics[key][0].get("cvssData", {}).get("vectorString", "")
                break

        if score < CVSS_MIN:
            continue

        descs       = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        refs        = cve.get("references", [])
        ref_urls    = "\n".join(r.get("url", "") for r in refs[:5])
        poc_raw     = f"CVSS Vector: {vector}\n\n--- References ---\n{ref_urls}"

        row = {
            "id":             str(uuid.uuid5(uuid.NAMESPACE_URL, cve_id)),
            "source_id":      cve_id,
            "type":           "Vulnerability",
            "title":          cve_id,
            "description":    description,
            "cvss_score":     score,
            "poc_code":       encode_poc(poc_raw) if poc_raw.strip() else None,
            "remediation":    next((r.get("url") for r in refs if "patch" in r.get("tags", [])), "Check vendor advisory."),
            "published_date": cve.get("published", now.isoformat())[:19],
        }
        if upsert_vulnerability(row):
            count += 1

    set_last_update("nvd", now.isoformat())
    return count


# ──────────────────────────────────────────────────────────────────────────────
# PhishTank — Phishing actif
# ──────────────────────────────────────────────────────────────────────────────

async def delta_phishtank(client: httpx.AsyncClient) -> int:
    """Fetch new PhishTank entries."""
    count = 0
    if PHISHTANK_API_KEY:
        url = f"https://data.phishtank.com/data/{PHISHTANK_API_KEY}/online-valid.json"
    else:
        url = "https://data.phishtank.com/data/online-valid.json"

    try:
        resp = await client.get(url, timeout=60, headers={"User-Agent": "phishtank/CyberDashboard"})
        resp.raise_for_status()
        entries = resp.json()
    except Exception as e:
        print(f"[DELTA PhishTank] Error: {e}")
        return 0

    for entry in entries[:100]:
        phish_id = f"PT-{entry.get('phish_id', uuid.uuid4().hex[:8])}"
        url_val  = entry.get("url", "")
        target   = entry.get("target", "Unknown")
        submitted= entry.get("submission_time", datetime.now(timezone.utc).isoformat())

        row = {
            "id":             str(uuid.uuid5(uuid.NAMESPACE_URL, phish_id)),
            "source_id":      phish_id,
            "type":           "Phishing",
            "title":          f"Phishing – {target}",
            "description":    f"Active phishing page targeting {target}. URL: {url_val}",
            "cvss_score":     0.0,
            "poc_code":       encode_poc(f"Phishing URL: {url_val}\nTarget: {target}"),
            "remediation":    "Block URL at perimeter. Report to hosting provider.",
            "published_date": submitted[:19],
        }
        if upsert_vulnerability(row):
            count += 1

    set_last_update("phishtank", datetime.now(timezone.utc).isoformat())
    return count


# ──────────────────────────────────────────────────────────────────────────────
# CISA KEV — CVE activement exploitées (Gouvernement US)
# ──────────────────────────────────────────────────────────────────────────────

async def delta_cisa_kev(client: httpx.AsyncClient) -> int:
    """
    Fetch CISA Known Exploited Vulnerabilities catalog.
    Ce catalogue liste les CVE activement exploitées en conditions réelles.
    Mis à jour quotidiennement par l'agence de cybersécurité américaine.
    Aucune clé API requise.
    """
    last  = get_last_update("cisa_kev")
    count = 0
    cutoff = last[:10] if last else None  # YYYY-MM-DD

    try:
        resp = await client.get(CISA_KEV_URL, timeout=30,
                                headers={"User-Agent": "CyberDashboard/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[DELTA CISA KEV] Error: {e}")
        return 0

    for vuln in data.get("vulnerabilities", []):
        cve_id     = vuln.get("cveID", "UNKNOWN")
        date_added = vuln.get("dateAdded", "")

        # Sauter les entrées déjà vues
        if cutoff and date_added and date_added <= cutoff:
            continue

        vendor      = vuln.get("vendorProject", "")
        product     = vuln.get("product", "")
        name        = vuln.get("vulnerabilityName", cve_id)
        description = vuln.get("shortDescription", "")
        action      = vuln.get("requiredAction", "Apply vendor patch immediately.")
        due_date    = vuln.get("dueDate", "")
        notes       = vuln.get("notes", "")

        poc_raw = (
            f"Vendor:   {vendor}\n"
            f"Product:  {product}\n"
            f"Action:   {action}\n"
            f"Due date: {due_date}\n"
            f"Notes:    {notes}\n\n"
            f"Source:   CISA Known Exploited Vulnerabilities Catalog\n"
            f"URL:      https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        )

        row = {
            "id":          str(uuid.uuid5(uuid.NAMESPACE_URL, f"cisa-{cve_id}")),
            "source_id":   cve_id,
            "type":        "Vulnerability",
            "title":       f"[KEV] {name}",
            "description": (
                f"⚠ EXPLOITATION ACTIVE CONFIRMÉE par la CISA. "
                f"{description} "
                f"Produit concerné : {vendor} {product}."
            ),
            "cvss_score":     9.0,  # KEV = exploité réellement, toujours critique
            "poc_code":       encode_poc(poc_raw),
            "remediation":    action,
            "published_date": date_added if date_added else datetime.now(timezone.utc).isoformat()[:10],
        }
        if upsert_vulnerability(row):
            count += 1

    set_last_update("cisa_kev", datetime.now(timezone.utc).isoformat())
    return count


# ──────────────────────────────────────────────────────────────────────────────
# URLhaus (abuse.ch) — URLs malveillantes actives
# ──────────────────────────────────────────────────────────────────────────────

async def delta_urlhaus(client: httpx.AsyncClient) -> int:
    """
    Fetch recent malicious URLs from abuse.ch URLhaus.
    Base de données communautaire d'URLs servant à distribuer des malwares.
    Mise à jour en temps réel, aucune clé API requise.
    """
    last   = get_last_update("urlhaus")
    count  = 0
    cutoff = last[:19] if last else None

    try:
        resp = await client.get(
            URLHAUS_URL,
            timeout=30,
            headers={"User-Agent": "CyberDashboard/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[DELTA URLhaus] Error: {e}")
        return 0

    if data.get("query_status") == "no_results":
        set_last_update("urlhaus", datetime.now(timezone.utc).isoformat())
        return 0

    for entry in data.get("urls", []):
        entry_id   = str(entry.get("id", uuid.uuid4().hex[:8]))
        date_added = (entry.get("date_added") or "")[:19]

        if cutoff and date_added and date_added <= cutoff:
            continue

        url_val    = entry.get("url", "")
        threat     = entry.get("threat", "unknown")
        host       = entry.get("host", "")
        url_status = entry.get("url_status", "")
        tags       = ", ".join(entry.get("tags", []) or []) or "N/A"

        row = {
            "id":          str(uuid.uuid5(uuid.NAMESPACE_URL, f"urlhaus-{entry_id}")),
            "source_id":   f"UH-{entry_id}",
            "type":        "Malware",
            "title":       f"URL malveillante – {threat} ({host})",
            "description": (
                f"URL malveillante active détectée par URLhaus (abuse.ch). "
                f"Menace : {threat}. Hôte : {host}. Statut : {url_status}. "
                f"Tags : {tags}."
            ),
            "cvss_score":     8.0,
            "poc_code":       encode_poc(
                f"URL:     {url_val}\n"
                f"Threat:  {threat}\n"
                f"Host:    {host}\n"
                f"Status:  {url_status}\n"
                f"Tags:    {tags}\n\n"
                f"Source:  https://urlhaus.abuse.ch/"
            ),
            "remediation":    (
                "Bloquer l'URL et le domaine au niveau firewall et DNS. "
                "Signaler à l'hébergeur. Vérifier les logs de connexion sortants."
            ),
            "published_date": date_added if date_added else datetime.now(timezone.utc).isoformat()[:19],
        }
        if upsert_vulnerability(row):
            count += 1

    set_last_update("urlhaus", datetime.now(timezone.utc).isoformat())
    return count


# ──────────────────────────────────────────────────────────────────────────────
# MalwareBazaar (abuse.ch) — Samples de malwares récents
# ──────────────────────────────────────────────────────────────────────────────

async def delta_malwarebazaar(client: httpx.AsyncClient) -> int:
    """
    Fetch recent malware samples from abuse.ch MalwareBazaar.
    Fournit les hashes SHA256 et signatures des malwares soumis récemment.
    Idéal pour alimenter les règles EDR/AV. Aucune clé API requise.
    """
    last   = get_last_update("malwarebazaar")
    count  = 0
    cutoff = last[:19] if last else None

    try:
        resp = await client.post(
            MALWAREBAZAAR_URL,
            data={"query": "get_recent", "selector": "time"},
            timeout=30,
            headers={"User-Agent": "CyberDashboard/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[DELTA MalwareBazaar] Error: {e}")
        return 0

    if data.get("query_status") != "ok":
        print(f"[DELTA MalwareBazaar] Status: {data.get('query_status')}")
        return 0

    for sample in data.get("data", []):
        sha256     = sample.get("sha256_hash", "")
        first_seen = (sample.get("first_seen") or "")[:19]

        if not sha256:
            continue
        if cutoff and first_seen and first_seen <= cutoff:
            continue

        file_name = sample.get("file_name", "unknown")
        file_type = sample.get("file_type", "unknown")
        file_size = sample.get("file_size", 0)
        signature = sample.get("signature") or "Unknown malware"
        tags      = ", ".join(sample.get("tags", []) or []) or "N/A"
        reporter  = sample.get("reporter", "unknown")

        row = {
            "id":          str(uuid.uuid5(uuid.NAMESPACE_URL, f"mb-{sha256}")),
            "source_id":   f"MB-{sha256[:12].upper()}",
            "type":        "Malware",
            "title":       f"{signature} – {file_type.upper()}",
            "description": (
                f"Sample malware détecté par MalwareBazaar (abuse.ch). "
                f"Famille : {signature}. "
                f"Fichier : {file_name} ({file_type}, {file_size} octets). "
                f"Tags : {tags}. Signalé par : {reporter}."
            ),
            "cvss_score":  8.5,
            "poc_code":    encode_poc(
                f"SHA256:    {sha256}\n"
                f"Fichier:   {file_name}\n"
                f"Type:      {file_type}\n"
                f"Taille:    {file_size} bytes\n"
                f"Signature: {signature}\n"
                f"Tags:      {tags}\n"
                f"Reporter:  {reporter}\n\n"
                f"Lookup:    https://bazaar.abuse.ch/sample/{sha256}/"
            ),
            "remediation": (
                f"Bloquer le hash SHA256 dans l'EDR/AV : {sha256}. "
                "Scanner les endpoints pour détecter ce hash. "
                "Isoler les machines infectées."
            ),
            "published_date": first_seen if first_seen else datetime.now(timezone.utc).isoformat()[:19],
        }
        if upsert_vulnerability(row):
            count += 1

    set_last_update("malwarebazaar", datetime.now(timezone.utc).isoformat())
    return count


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrateur principal
# ──────────────────────────────────────────────────────────────────────────────

async def run_delta_update() -> dict:
    """Run all delta updaters and return a summary."""
    now       = datetime.now(timezone.utc).isoformat()
    new_total = 0
    sources   = []

    async with httpx.AsyncClient() as client:
        # ── Sources existantes ──
        nvd_new = await delta_nvd(client)
        new_total += nvd_new
        sources.append(f"NVD ({'+' if nvd_new else ''}{nvd_new})")

        phish_new = await delta_phishtank(client)
        new_total += phish_new
        sources.append(f"PhishTank ({'+' if phish_new else ''}{phish_new})")

        # ── Nouvelles sources ──
        cisa_new = await delta_cisa_kev(client)
        new_total += cisa_new
        sources.append(f"CISA KEV ({'+' if cisa_new else ''}{cisa_new})")

        urlhaus_new = await delta_urlhaus(client)
        new_total += urlhaus_new
        sources.append(f"URLhaus ({'+' if urlhaus_new else ''}{urlhaus_new})")

        mb_new = await delta_malwarebazaar(client)
        new_total += mb_new
        sources.append(f"MalwareBazaar ({'+' if mb_new else ''}{mb_new})")

    return {
        "new_count":       new_total,
        "sources_checked": sources,
        "last_checked":    now,
    }


if __name__ == "__main__":
    result = asyncio.run(run_delta_update())
    print(result)
