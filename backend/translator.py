"""
CyberDashboard - Moteur de Traduction EN → FR
Traduit les descriptions de vulnérabilités en français en préservant
tous les termes techniques (CVE, protocoles, noms de malware, hashes…).

Utilise Google Translate via deep-translator (gratuit, sans clé API).
"""

import re
import time
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Termes techniques à protéger (ordre important : URLs en PREMIER pour
#     éviter que les patterns internes ne fragmentent les URLs) ──────────────
PROTECTED_PATTERNS = [
    # URLs complètes (en premier — capture CVE/hash/IP à l'intérieur de l'URL)
    (r'https?://[^\s<>"\')\]]+',                                            'URL'),
    # Identifiants de vulnérabilités
    (r'CVE-\d{4}-\d+',                                                     'CVE'),
    (r'CWE-\d+',                                                            'CWE'),
    (r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}',                        'GHSA'),
    # Chemins de registre Windows
    (r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT)\\[^\s,;)]+', 'REG'),
    # Chemins de fichiers Windows
    (r'[A-Za-z]:\\(?:[^\s<>"\'\\/:*?|]+\\)*[^\s<>"\'\\/:*?|]+\.\w{1,6}', 'WPATH'),
    # Chemins Unix
    (r'/(?:usr|etc|var|tmp|opt|home|bin|sbin|lib|proc)/[^\s<>"\']+',       'UPATH'),
    # Hashes (SHA256/SHA1/MD5)
    (r'\b[A-Fa-f0-9]{64}\b',                                               'SHA256'),
    (r'\b[A-Fa-f0-9]{40}\b',                                               'SHA1'),
    (r'\b[A-Fa-f0-9]{32}\b',                                               'MD5'),
    # Adresses IP (avec masque ou port optionnel)
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?(?::\d{1,5})?\b','IP'),
    # Numéros de version (v1.2.3 ou 1.2.3.4)
    (r'\bv?\d+\.\d+(?:\.\d+){0,3}\b',                                      'VER'),
    # Types de vulnérabilités (abréviations)
    (r'\b(?:XSS|SQLi|SQL\s+Injection|CSRF|XXE|SSRF|LFI|RFI|IDOR|SSTI|RCE|'
     r'ROP|UAF|OOB|DoS|DDoS|PoC|IoC|C2|C&C|APT|TTP|TTPs|MITRE|ATT&CK|'
     r'CVSS|EPSS|NVD|NIST|CERT|CISA|OWASP|SANS)\b',                       'SECTERM'),
    # Protocoles réseau
    (r'\b(?:RDP|SSH|SMB|FTP|SFTP|FTPS|HTTP|HTTPS|TLS|SSL|TCP|UDP|DNS|'
     r'LDAP|LDAPS|NTLM|Kerberos|OAuth|SAML|JWT|SNMP|SMTP|IMAP|POP3|'
     r'MQTT|gRPC|REST|SOAP|WebSocket|BGP|OSPF|IPsec)\b',                   'PROTO'),
    # Composants Windows/système
    (r'\b(?:PowerShell|WMI|DCOM|COM|DLL|EXE|MSI|BAT|CMD|PS1|VBA|VBS|HTA|'
     r'LNK|ISO|VHD|VHDX|mshta|wscript|cscript|regsvr32|rundll32|msiexec|'
     r'svchost|lsass|winlogon|csrss|services\.exe|explorer\.exe)\b',       'WINCOMP'),
    # Familles de malware / acteurs de menace connus
    (r'\b(?:LockBit|Emotet|Ryuk|Conti|REvil|BlackCat|ALPHV|Cl0p|Hive|'
     r'BlackBasta|Lazarus|Sandworm|CozyBear|FancyBear|Carbanak|Turla|'
     r'APT\d+|TA\d+|FIN\d+|UNC\d+|LAPSUS\$?)\b',                         'MALWARE'),
    # Noms propres de produits logiciels (garde le nom exact)
    (r'\b(?:Windows|Linux|macOS|Android|iOS|Outlook|Exchange|SharePoint|'
     r'Apache|Nginx|OpenSSL|Log4j|Spring|Kubernetes|Docker|VMware|'
     r'Fortinet|Citrix|Ivanti|Palo\s+Alto|Check\s+Point|CrowdStrike)\b',   'PRODUCT'),
]

MAX_CHARS = 4500  # Limite sécurisée Google Translate


class _Protector:
    """Remplace les termes techniques par des marqueurs avant traduction."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._n = 0

    def _mark(self, prefix: str, value: str) -> str:
        # Format : ZPROT<n>_<PREFIX>Z — sans espaces pour survivre à la traduction
        key = f'ZPROT{self._n}_{prefix}Z'
        self._n += 1
        self._store[key] = value
        return key

    def protect(self, text: str) -> str:
        for pattern, prefix in PROTECTED_PATTERNS:
            def _sub(m, p=prefix):
                return self._mark(p, m.group(0))
            text = re.sub(pattern, _sub, text, flags=re.IGNORECASE)
        return text

    def restore(self, text: str) -> str:
        # Restauration en ordre inverse d'insertion :
        # les placeholders imbriqués (ex: CVE dans une URL) sont résolus correctement
        for key, original in reversed(list(self._store.items())):
            text = text.replace(key, original)
        return text


def _chunk_text(text: str, max_len: int) -> list[str]:
    """Découpe le texte en morceaux ≤ max_len en respectant les fins de phrases."""
    if len(text) <= max_len:
        return [text]
    sentences = re.split(r'(?<=[.!?\n])\s+', text)
    chunks, current = [], ''
    for sent in sentences:
        if len(current) + len(sent) + 1 <= max_len:
            current += (' ' if current else '') + sent
        else:
            if current:
                chunks.append(current)
            # Si une phrase seule dépasse la limite, on la coupe brutalement
            while len(sent) > max_len:
                chunks.append(sent[:max_len])
                sent = sent[max_len:]
            current = sent
    if current:
        chunks.append(current)
    return chunks


def _translate_sync(text: str) -> str:
    """Traduction synchrone (appelée dans un thread depuis le contexte async)."""
    from deep_translator import GoogleTranslator

    protector = _Protector()
    protected = protector.protect(text)

    chunks = _chunk_text(protected, MAX_CHARS)
    gt = GoogleTranslator(source='en', target='fr')

    translated_parts = []
    for i, chunk in enumerate(chunks):
        if i > 0:
            time.sleep(0.4)  # Politesse envers l'API Google
        part = gt.translate(chunk)
        translated_parts.append(part or chunk)

    merged = ' '.join(translated_parts)
    return protector.restore(merged)


# ─── API publique ─────────────────────────────────────────────────────────────

async def translate_to_french(text: str) -> Optional[str]:
    """
    Traduit `text` de l'anglais vers le français de manière asynchrone,
    en préservant tous les termes techniques.
    Retourne None si la traduction échoue ou si deep-translator est absent.
    """
    if not text or not text.strip():
        return None
    try:
        result = await asyncio.to_thread(_translate_sync, text)
        return result
    except ImportError:
        logger.warning(
            "[Traducteur] deep-translator non installé. "
            "Lance : python -m pip install deep-translator"
        )
        return None
    except Exception as e:
        logger.warning(f"[Traducteur] Échec : {e}")
        return None


async def translate_entry(entry: dict) -> dict:
    """
    Traduit title + description + remediation d'une entrée.
    Retourne le dict enrichi des champs _fr.
    """
    title_fr, desc_fr, remed_fr = await asyncio.gather(
        translate_to_french(entry.get('title', '')),
        translate_to_french(entry.get('description', '')),
        translate_to_french(entry.get('remediation', '')),
    )
    return {
        'title_fr':       title_fr,
        'description_fr': desc_fr,
        'remediation_fr': remed_fr,
    }


def is_available() -> bool:
    """Vérifie si deep-translator est installé."""
    try:
        from deep_translator import GoogleTranslator  # noqa: F401
        return True
    except ImportError:
        return False
