"""
CyberDashboard - Pydantic Models
"""

from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class VulnType(str, Enum):
    VULNERABILITY = "Vulnerability"
    MALWARE = "Malware"
    PHISHING = "Phishing"


class Severity(str, Enum):
    CRITICAL = "Critical"     # CVSS >= 9.0
    HIGH = "High"             # CVSS 7.0 - 8.9
    MEDIUM = "Medium"         # CVSS 4.0 - 6.9
    LOW = "Low"               # CVSS 0.1 - 3.9
    INFO = "Info"             # CVSS 0.0 / N/A


class VulnerabilityOut(BaseModel):
    id: str
    source_id: str
    type: str
    title: str
    description: Optional[str] = None
    cvss_score: float = 0.0
    severity: str = "Info"
    poc_code: Optional[str] = None
    remediation: Optional[str] = None
    published_date: Optional[str] = None
    created_at: Optional[str] = None

    model_config = {"from_attributes": True}


class SearchParams(BaseModel):
    q: Optional[str] = None
    type: Optional[str] = None
    min_cvss: float = 0.0
    page: int = 1
    per_page: int = 20


class UpdateCheckResult(BaseModel):
    new_count: int
    sources_checked: list[str]
    last_checked: str


class StatsResult(BaseModel):
    total: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    latest_date: Optional[str]


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "Info"
