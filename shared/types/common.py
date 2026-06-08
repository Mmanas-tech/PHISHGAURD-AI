from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    SOCIAL_ENGINEERING = "social_engineering"
    CREDENTIAL_THEFT = "credential_theft"
    FINANCIAL_FRAUD = "financial_fraud"
    BRAND_IMPERSONATION = "brand_impersonation"
    HOMOGRAPH_ATTACK = "homograph_attack"
    TYPOSQUATTING = "typosquatting"
    UNKNOWN = "unknown"


class SignalSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UserTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class ThreatSignal(BaseModel):
    name: str
    severity: SignalSeverity
    description: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class ScanResult(BaseModel):
    scan_id: str
    url: str
    domain: str
    risk_score: int = Field(ge=0, le=100)
    threat_level: ThreatLevel
    threat_type: ThreatType
    signals: list[ThreatSignal] = Field(default_factory=list)
    recommendation: str
    is_cached: bool = False
    scan_duration_ms: float = 0.0


class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    html_content: Optional[str] = Field(None, max_length=10_000_000)
    screenshot_b64: Optional[str] = Field(None, max_length=50_000_000)


class URLFeatures(BaseModel):
    url_length: int = 0
    num_subdomains: int = 0
    num_hyphens: int = 0
    num_digits: int = 0
    has_ip_address: bool = False
    has_port: bool = False
    uses_https: bool = False
    has_at_symbol: bool = False
    domain_entropy: float = 0.0
    tld_risk_score: float = 0.0
    homograph_score: float = 0.0
    levenshtein_distance: int = 0
    path_depth: int = 0
    has_redirect_params: bool = False
    suspicious_keywords: list[str] = Field(default_factory=list)
    domain_age_days: Optional[int] = None
    certificate_valid: Optional[bool] = None
    certificate_issuer: Optional[str] = None


class ContentFeatures(BaseModel):
    login_form_count: int = 0
    password_field_count: int = 0
    credit_card_field_count: int = 0
    brand_mentions: list[str] = Field(default_factory=list)
    urgency_score: float = 0.0
    hidden_element_count: int = 0
    external_resource_count: int = 0
    obfuscated_js_count: int = 0
    favicon_mismatch: bool = False
    copyright_year: Optional[int] = None


class GPT4Analysis(BaseModel):
    is_phishing: bool
    confidence: float = Field(ge=0.0, le=1.0)
    targeted_brand: Optional[str] = None
    attack_technique: str = ""
    signals: list[ThreatSignal] = Field(default_factory=list)
    reasoning: str = ""


class EnsembleScore(BaseModel):
    final_score: int = Field(ge=0, le=100)
    url_heuristic_score: float = 0.0
    content_analysis_score: float = 0.0
    gpt4_score: float = 0.0
    virustotal_score: float = 0.0
    domain_reputation_score: float = 0.0
    override_triggered: bool = False
    override_reason: Optional[str] = None


class ThreatReport(BaseModel):
    id: str
    url: str
    domain: str
    threat_type: ThreatType
    severity: ThreatLevel
    signals: list[ThreatSignal]
    ml_votes: int = 0
    community_reports: int = 0
    first_seen: str
    last_seen: str
    is_confirmed: bool = False
