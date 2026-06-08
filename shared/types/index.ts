export enum ThreatLevel {
  SAFE = "safe",
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export enum AnalysisStatus {
  PENDING = "pending",
  IN_PROGRESS = "in_progress",
  COMPLETED = "completed",
  FAILED = "failed",
}

export enum ThreatType {
  PHISHING = "phishing",
  MALWARE = "malware",
  SOCIAL_ENGINEERING = "social_engineering",
  CREDENTIAL_THEFT = "credential_theft",
  FINANCIAL_FRAUD = "financial_fraud",
  BRAND_IMPERSONATION = "brand_impersonation",
  HOMOGRAPH_ATTACK = "homograph_attack",
  TYPOSQUATTING = "typosquatting",
  UNKNOWN = "unknown",
}

export enum SignalSeverity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export enum UserTier {
  FREE = "free",
  PRO = "pro",
  ENTERPRISE = "enterprise",
}

export interface ThreatSignal {
  name: string;
  severity: SignalSeverity;
  description?: string;
  confidence: number;
}

export interface ScanResult {
  scan_id: string;
  url: string;
  domain: string;
  risk_score: number;
  threat_level: ThreatLevel;
  threat_type: ThreatType;
  signals: ThreatSignal[];
  recommendation: string;
  is_cached: boolean;
  scan_duration_ms: number;
}

export interface ScanRequest {
  url: string;
  html_content?: string;
  screenshot_b64?: string;
}

export interface User {
  id: string;
  email: string;
  tier: UserTier;
  is_active: boolean;
  created_at: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface DashboardStats {
  scans_today: number;
  threats_blocked_today: number;
  detection_accuracy: number;
  avg_response_time_ms: number;
  total_scans: number;
  total_threats: number;
}

export interface TimelinePoint {
  date: string;
  scans: number;
  threats: number;
}

export interface ThreatLogEntry {
  id: string;
  url: string;
  domain: string;
  threat_type: ThreatType;
  severity: ThreatLevel;
  risk_score: number;
  detected_at: string;
  status: "active" | "blocked" | "false_positive";
}

export interface SettingsConfig {
  protection_level: "paranoid" | "balanced" | "relaxed";
  whitelist: string[];
  blacklist: string[];
  notifications_enabled: boolean;
  data_sharing: "none" | "anonymized" | "full";
}

export interface ExtensionMessage {
  type: "SCAN_REQUEST" | "SCAN_RESULT" | "PAGE_LOADED" | "UPDATE_BADGE";
  payload: Record<string, unknown>;
}
