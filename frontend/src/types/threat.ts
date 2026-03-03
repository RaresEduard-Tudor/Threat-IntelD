export interface SafeBrowsingResult {
  flagged: boolean;
  threat_type: string | null;
  details: string;
}

export interface DomainAgeResult {
  days_registered: number | null;
  risk_level: 'Low' | 'Medium' | 'High' | 'Unknown';
  details: string;
}

export interface SSLResult {
  valid: boolean;
  issuer: string | null;
  expires_in_days: number | null;
  details: string;
}

export interface VirusTotalResult {
  detected: boolean;
  malicious: number;
  suspicious: number;
  total: number;
  details: string;
}

export interface IpReputationResult {
  ip: string | null;
  abuse_confidence_score: number;
  is_flagged: boolean;
  country_code: string | null;
  total_reports: number;
  details: string;
}

export interface UrlHeuristicsResult {
  is_suspicious: boolean;
  flag_count: number;
  flags: string[];
  risk_score: number;
  details: string;
}

export interface ScreenshotResult {
  available: boolean;
  image_b64: string | null;
  details: string;
}

export interface ThreatChecks {
  safe_browsing: SafeBrowsingResult;
  domain_age: DomainAgeResult;
  ssl_certificate: SSLResult;
  virustotal: VirusTotalResult;
  ip_reputation: IpReputationResult;
  url_heuristics: UrlHeuristicsResult;
}

export type Assessment = 'Safe' | 'Suspicious' | 'Malicious';

export interface ThreatReport {
  target_url: string;
  timestamp: string;
  threat_score: number;
  assessment: Assessment;
  checks: ThreatChecks;
  screenshot?: ScreenshotResult;
}

export interface HistoryEntry {
  id: number;
  url: string;
  threat_score: number;
  assessment: Assessment;
  timestamp: string;
}
