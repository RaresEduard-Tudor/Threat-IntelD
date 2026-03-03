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

export interface ThreatChecks {
  safe_browsing: SafeBrowsingResult;
  domain_age: DomainAgeResult;
  ssl_certificate: SSLResult;
  virustotal: VirusTotalResult;
}

export type Assessment = 'Safe' | 'Suspicious' | 'Malicious';

export interface ThreatReport {
  target_url: string;
  timestamp: string;
  threat_score: number;
  assessment: Assessment;
  checks: ThreatChecks;
}

export interface HistoryEntry {
  id: number;
  url: string;
  threat_score: number;
  assessment: Assessment;
  timestamp: string;
}
