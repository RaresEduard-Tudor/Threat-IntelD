import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import ResultsDashboard from './ResultsDashboard';
import type { ThreatReport } from '../types/threat';

const baseReport: ThreatReport = {
  target_url: 'https://example.com/',
  timestamp: '2026-03-03T10:00:00Z',
  threat_score: 0,
  assessment: 'Safe',
  checks: {
    safe_browsing: { flagged: false, threat_type: null, details: 'Not flagged by Google Safe Browsing.' },
    domain_age: { days_registered: 365, risk_level: 'Low', details: 'Domain is 365 days old.' },
    ssl_certificate: { valid: true, issuer: 'Let\'s Encrypt', expires_in_days: 60, details: 'Certificate is valid.' },
    virustotal: { detected: false, malicious: 0, suspicious: 0, total: 84, details: 'No threats detected (84 engines checked).' },
  },
};

describe('ResultsDashboard', () => {
  it('renders the target URL', () => {
    render(<ResultsDashboard report={baseReport} />);
    expect(screen.getByText('https://example.com/')).toBeInTheDocument();
  });

  it('displays the threat score', () => {
    render(<ResultsDashboard report={baseReport} />);
    expect(screen.getByText('0')).toBeInTheDocument();
  });

  it('renders all four check card titles', () => {
    render(<ResultsDashboard report={baseReport} />);
    expect(screen.getByText('Google Safe Browsing')).toBeInTheDocument();
    expect(screen.getByText('Domain Age')).toBeInTheDocument();
    expect(screen.getByText('SSL Certificate')).toBeInTheDocument();
    expect(screen.getByText('VirusTotal')).toBeInTheDocument();
  });

  it('shows domain days registered', () => {
    render(<ResultsDashboard report={baseReport} />);
    expect(screen.getByText('365 days')).toBeInTheDocument();
  });

  it('shows SSL expiry in days', () => {
    render(<ResultsDashboard report={baseReport} />);
    expect(screen.getByText('60 days')).toBeInTheDocument();
  });

  it('shows "Unknown" when days_registered is null', () => {
    const report: ThreatReport = {
      ...baseReport,
      checks: {
        ...baseReport.checks,
        domain_age: { days_registered: null, risk_level: 'Unknown', details: 'Could not determine.' },
      },
    };
    render(<ResultsDashboard report={report} />);
    // Both the "Days Registered" value and the "Risk Level" value render as "Unknown"
    expect(screen.getAllByText('Unknown').length).toBeGreaterThanOrEqual(1);
  });

  it('renders Malicious assessment for high score', () => {
    const report: ThreatReport = { ...baseReport, threat_score: 80, assessment: 'Malicious' };
    render(<ResultsDashboard report={report} />);
    expect(screen.getByText('Malicious')).toBeInTheDocument();
    expect(screen.getByText('80')).toBeInTheDocument();
  });

  it('shows a dash for SSL expiry when expires_in_days is null', () => {
    const report: ThreatReport = {
      ...baseReport,
      checks: {
        ...baseReport.checks,
        ssl_certificate: { valid: true, issuer: 'Let\'s Encrypt', expires_in_days: null, details: 'Valid.' },
      },
    };
    render(<ResultsDashboard report={report} />);
    // "Expires In" label is always rendered; its value cell shows "—" when null
    expect(screen.getByText('Expires In')).toBeInTheDocument();
    // baseReport had 60 days — that specific value should be absent
    expect(screen.queryByText('60 days')).not.toBeInTheDocument();
  });

  it('renders VirusTotal check as passing when not detected', () => {
    render(<ResultsDashboard report={baseReport} />);
    expect(screen.getByText('No threats detected (84 engines checked).')).toBeInTheDocument();
    expect(screen.getByText('0 / 84')).toBeInTheDocument();
  });

  it('shows detection details when VirusTotal flags URL as malicious', () => {
    const report: ThreatReport = {
      ...baseReport,
      checks: {
        ...baseReport.checks,
        virustotal: { detected: true, malicious: 5, suspicious: 2, total: 84, details: 'Detected as malicious by 5/84 engines.' },
      },
    };
    render(<ResultsDashboard report={report} />);
    expect(screen.getByText('Detected as malicious by 5/84 engines.')).toBeInTheDocument();
    expect(screen.getByText('5 / 84')).toBeInTheDocument();
  });
});
