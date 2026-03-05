import { describe, it, expect } from 'vitest';
import type { ThreatReport } from '../types/threat';

// We need to test the buildHtml output for XSS. Since buildHtml is private,
// we test through exportHtml by intercepting the Blob it creates.
// Alternatively, we import the module and test the escaping behavior.

// Re-implement the escapeHtml function to verify the module's output matches
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '"><img src=x onerror=alert(1)>',
  "javascript:alert('xss')",
  '<svg onload=alert(1)>',
  "'; DROP TABLE users; --",
];

function makeReport(overrides: Partial<ThreatReport> = {}): ThreatReport {
  return {
    target_url: 'https://example.com/',
    timestamp: '2026-03-03T10:00:00Z',
    threat_score: 0,
    assessment: 'Safe',
    checks: {
      safe_browsing: { flagged: false, threat_type: null, details: 'Clean.' },
      domain_age: { days_registered: 365, risk_level: 'Low', details: 'Established.' },
      ssl_certificate: { valid: true, issuer: "Let's Encrypt", expires_in_days: 60, details: 'Valid.' },
      virustotal: { detected: false, malicious: 0, suspicious: 0, total: 84, details: 'Clean.' },
      ip_reputation: { ip: '93.184.216.34', abuse_confidence_score: 0, is_flagged: false, country_code: 'US', total_reports: 0, details: 'Clean.' },
      url_heuristics: { is_suspicious: false, flag_count: 0, flags: [], risk_score: 0, details: 'No patterns.' },
      dnsbl: { flagged: false, listed_in: [], details: 'Not listed.' },
      openphish: { flagged: false, details: 'Not found.' },
    },
    ...overrides,
  };
}

// To test the actual HTML export, we capture the Blob created by exportHtml
const originalCreateObjectURL = URL.createObjectURL;
const originalRevokeObjectURL = URL.revokeObjectURL;
const originalCreateElement = document.createElement.bind(document);

beforeEach(() => {
  URL.createObjectURL = () => 'blob:mock';
  URL.revokeObjectURL = () => {};

  // Intercept link element click to capture the download without actually triggering it
  document.createElement = ((tag: string) => {
    const el = originalCreateElement(tag);
    if (tag === 'a') {
      el.click = () => {}; // no-op
    }
    return el;
  }) as typeof document.createElement;
});

afterEach(() => {
  URL.createObjectURL = originalCreateObjectURL;
  URL.revokeObjectURL = originalRevokeObjectURL;
  document.createElement = originalCreateElement;
});

// Dynamic import so our mocks are in place
const { exportHtml } = await import('./exportReport');

describe('exportHtml XSS prevention', () => {
  it.each(XSS_PAYLOADS)('escapes XSS payload in target_url: %s', async (payload) => {
    // Intercept the Blob
    let blobContent = '';
    URL.createObjectURL = (blob: Blob) => {
      blob.text().then((t) => { blobContent = t; });
      return 'blob:mock';
    };

    const report = makeReport({ target_url: payload });
    exportHtml(report);

    // Wait for async blob.text()
    await new Promise((r) => setTimeout(r, 10));

    // The raw payload should NOT appear in the HTML — it should be escaped
    expect(blobContent).not.toContain(payload);
    expect(blobContent).toContain(escapeHtml(payload));
  });

  it('escapes XSS in check details field', async () => {
    const xssDetails = '<img src=x onerror=alert("pwned")>';
    let blobContent = '';
    URL.createObjectURL = (blob: Blob) => {
      blob.text().then((t) => { blobContent = t; });
      return 'blob:mock';
    };

    const report = makeReport({
      checks: {
        ...makeReport().checks,
        safe_browsing: { flagged: true, threat_type: 'MALWARE', details: xssDetails },
      },
    });
    exportHtml(report);

    await new Promise((r) => setTimeout(r, 10));

    expect(blobContent).not.toContain(xssDetails);
    expect(blobContent).toContain(escapeHtml(xssDetails));
  });

  it('escapes XSS in heuristic flags', async () => {
    const xssFlag = '<script>document.cookie</script>';
    let blobContent = '';
    URL.createObjectURL = (blob: Blob) => {
      blob.text().then((t) => { blobContent = t; });
      return 'blob:mock';
    };

    const report = makeReport({
      checks: {
        ...makeReport().checks,
        url_heuristics: {
          is_suspicious: true,
          flag_count: 1,
          flags: [xssFlag],
          risk_score: 10,
          details: 'Suspicious patterns.',
        },
      },
    });
    exportHtml(report);

    await new Promise((r) => setTimeout(r, 10));

    expect(blobContent).not.toContain(xssFlag);
    expect(blobContent).toContain(escapeHtml(xssFlag));
  });

  it('escapes XSS in assessment field', async () => {
    const xssAssessment = '<script>alert(1)</script>' as any;
    let blobContent = '';
    URL.createObjectURL = (blob: Blob) => {
      blob.text().then((t) => { blobContent = t; });
      return 'blob:mock';
    };

    const report = makeReport({ assessment: xssAssessment });
    exportHtml(report);

    await new Promise((r) => setTimeout(r, 10));

    expect(blobContent).not.toContain('<script>alert(1)</script>');
    expect(blobContent).toContain(escapeHtml(xssAssessment));
  });
});
