import { useState } from 'react';
import type { ThreatReport } from '../types/threat';
import AssessmentBadge from './AssessmentBadge';
import ThreatScoreDonut from './ThreatScoreDonut';
import CheckCard from './CheckCard';
import { exportJson, exportHtml } from '../utils/exportReport';

interface Props {
  report: ThreatReport;
  reportId?: number;
}

export default function ResultsDashboard({ report, reportId }: Props) {
  const { target_url, timestamp, threat_score, assessment, checks } = report;
  const [copied, setCopied] = useState(false);

  function handleShare() {
    if (reportId == null) return;
    const url = new URL(window.location.href);
    url.search = '';
    url.searchParams.set('id', String(reportId));
    navigator.clipboard.writeText(url.toString()).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="w-full max-w-3xl mx-auto mt-10 flex flex-col gap-8 animate-fade-in">
      {/* Header summary */}
      <div className="rounded-2xl border border-gray-800 bg-gray-900 p-6 flex flex-col sm:flex-row items-center gap-6">
        <ThreatScoreDonut score={threat_score} assessment={assessment} />
        <div className="flex flex-col gap-3 flex-1">
          <AssessmentBadge assessment={assessment} />
          <p className="text-sm text-gray-400 break-all">
            <span className="text-gray-500">Target: </span>
            <a
              href={target_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:underline"
            >
              {target_url}
            </a>
          </p>
          <p className="text-xs text-gray-600">
            Analyzed at {new Date(timestamp).toLocaleString()}
          </p>
          {reportId != null && (
            <button
              onClick={handleShare}
              className="mt-1 self-start text-xs text-blue-500 hover:text-blue-400 transition-colors"
            >
              {copied ? '✅ Link copied!' : '🔗 Copy shareable link'}
            </button>
          )}
          <div className="flex gap-2 mt-1">
            <button
              onClick={() => exportJson(report)}
              className="text-xs text-gray-400 hover:text-gray-200 border border-gray-700 rounded px-2 py-1 transition-colors"
            >
              ⬇ JSON
            </button>
            <button
              onClick={() => exportHtml(report)}
              className="text-xs text-gray-400 hover:text-gray-200 border border-gray-700 rounded px-2 py-1 transition-colors"
            >
              🖨 HTML
            </button>
          </div>
        </div>
      </div>

      {/* Screenshot Preview */}
      {report.screenshot?.available && report.screenshot.image_b64 && (
        <div className="rounded-2xl border border-gray-800 bg-gray-900 p-4">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">
            Page Preview
          </p>
          <img
            src={`data:image/jpeg;base64,${report.screenshot.image_b64}`}
            alt="Page screenshot"
            className="w-full rounded-lg object-cover max-h-64"
          />
          <p className="mt-2 text-xs text-gray-600">{report.screenshot.details}</p>
        </div>
      )}

      {/* Check breakdowns */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <CheckCard
          title="Google Safe Browsing"
          icon="🛡️"
          passed={!checks.safe_browsing.flagged}
          skipped={checks.safe_browsing.details.includes('skipped')}
          details={checks.safe_browsing.details}
          meta={[
            { label: 'Flagged', value: checks.safe_browsing.flagged ? 'Yes' : 'No' },
            { label: 'Threat Type', value: checks.safe_browsing.threat_type ?? 'None' },
          ]}
        />
        <CheckCard
          title="Domain Age"
          icon="📅"
          passed={checks.domain_age.risk_level === 'Low'}
          details={checks.domain_age.details}
          meta={[
            {
              label: 'Days Registered',
              value: checks.domain_age.days_registered !== null
                ? `${checks.domain_age.days_registered} days`
                : 'Unknown',
            },
            { label: 'Risk Level', value: checks.domain_age.risk_level },
          ]}
        />
        <CheckCard
          title="SSL Certificate"
          icon="🔒"
          passed={checks.ssl_certificate.valid}
          details={checks.ssl_certificate.details}
          meta={[
            { label: 'Valid', value: checks.ssl_certificate.valid ? 'Yes' : 'No' },
            { label: 'Issuer', value: checks.ssl_certificate.issuer },
            {
              label: 'Expires In',
              value: checks.ssl_certificate.expires_in_days !== null
                ? `${checks.ssl_certificate.expires_in_days} days`
                : null,
            },
          ]}
        />
        <CheckCard
          title="VirusTotal"
          icon="🦠"
          passed={!checks.virustotal.detected}
          skipped={checks.virustotal.details.includes('skipped')}
          details={checks.virustotal.details}
          meta={[
            { label: 'Detected', value: checks.virustotal.detected ? 'Yes' : 'No' },
            {
              label: 'Engines (Malicious / Total)',
              value: checks.virustotal.total > 0
                ? `${checks.virustotal.malicious} / ${checks.virustotal.total}`
                : null,
            },
          ]}
        />
        <CheckCard
          title="IP Reputation"
          icon="🌐"
          passed={!checks.ip_reputation.is_flagged}
          skipped={checks.ip_reputation.details.includes('skipped')}
          details={checks.ip_reputation.details}
          meta={[
            { label: 'IP Address', value: checks.ip_reputation.ip },
            { label: 'Abuse Score', value: checks.ip_reputation.abuse_confidence_score !== null ? `${checks.ip_reputation.abuse_confidence_score}/100` : null },
            { label: 'Country', value: checks.ip_reputation.country_code },
          ]}
        />
        <CheckCard
          title="URL Heuristics"
          icon="🔍"
          passed={!checks.url_heuristics.is_suspicious}
          details={checks.url_heuristics.details}
          meta={[
            { label: 'Flags', value: checks.url_heuristics.flag_count > 0 ? checks.url_heuristics.flags.join(', ') : 'None' },
            { label: 'Risk Score', value: `${checks.url_heuristics.risk_score}/5` },
          ]}
        />
      </div>
    </div>
  );
}
