import type { ThreatReport } from '../types/threat';
import AssessmentBadge from './AssessmentBadge';
import ThreatScoreDonut from './ThreatScoreDonut';
import CheckCard from './CheckCard';

interface Props {
  report: ThreatReport;
}

export default function ResultsDashboard({ report }: Props) {
  const { target_url, timestamp, threat_score, assessment, checks } = report;

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
        </div>
      </div>

      {/* Check breakdowns */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <CheckCard
          title="Google Safe Browsing"
          icon="🛡️"
          passed={!checks.safe_browsing.flagged}
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
          ]}
        />
      </div>
    </div>
  );
}
