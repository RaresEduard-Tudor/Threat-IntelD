import type { HistoryEntry, Assessment } from '../types/threat';

interface Props {
  entries: HistoryEntry[];
  loading: boolean;
  onSelect: (url: string) => void;
}

const dotColor: Record<Assessment, string> = {
  Safe: 'bg-green-500',
  Suspicious: 'bg-yellow-400',
  Malicious: 'bg-red-500',
};

const scoreColor: Record<Assessment, string> = {
  Safe: 'text-green-400',
  Suspicious: 'text-yellow-400',
  Malicious: 'text-red-400',
};

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function HistoryPanel({ entries, loading, onSelect }: Props) {
  if (loading) {
    return (
      <div className="w-full max-w-3xl mx-auto mt-10">
        <div className="rounded-2xl border border-gray-800 bg-gray-900 p-5 text-sm text-gray-600 text-center">
          Loading history…
        </div>
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <div className="w-full max-w-3xl mx-auto mt-10">
        <div className="rounded-2xl border border-gray-800 bg-gray-900 p-5 text-sm text-gray-600 text-center">
          No scans yet — analyse a URL to get started.
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-3xl mx-auto mt-10">
      <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
        Recent Scans
      </h2>
      <div className="rounded-2xl border border-gray-800 bg-gray-900 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-500 text-xs uppercase tracking-wider">
              <th className="px-4 py-3 text-left font-medium">URL</th>
              <th className="px-4 py-3 text-center font-medium w-20">Score</th>
              <th className="px-4 py-3 text-center font-medium w-28">Assessment</th>
              <th className="px-4 py-3 text-right font-medium w-24">When</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, i) => (
              <tr
                key={entry.id}
                className={`border-b border-gray-800/50 last:border-0 hover:bg-gray-800/40 cursor-pointer transition-colors ${i % 2 === 0 ? '' : 'bg-gray-900/60'}`}
                onClick={() => onSelect(entry.url)}
                title={`Re-analyse ${entry.url}`}
              >
                <td className="px-4 py-3 text-gray-300 max-w-xs">
                  <span className="block truncate" title={entry.url}>
                    {entry.url.replace(/^https?:\/\//, '')}
                  </span>
                </td>
                <td className="px-4 py-3 text-center font-bold">
                  <span className={scoreColor[entry.assessment]}>{entry.threat_score}</span>
                </td>
                <td className="px-4 py-3 text-center">
                  <span className="inline-flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${dotColor[entry.assessment]}`} />
                    <span className={`font-medium ${scoreColor[entry.assessment]}`}>{entry.assessment}</span>
                  </span>
                </td>
                <td className="px-4 py-3 text-right text-gray-600 text-xs">{timeAgo(entry.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
