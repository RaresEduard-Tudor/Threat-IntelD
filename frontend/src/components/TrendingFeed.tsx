import type { HistoryEntry } from '../types/threat';

interface Props {
  entries: HistoryEntry[];
  loading: boolean;
  onSelect: (url: string) => void;
}

const assessmentColors: Record<string, string> = {
  Malicious: 'text-red-400 border-red-800 bg-red-950/30',
  Suspicious: 'text-yellow-400 border-yellow-800 bg-yellow-950/30',
};

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function TrendingFeed({ entries, loading, onSelect }: Props) {
  return (
    <div className="w-full max-w-3xl mx-auto mt-10">
      <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-widest mb-3">
        🔥 Threat Feed
      </h2>

      {loading && (
        <div className="text-xs text-gray-600 py-4 text-center">Loading…</div>
      )}

      {!loading && entries.length === 0 && (
        <div className="text-xs text-gray-600 py-4 text-center">
          No malicious or suspicious scans yet.
        </div>
      )}

      {!loading && entries.length > 0 && (
        <ul className="flex flex-col gap-2">
          {entries.map((e) => {
            const colors = assessmentColors[e.assessment] ?? 'text-gray-400 border-gray-700 bg-gray-900';
            return (
              <li key={e.id}>
                <button
                  onClick={() => onSelect(e.url)}
                  className={`w-full text-left rounded-xl border px-4 py-3 flex items-center gap-4 transition-opacity hover:opacity-80 ${colors}`}
                >
                  <span className="text-xs font-bold uppercase tracking-widest w-20 shrink-0">
                    {e.assessment}
                  </span>
                  <span className="text-xs font-mono text-gray-300 truncate flex-1">
                    {e.url}
                  </span>
                  <span className="text-xs font-semibold shrink-0">{e.threat_score}</span>
                  <span className="text-xs text-gray-600 shrink-0 w-14 text-right">
                    {timeAgo(e.timestamp)}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
