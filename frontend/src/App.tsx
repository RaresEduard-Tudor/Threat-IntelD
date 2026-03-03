import { useEffect, useState } from 'react';
import type { ThreatReport, HistoryEntry } from './types/threat';
import { analyzeUrl } from './api/analyze';
import { fetchHistory } from './api/history';
import UrlForm from './components/UrlForm';
import ResultsDashboard from './components/ResultsDashboard';
import HistoryPanel from './components/HistoryPanel';

export default function App() {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);

  async function loadHistory() {
    const entries = await fetchHistory();
    setHistory(entries);
    setHistoryLoading(false);
  }

  useEffect(() => { loadHistory(); }, []);

  async function handleSubmit(url: string) {
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const result = await analyzeUrl(url);
      setReport(result);
      await loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col items-center px-4 py-16">
      {/* Logo / Hero */}
      <div className="mb-10 text-center">
        <div className="flex justify-center mb-4">
          <span className="text-5xl">🔍</span>
        </div>
        <h1 className="text-3xl font-black text-white tracking-tight">
          Threat<span className="text-blue-500">IntelD</span>
        </h1>
        <p className="mt-2 text-gray-400 text-sm max-w-md">
          Paste any URL to instantly check it for malware, phishing, suspicious domain age, and SSL issues.
        </p>
      </div>

      <UrlForm onSubmit={handleSubmit} loading={loading} />

      {loading && (
        <div className="mt-12 flex flex-col items-center gap-3 text-gray-400">
          <div className="w-10 h-10 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm">Running security checks…</p>
        </div>
      )}

      {error && (
        <div className="mt-8 w-full max-w-2xl rounded-xl border border-red-800 bg-red-950/40 p-4 text-red-400 text-sm">
          <strong>Error: </strong>{error}
        </div>
      )}

      {report && <ResultsDashboard report={report} />}

      <HistoryPanel
        entries={history}
        loading={historyLoading}
        onSelect={handleSubmit}
      />

      <footer className="mt-20 text-xs text-gray-700">
        Threat-IntelD &mdash; powered by Google Safe Browsing, VirusTotal, WHOIS &amp; SSL checks
      </footer>
    </div>
  );
}

    </div>
  );
}
