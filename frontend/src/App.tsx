import { useEffect, useState } from 'react';
import type { ThreatReport, HistoryEntry } from './types/threat';
import { analyzeUrl } from './api/analyze';
import { fetchHistory } from './api/history';
import { fetchReport } from './api/report';
import UrlForm from './components/UrlForm';
import ResultsDashboard from './components/ResultsDashboard';
import HistoryPanel from './components/HistoryPanel';
import TrendingFeed from './components/TrendingFeed';
import { fetchTrending } from './api/trending';

export default function App() {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [reportId, setReportId] = useState<number | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [trending, setTrending] = useState<HistoryEntry[]>([]);
  const [trendingLoading, setTrendingLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    fetchHistory()
      .then((entries) => { if (!cancelled) { setHistory(entries); setHistoryLoading(false); } })
      .catch(() => { if (!cancelled) setHistoryLoading(false); });

    fetchTrending()
      .then((e) => { if (!cancelled) { setTrending(e); setTrendingLoading(false); } })
      .catch(() => { if (!cancelled) setTrendingLoading(false); });

    // Load a shared report if ?id= is present in the URL
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    if (id) {
      const numId = parseInt(id, 10);
      if (!isNaN(numId)) {
        fetchReport(numId).then((r) => {
          if (!cancelled && r) {
            setReport(r);
            setReportId(numId);
          }
        });
      }
    }

    return () => { cancelled = true; };
  }, []);

  async function handleSubmit(url: string) {
    setLoading(true);
    setError(null);
    setReport(null);
    setReportId(undefined);
    // Clear ?id= from address bar without reloading
    window.history.replaceState({}, '', window.location.pathname);
    try {
      const result = await analyzeUrl(url);
      setReport(result);
      const entries = await fetchHistory();
      setHistory(entries);
      setHistoryLoading(false);
      // Refresh trending feed after a new scan
      fetchTrending().then((e) => { setTrending(e); setTrendingLoading(false); }).catch(() => {});
      // Pick up the id of the scan we just saved (it will be the newest entry)
      if (entries.length > 0 && entries[0].url === result.target_url) {
        setReportId(entries[0].id);
      }
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

      {report && <ResultsDashboard report={report} reportId={reportId} />}

      <HistoryPanel
        entries={history}
        loading={historyLoading}
        onSelect={handleSubmit}
      />

      <TrendingFeed
        entries={trending}
        loading={trendingLoading}
        onSelect={handleSubmit}
      />

      <footer className="mt-20 text-xs text-gray-700">
        Threat-IntelD &mdash; powered by Google Safe Browsing, VirusTotal, WHOIS &amp; SSL checks
      </footer>
    </div>
  );
}
