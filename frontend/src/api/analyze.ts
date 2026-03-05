import type { ThreatReport } from '../types/threat';

const BASE_URL = import.meta.env.VITE_API_URL ?? '/api';

function isThreatReport(data: unknown): data is ThreatReport {
  if (typeof data !== 'object' || data === null) return false;
  const obj = data as Record<string, unknown>;
  return (
    typeof obj.target_url === 'string' &&
    typeof obj.threat_score === 'number' &&
    typeof obj.assessment === 'string' &&
    typeof obj.checks === 'object' &&
    obj.checks !== null
  );
}

export async function analyzeUrl(url: string): Promise<ThreatReport> {
  const response = await fetch(`${BASE_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(30_000),
  });

  if (!response.ok) {
    if (response.status === 429) {
      throw new Error('Rate limit reached — please wait a moment before trying again.');
    }
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail ?? `Server returned ${response.status}`);
  }

  const data: unknown = await response.json();
  if (!isThreatReport(data)) {
    throw new Error('Unexpected response format from server.');
  }
  return data;
}
