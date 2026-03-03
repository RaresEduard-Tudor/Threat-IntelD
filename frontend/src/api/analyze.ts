import type { ThreatReport } from '../types/threat';

const BASE_URL = import.meta.env.VITE_API_URL ?? '/api';

export async function analyzeUrl(url: string): Promise<ThreatReport> {
  const response = await fetch(`${BASE_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    if (response.status === 429) {
      throw new Error('Rate limit reached — please wait a moment before trying again.');
    }
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail ?? `Server returned ${response.status}`);
  }

  return response.json() as Promise<ThreatReport>;
}
