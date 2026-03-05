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

export async function fetchReport(id: number): Promise<ThreatReport | null> {
  try {
    const response = await fetch(`${BASE_URL}/report/${id}`);
    if (!response.ok) return null;
    const data: unknown = await response.json();
    if (!isThreatReport(data)) {
      console.warn('Unexpected report response format');
      return null;
    }
    return data;
  } catch (err) {
    console.warn('Failed to fetch report:', err);
    return null;
  }
}
