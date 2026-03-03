import type { ThreatReport } from '../types/threat';

const BASE_URL = import.meta.env.VITE_API_URL ?? '/api';

export async function fetchReport(id: number): Promise<ThreatReport | null> {
  try {
    const response = await fetch(`${BASE_URL}/report/${id}`);
    if (!response.ok) return null;
    return response.json() as Promise<ThreatReport>;
  } catch {
    return null;
  }
}
