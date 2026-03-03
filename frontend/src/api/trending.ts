import type { HistoryEntry } from '../types/threat';

const API_BASE = import.meta.env.VITE_API_URL ?? '/api';

export async function fetchTrending(): Promise<HistoryEntry[]> {
  const res = await fetch(`${API_BASE}/trending`);
  if (!res.ok) return [];
  return res.json();
}
