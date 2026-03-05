import type { HistoryEntry } from '../types/threat';

const API_BASE = import.meta.env.VITE_API_URL ?? '/api';

export async function fetchTrending(): Promise<HistoryEntry[]> {
  try {
    const res = await fetch(`${API_BASE}/trending`);
    if (!res.ok) return [];
    return res.json();
  } catch (err) {
    console.warn('Failed to fetch trending feed:', err);
    return [];
  }
}
