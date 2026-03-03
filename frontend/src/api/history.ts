import type { HistoryEntry } from '../types/threat';

const BASE_URL = import.meta.env.VITE_API_URL ?? '/api';

export async function fetchHistory(): Promise<HistoryEntry[]> {
  try {
    const response = await fetch(`${BASE_URL}/history`);
    if (!response.ok) return [];
    return response.json() as Promise<HistoryEntry[]>;
  } catch {
    return [];
  }
}
