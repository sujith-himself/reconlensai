import type { AnalysisRecord } from "@/components/reconlens/types";

const KEY = "reconlens_history";
const MAX = 50;

export function getHistory(): AnalysisRecord[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as AnalysisRecord[]) : [];
  } catch {
    return [];
  }
}

export function saveToHistory(record: Omit<AnalysisRecord, "id">): AnalysisRecord {
  const history = getHistory();
  const entry: AnalysisRecord = { ...record, id: `scan_${Date.now()}` };
  const updated = [entry, ...history].slice(0, MAX);
  try {
    localStorage.setItem(KEY, JSON.stringify(updated));
  } catch {
    // localStorage full or unavailable — fail silently
  }
  return entry;
}

export function clearHistory(): void {
  localStorage.removeItem(KEY);
}
