export const formatScore = (score: number | null): string => (score === null ? "N/A" : score.toFixed(1));

export function formatStart(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString(); // viewer's time zone
}

export function formatDuration(start: string, end: string | null): string {
  if (!end) return "…";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (Number.isNaN(ms)) return "–";
  return ms < 60_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`;
}
