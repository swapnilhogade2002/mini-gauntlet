import { useCallback, useEffect, useState } from "react";
import { listScans, startScan } from "./api";
import { formatDuration, formatScore, formatStart } from "./format";
import type { ScanSummary } from "./types";
import { usePolling } from "./usePolling";

export function ScansPage() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const load = useCallback(async () => {
    try {
      setScans(await listScans());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);
  usePolling(() => void load(), !!scans?.some((s) => s.status === "RUNNING"));

  async function onRun() {
    setStarting(true);
    try {
      await startScan();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setStarting(false);
    }
  }

  return (
    <section>
      <div className="page-head">
        <h1>Scans</h1>
        <button className="primary" onClick={() => void onRun()} disabled={starting}>
          {starting ? "Starting…" : "Run scan"}
        </button>
      </div>
      {error && (
        <div role="alert" className="notice error">
          {error}{" "}
          <button onClick={() => void load()}>Retry</button>
        </div>
      )}
      {!scans && !error && <p className="muted">Loading scans…</p>}
      {scans && scans.length === 0 && !error && (
        <p className="empty">No scans yet. Run a scan to check every account in the snapshot.</p>
      )}
      {scans && scans.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Scan</th>
              <th>Status</th>
              <th>Started</th>
              <th className="num">Duration</th>
              <th className="num">Score</th>
              <th className="num">Fail</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td>
                  <a href={`#/scans/${s.id}`}>{s.id.slice(0, 8)}</a>
                </td>
                <td>
                  <span className={`badge ${s.status}`}>{s.status}</span>
                </td>
                <td>{formatStart(s.started_at)}</td>
                <td className="num">{formatDuration(s.started_at, s.finished_at)}</td>
                <td className="num">{formatScore(s.score)}</td>
                <td className="num">{s.counts.FAIL}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
