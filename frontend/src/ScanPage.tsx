import { useCallback, useEffect, useState } from "react";
import { getScan, listFindings } from "./api";
import { formatDuration, formatScore, formatStart } from "./format";
import type { FindingFilters, FindingsPage, ScanDetail, Severity } from "./types";
import { usePolling } from "./usePolling";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const NO_FILTERS: FindingFilters = { status: "", severity: "", provider: "", account_id: "" };

export function ScanPage({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [filters, setFilters] = useState<FindingFilters>(NO_FILTERS);
  const [page, setPage] = useState(1);
  const [findings, setFindings] = useState<FindingsPage | null>(null);
  const [findingsError, setFindingsError] = useState<string | null>(null);

  const loadScan = useCallback(async () => {
    try {
      setScan(await getScan(scanId));
      setScanError(null);
    } catch (e) {
      setScanError(e instanceof Error ? e.message : "Unknown error");
    }
  }, [scanId]);

  useEffect(() => {
    void loadScan();
  }, [loadScan]);
  usePolling(() => void loadScan(), scan?.status === "RUNNING");

  const status = scan?.status;
  useEffect(() => {
    if (status === undefined) return;
    let cancelled = false;
    listFindings(scanId, filters, page)
      .then((result) => {
        if (!cancelled) {
          setFindings(result);
          setFindingsError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) setFindingsError(e instanceof Error ? e.message : "Unknown error");
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, filters, page, status]);

  function setFilter(key: keyof FindingFilters, value: string) {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(1);
  }

  if (scanError && !scan) {
    return (
      <section>
        <a href="#/">← All scans</a>
        <div role="alert" className="notice error">
          {scanError} <button onClick={() => void loadScan()}>Retry</button>
        </div>
      </section>
    );
  }
  if (!scan) return <p className="muted">Loading scan…</p>;

  const pages = findings ? Math.max(1, Math.ceil(findings.total / findings.page_size)) : 1;

  return (
    <section>
      <a href="#/">← All scans</a>
      <div className="page-head">
        <h1>
          Scan {scan.id.slice(0, 8)} <span className={`badge ${scan.status}`}>{scan.status}</span>
        </h1>
        <span className="muted">
          Started {formatStart(scan.started_at)} · {formatDuration(scan.started_at, scan.finished_at)}
        </span>
      </div>
      {scan.status === "FAILED" && (
        <div role="alert" className="notice error">
          Scan failed: {scan.error ?? "unknown reason"}
        </div>
      )}

      <div className="summary">
        <div className="score" aria-label="Posture score">
          <span className="score-value">{formatScore(scan.score)}</span>
          <span className="muted">posture score</span>
        </div>
        <dl className="stats">
          <div><dt>Pass</dt><dd>{scan.counts.PASS}</dd></div>
          <div><dt>Fail</dt><dd>{scan.counts.FAIL}</dd></div>
          <div><dt>Cannot scan</dt><dd>{scan.counts.CANNOT_SCAN}</dd></div>
        </dl>
        <dl className="stats">
          {SEVERITIES.map((s) => (
            <div key={s}><dt>{s} fails</dt><dd>{scan.fail_by_severity[s]}</dd></div>
          ))}
        </dl>
      </div>

      <h2>Score by account</h2>
      <table>
        <thead>
          <tr><th>Account</th><th>Provider</th><th className="num">Score</th><th className="num">Pass</th><th className="num">Fail</th><th className="num">Cannot scan</th></tr>
        </thead>
        <tbody>
          {scan.accounts.map((a) => (
            <tr key={a.account_id}>
              <td>{a.name || a.account_id}<div className="muted small">{a.account_id}</div></td>
              <td>{a.provider}</td>
              <td className="num">{formatScore(a.score)}</td>
              <td className="num">{a.counts.PASS}</td>
              <td className="num">{a.counts.FAIL}</td>
              <td className="num">{a.counts.CANNOT_SCAN}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Findings</h2>
      <div className="filters">
        <label>Status
          <select value={filters.status} onChange={(e) => setFilter("status", e.target.value)}>
            <option value="">All</option><option>FAIL</option><option>CANNOT_SCAN</option><option>PASS</option>
          </select>
        </label>
        <label>Severity
          <select value={filters.severity} onChange={(e) => setFilter("severity", e.target.value)}>
            <option value="">All</option>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label>Provider
          <select value={filters.provider} onChange={(e) => setFilter("provider", e.target.value)}>
            <option value="">All</option><option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">Google Cloud</option>
          </select>
        </label>
        <label>Account
          <select value={filters.account_id} onChange={(e) => setFilter("account_id", e.target.value)}>
            <option value="">All</option>
            {scan.accounts.map((a) => <option key={a.account_id} value={a.account_id}>{a.name || a.account_id}</option>)}
          </select>
        </label>
      </div>

      {findingsError && (
        <div role="alert" className="notice error">{findingsError}</div>
      )}
      {!findings && !findingsError && <p className="muted">Loading findings…</p>}
      {findings && findings.items.length === 0 && (
        <p className="empty">
          {scan.status === "RUNNING" ? "The scan is still running. Findings appear when it finishes." : "No findings match these filters."}
        </p>
      )}
      {findings && findings.items.length > 0 && (
        <>
          <table className="findings">
            <thead>
              <tr><th>Status</th><th>Severity</th><th>Check</th><th>Resource</th><th>Account</th><th>Region</th><th>Details</th></tr>
            </thead>
            <tbody>
              {findings.items.map((f) => (
                <tr key={f.id}>
                  <td><span className={`badge ${f.status}`}>{f.status}</span></td>
                  <td><span className={`sev ${f.severity}`}>{f.severity}</span></td>
                  <td>{f.check_id}<div className="muted small">{f.title}</div></td>
                  <td>{f.resource_id ?? "–"}</td>
                  <td>{f.account_id}</td>
                  <td>{f.region ?? "–"}</td>
                  {/* Untrusted text: rendered as a plain React text node, never as HTML. */}
                  <td className="details">{f.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="pager">
            <button onClick={() => setPage((p) => p - 1)} disabled={page <= 1}>Previous</button>
            <span>Page {findings.page} of {pages} · {findings.total} findings</span>
            <button onClick={() => setPage((p) => p + 1)} disabled={page >= pages}>Next</button>
          </div>
        </>
      )}
    </section>
  );
}
