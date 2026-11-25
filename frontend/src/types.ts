export type Status = "PASS" | "FAIL" | "CANNOT_SCAN";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type ScanStatus = "RUNNING" | "COMPLETED" | "FAILED";
export type Counts = Record<Status, number>;

export interface ScanSummary {
  id: string;
  status: ScanStatus;
  started_at: string;
  finished_at: string | null;
  account_ids: string[];
  error: string | null;
  counts: Counts;
  score: number | null;
}

export interface AccountScore {
  account_id: string;
  name: string;
  provider: string;
  counts: Counts;
  score: number | null;
}

export interface ScanDetail extends ScanSummary {
  fail_by_severity: Record<Severity, number>;
  accounts: AccountScore[];
}

export interface Finding {
  id: number;
  scan_id: string;
  check_id: string;
  title: string;
  provider: string;
  account_id: string;
  region: string | null;
  resource_id: string | null;
  status: Status;
  severity: Severity;
  details: string;
}

export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingFilters {
  status: string;
  severity: string;
  provider: string;
  account_id: string;
}
