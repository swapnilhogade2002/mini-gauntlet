import type { FindingFilters, FindingsPage, ScanDetail, ScanSummary } from "./types";

export class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError("Can't reach the API. Check that the backend is running, then try again.");
  }
  if (!response.ok) {
    let detail = "";
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? `: ${body.detail}` : "";
    } catch {
      /* body was not JSON */
    }
    throw new ApiError(`The API returned ${response.status}${detail}`);
  }
  return (await response.json()) as T;
}

export const listScans = () => request<ScanSummary[]>("/api/scans");
export const getScan = (id: string) => request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`);
export const startScan = () => request<ScanSummary>("/api/scans", { method: "POST" });

export function listFindings(id: string, filters: FindingFilters, page: number, pageSize = 25) {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
  return request<FindingsPage>(`/api/scans/${encodeURIComponent(id)}/findings?${params}`);
}
