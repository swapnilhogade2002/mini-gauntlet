import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";
import { ScanPage } from "./ScanPage";
import type { Finding, ScanDetail } from "./types";

vi.mock("./api");

const detail: ScanDetail = {
  id: "abcdef123456", status: "COMPLETED", started_at: "2026-10-01T00:00:00Z", finished_at: "2026-10-01T00:00:03Z",
  account_ids: ["g"], error: null, counts: { PASS: 1, FAIL: 1, CANNOT_SCAN: 0 }, score: 50,
  fail_by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0 },
  accounts: [{ account_id: "g", name: "gcp-prod", provider: "gcp", counts: { PASS: 1, FAIL: 1, CANNOT_SCAN: 0 }, score: 50 }],
};
const evil = "<img src=x onerror=alert('untrusted-input')> temporary rule";
const finding: Finding = {
  id: 1, scan_id: "abcdef123456", check_id: "GCP-VPC-01", title: "Firewall", provider: "gcp", account_id: "g",
  region: "global", resource_id: "allow-rdp-anywhere", status: "FAIL", severity: "CRITICAL", details: evil,
};

describe("ScanPage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.getScan).mockResolvedValue(detail);
    vi.mocked(api.listFindings).mockResolvedValue({ items: [finding], total: 30, page: 1, page_size: 25 });
  });

  it("renders untrusted snapshot strings as text, never as HTML", async () => {
    const { container } = render(<ScanPage scanId="abcdef123456" />);
    expect(await screen.findByText(evil)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows score, counts, per-account score and pagination", async () => {
    render(<ScanPage scanId="abcdef123456" />);
    expect(await screen.findByLabelText("Posture score")).toHaveTextContent("50.0");
    expect(screen.getAllByText("gcp-prod").length).toBeGreaterThan(0);
    expect(screen.getByText(/Page 1 of 2/)).toBeInTheDocument();
  });

  it("re-queries the API from page 1 when a filter changes", async () => {
    render(<ScanPage scanId="abcdef123456" />);
    await screen.findByText(evil);
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(api.listFindings).toHaveBeenLastCalledWith("abcdef123456", expect.anything(), 2));
    await userEvent.selectOptions(screen.getByLabelText("Status"), "FAIL");
    await waitFor(() =>
      expect(api.listFindings).toHaveBeenLastCalledWith("abcdef123456", expect.objectContaining({ status: "FAIL" }), 1),
    );
  });

  it("shows an error state when the scan can't be loaded", async () => {
    vi.mocked(api.getScan).mockRejectedValue(new Error("The API returned 404: scan not found"));
    render(<ScanPage scanId="nope" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("scan not found");
  });
});
