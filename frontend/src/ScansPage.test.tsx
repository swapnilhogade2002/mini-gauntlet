import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";
import { ScansPage } from "./ScansPage";
import type { ScanSummary } from "./types";

vi.mock("./api");

const scan = (over: Partial<ScanSummary>): ScanSummary => ({
  id: "abcdef123456", status: "COMPLETED", started_at: "2026-10-01T00:00:00Z", finished_at: "2026-10-01T00:00:03Z",
  account_ids: ["a"], error: null, counts: { PASS: 27, FAIL: 18, CANNOT_SCAN: 4 }, score: 60, ...over,
});

describe("ScansPage", () => {
  beforeEach(() => vi.resetAllMocks());

  it("lists scans with score, duration and N/A when nothing was scored", async () => {
    vi.mocked(api.listScans).mockResolvedValue([scan({}), scan({ id: "zzzzzzzz9999", score: null })]);
    render(<ScansPage />);
    expect(await screen.findByText("60.0")).toBeInTheDocument();
    expect(screen.getByText("N/A")).toBeInTheDocument();
    expect(screen.getAllByText("3.0 s")).toHaveLength(2);
  });

  it("shows an empty state", async () => {
    vi.mocked(api.listScans).mockResolvedValue([]);
    render(<ScansPage />);
    expect(await screen.findByText(/No scans yet/)).toBeInTheDocument();
  });

  it("shows an error state with retry when the API is down", async () => {
    vi.mocked(api.listScans).mockRejectedValue(new Error("Can't reach the API."));
    render(<ScansPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Can't reach the API.");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("starts a scan when Run scan is clicked", async () => {
    vi.mocked(api.listScans).mockResolvedValue([]);
    vi.mocked(api.startScan).mockResolvedValue(scan({ status: "RUNNING", finished_at: null }));
    render(<ScansPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Run scan" }));
    await waitFor(() => expect(api.startScan).toHaveBeenCalledTimes(1));
  });
});
