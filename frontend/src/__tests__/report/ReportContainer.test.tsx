import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import ReportContainer from "../../components/report/ReportContainer";
import type { AnalysisReport } from "../../types/analysis";

type RenderResult = {
  container: HTMLDivElement;
};

const cleanups: Array<() => void> = [];

const render = (ui: ReactElement): RenderResult => {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);

  act(() => {
    root.render(ui);
  });

  cleanups.push(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
  });

  return { container };
};

const getByTestId = (container: HTMLElement, testId: string): HTMLElement => {
  const element = container.querySelector(`[data-testid="${testId}"]`);
  if (!element) {
    throw new Error(`Expected element ${testId} to be rendered.`);
  }
  return element as HTMLElement;
};

const report: AnalysisReport = {
  results: [
    {
      testId: 101,
      testName: "SpamAssassin Rule Hits",
      headerName: "X-Spam-Flag",
      headerValue: "YES",
      analysis: "Flagged by local rules.",
      description: "SpamAssassin rules matched.",
      severity: "spam",
      status: "error",
      error: "Timeout",
    },
    {
      testId: 202,
      testName: "Mimecast Fingerprint",
      headerName: "X-Mimecast-Spam-Info",
      headerValue: "none",
      analysis: "No fingerprint detected.",
      description: "No known fingerprint found.",
      severity: "clean",
      status: "success",
      error: null,
    },
    {
      testId: 303,
      testName: "Barracuda Reputation",
      headerName: "X-Barracuda",
      headerValue: "neutral",
      analysis: "Reputation check pending.",
      description: "Awaiting response.",
      severity: "suspicious",
      status: "success",
      error: null,
    },
    {
      testId: 404,
      testName: "Custom Header Check",
      headerName: "X-Custom",
      headerValue: "ok",
      analysis: "Custom info.",
      description: "Informational.",
      severity: "info",
      status: "success",
      error: null,
    },
  ],
  hopChain: [
    {
      index: 0,
      hostname: "mail.sender.example",
      ip: "192.0.2.10",
      timestamp: "2026-02-17 10:00:01",
      serverInfo: "Postfix",
    },
    {
      index: 1,
      hostname: "mx.receiver.example",
      ip: "203.0.113.5",
      timestamp: "2026-02-17 10:00:04",
      serverInfo: "Exchange 2019",
    },
  ],
  securityAppliances: [
    {
      name: "Mimecast Email Security",
      vendor: "Mimecast",
      headers: ["X-Mimecast-Spam-Info"],
    },
  ],
  metadata: {
    totalTests: 4,
    passedTests: 3,
    failedTests: 1,
    skippedTests: 0,
    elapsedMs: 4200,
    timedOut: false,
    incompleteTests: [],
  },
};

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
});

describe("ReportContainer", () => {
  it("renders the full report with summary stats and sections", () => {
    const { container } = render(<ReportContainer report={report} />);

    getByTestId(container, "report-container");

    const total = getByTestId(container, "report-summary-total");
    const passed = getByTestId(container, "report-summary-passed");
    const failed = getByTestId(container, "report-summary-failed");
    const spam = getByTestId(container, "report-summary-severity-spam");
    const suspicious = getByTestId(container, "report-summary-severity-suspicious");
    const clean = getByTestId(container, "report-summary-severity-clean");
    const info = getByTestId(container, "report-summary-severity-info");

    expect(total.textContent ?? "").toContain("4");
    expect(passed.textContent ?? "").toContain("3");
    expect(failed.textContent ?? "").toContain("1");
    expect(spam.textContent ?? "").toContain("1");
    expect(suspicious.textContent ?? "").toContain("1");
    expect(clean.textContent ?? "").toContain("1");
    expect(info.textContent ?? "").toContain("1");

    getByTestId(container, "report-search-bar");
    getByTestId(container, "report-export");
    getByTestId(container, "security-appliances-summary");
    getByTestId(container, "hop-chain-visualisation");

    report.results.forEach((result) => {
      getByTestId(container, `test-result-card-${result.testId}`);
    });
  });
});
