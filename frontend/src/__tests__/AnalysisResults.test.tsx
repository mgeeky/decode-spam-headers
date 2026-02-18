import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import AnalysisResults from "../components/AnalysisResults";
import type { AnalysisReport } from "../types/analysis";

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

const queryByTestId = (container: HTMLElement, testId: string): HTMLElement | null =>
  container.querySelector(`[data-testid="${testId}"]`);

const report: AnalysisReport = {
  results: [
    {
      testId: 101,
      testName: "SpamAssassin Rule Hits",
      headerName: "X-Spam-Flag",
      headerValue: "YES",
      analysis: "Flagged by local rules.",
      description: "SpamAssassin rules matched during analysis.",
      severity: "spam",
      status: "error",
      error: "SpamAssassin database timeout.",
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
  ],
  hopChain: [],
  securityAppliances: [],
  metadata: {
    totalTests: 2,
    passedTests: 1,
    failedTests: 1,
    skippedTests: 0,
    elapsedMs: 2200,
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

describe("AnalysisResults", () => {
  it("shows inline error indicators for failed tests", () => {
    const { container } = render(<AnalysisResults report={report} />);

    const errorIndicator = getByTestId(container, "analysis-error-101");
    expect(errorIndicator.textContent ?? "").toMatch(/SpamAssassin database timeout/);
  });

  it("does not render error indicators for successful tests", () => {
    const { container } = render(<AnalysisResults report={report} />);

    expect(queryByTestId(container, "analysis-error-202")).toBeNull();
  });
});
