import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import TestResultCard from "../../components/report/TestResultCard";
import type { TestResult, TestSeverity } from "../../types/analysis";

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

const buildResult = (overrides: Partial<TestResult>): TestResult => ({
  testId: 101,
  testName: "SpamAssassin Rule Hits",
  headerName: "X-Spam-Flag",
  headerValue: "YES",
  analysis: "Flagged by local rules.",
  description: "SpamAssassin rules matched during analysis.",
  severity: "spam",
  status: "success",
  error: null,
  ...overrides,
});

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
});

describe("TestResultCard", () => {
  it("renders severity labels with mapped styles", () => {
    const severityCases: Array<{
      severity: TestSeverity;
      label: string;
      className: string;
    }> = [
      { severity: "spam", label: "Spam", className: "text-spam" },
      { severity: "suspicious", label: "Suspicious", className: "text-suspicious" },
      { severity: "clean", label: "Clean", className: "text-clean" },
      { severity: "info", label: "Info", className: "text-accent" },
    ];

    severityCases.forEach((severityCase, index) => {
      const result = buildResult({
        testId: 200 + index,
        testName: `Severity ${severityCase.label}`,
        severity: severityCase.severity,
      });

      const { container } = render(<TestResultCard result={result} />);

      const severityBadge = getByTestId(container, `test-result-severity-${result.testId}`);

      expect(severityBadge.textContent ?? "").toContain(severityCase.label);
      expect(severityBadge.className).toContain(severityCase.className);
    });
  });

  it("expands and collapses on click and keyboard", () => {
    const result = buildResult({ testId: 311, testName: "Header Anomaly" });
    const { container } = render(<TestResultCard result={result} />);

    const toggle = getByTestId(container, `test-result-toggle-${result.testId}`);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");

    act(() => {
      toggle.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(toggle.getAttribute("aria-expanded")).toBe("true");

    act(() => {
      toggle.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });

    expect(toggle.getAttribute("aria-expanded")).toBe("false");

    act(() => {
      toggle.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    });

    expect(toggle.getAttribute("aria-expanded")).toBe("true");
  });

  it("shows error indicators for failed tests", () => {
    const result = buildResult({
      testId: 404,
      status: "error",
      error: "SpamAssassin database timeout.",
    });
    const { container } = render(<TestResultCard result={result} />);

    const errorIndicator = getByTestId(container, `test-result-error-${result.testId}`);
    expect(errorIndicator.textContent ?? "").toMatch(/SpamAssassin database timeout/);
  });
});
