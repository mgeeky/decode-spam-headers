import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import ProgressIndicator from "../components/ProgressIndicator";
import type { AnalysisProgress } from "../types/analysis";

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

const baseProgress: AnalysisProgress = {
  currentIndex: 1,
  totalTests: 4,
  currentTest: "SpamAssassin Rule Hits",
  elapsedMs: 12000,
  percentage: 50,
};

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
});

describe("ProgressIndicator", () => {
  it("renders progress details while analysing", () => {
    const { container } = render(
      <ProgressIndicator status="analysing" progress={baseProgress} timeoutSeconds={30} />,
    );

    const indicator = getByTestId(container, "progress-indicator");
    expect(indicator.getAttribute("data-status")).toBe("analysing");
    expect(indicator.getAttribute("data-variant")).toBe("normal");

    expect(getByTestId(container, "progress-percentage").textContent ?? "").toMatch(/50%/);
    expect(getByTestId(container, "progress-current-test").textContent ?? "").toMatch(
      /SpamAssassin Rule Hits/,
    );
    expect(getByTestId(container, "progress-elapsed").textContent ?? "").toMatch(/12s/);
    expect(getByTestId(container, "progress-remaining").textContent ?? "").toMatch(/18s/);
    expect(getByTestId(container, "progress-spinner")).toBeTruthy();

    const progressbar = container.querySelector('[role="progressbar"]');
    expect(progressbar?.getAttribute("aria-valuenow")).toBe("50");
    expect(progressbar?.getAttribute("aria-valuemax")).toBe("100");
  });

  it("uses warning styling when near timeout", () => {
    const nearTimeout: AnalysisProgress = {
      ...baseProgress,
      elapsedMs: 28000,
      percentage: 93,
    };

    const { container } = render(
      <ProgressIndicator status="analysing" progress={nearTimeout} timeoutSeconds={30} />,
    );

    const indicator = getByTestId(container, "progress-indicator");
    expect(indicator.getAttribute("data-variant")).toBe("warning");
    expect(getByTestId(container, "progress-remaining").textContent ?? "").toMatch(/2s/);
  });

  it("shows a timeout notification with incomplete tests", () => {
    const { container } = render(
      <ProgressIndicator
        status="timeout"
        progress={baseProgress}
        timeoutSeconds={30}
        incompleteTests={["Mimecast Fingerprint", "Proofpoint TAP"]}
      />,
    );

    const indicator = getByTestId(container, "progress-indicator");
    expect(indicator.getAttribute("data-status")).toBe("timeout");
    expect(indicator.getAttribute("data-variant")).toBe("timeout");

    const alert = container.querySelector('[role="alert"]');
    expect(alert).not.toBeNull();
    expect(alert?.textContent ?? "").toMatch(/timeout/i);
    expect(getByTestId(container, "timeout-tests").textContent ?? "").toMatch(
      /Mimecast Fingerprint/,
    );
    expect(getByTestId(container, "timeout-tests").textContent ?? "").toMatch(/Proofpoint TAP/);
  });
});
