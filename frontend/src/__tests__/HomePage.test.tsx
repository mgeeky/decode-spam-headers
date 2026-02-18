import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import Home from "../app/page";
import type { AnalysisProgress, AnalysisReport } from "../types/analysis";

const { submitSpy, cancelSpy, useAnalysisState } = vi.hoisted(() => {
  const submitSpy = vi.fn().mockResolvedValue(undefined);
  const cancelSpy = vi.fn();

  return {
    submitSpy,
    cancelSpy,
    useAnalysisState: {
      status: "idle",
      progress: null,
      result: null,
      error: null,
      captchaChallenge: null,
      submit: submitSpy,
      cancel: cancelSpy,
      clearCaptchaChallenge: vi.fn(),
    },
  };
});

vi.mock("../hooks/useAnalysis", () => ({
  __esModule: true,
  default: () => useAnalysisState,
}));

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

const getTextarea = (container: HTMLElement): HTMLTextAreaElement => {
  const textarea = container.querySelector("textarea");
  if (!textarea) {
    throw new Error("Expected header textarea to be rendered.");
  }
  return textarea as HTMLTextAreaElement;
};

const getAnalyseButton = (container: HTMLElement): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll("button"));
  const button = buttons.find((candidate) =>
    (candidate.textContent ?? "").toLowerCase().includes("analyse"),
  );
  if (!button) {
    throw new Error("Expected analyse button to be rendered.");
  }
  return button as HTMLButtonElement;
};

const baseProgress: AnalysisProgress = {
  currentIndex: 2,
  totalTests: 4,
  currentTest: "SpamAssassin Rule Hits",
  elapsedMs: 29000,
  percentage: 78,
};

const resetUseAnalysisState = (): void => {
  useAnalysisState.status = "idle";
  useAnalysisState.progress = null;
  useAnalysisState.result = null;
  useAnalysisState.error = null;
  useAnalysisState.captchaChallenge = null;
};

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
  submitSpy.mockClear();
  cancelSpy.mockClear();
  resetUseAnalysisState();
});

describe("Home page", () => {
  it("submits analysis when analyse is clicked", () => {
    const { container } = render(<Home />);
    const textarea = getTextarea(container);

    act(() => {
      textarea.value = "Received: from mail.example.com";
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const button = getAnalyseButton(container);
    act(() => {
      button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(submitSpy).toHaveBeenCalledTimes(1);
    expect(submitSpy).toHaveBeenCalledWith({
      headers: "Received: from mail.example.com",
      config: { testIds: [], resolve: false, decodeAll: false },
    });
  });

  it("shows timeout notification with incomplete tests and partial results", () => {
    const timeoutReport: AnalysisReport = {
      results: [],
      hopChain: [],
      securityAppliances: [],
      metadata: {
        totalTests: 4,
        passedTests: 1,
        failedTests: 0,
        skippedTests: 0,
        elapsedMs: 30000,
        timedOut: true,
        incompleteTests: ["Mimecast Fingerprint", "Proofpoint TAP"],
      },
    };

    useAnalysisState.status = "timeout";
    useAnalysisState.progress = baseProgress;
    useAnalysisState.result = timeoutReport;

    const { container } = render(<Home />);
    const alert = container.querySelector('[role="alert"]');
    expect(alert).not.toBeNull();
    const timeoutTests = container.querySelector('[data-testid="timeout-tests"]');
    expect(timeoutTests?.textContent ?? "").toMatch(/Mimecast Fingerprint/);
    expect(timeoutTests?.textContent ?? "").toMatch(/Proofpoint TAP/);

    const results = container.querySelector('[data-testid="analysis-results"]');
    expect(results).not.toBeNull();
  });

  it("renders the captcha modal when rate limited", () => {
    useAnalysisState.captchaChallenge = {
      challengeToken: "challenge-123",
      imageBase64: "image-data",
    };

    const { container } = render(<Home />);
    const modal = container.querySelector('[data-testid="captcha-challenge"]');
    expect(modal).not.toBeNull();
  });
});
