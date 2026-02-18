import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import Home from "../app/page";
import type { AnalysisConfig, AnalysisReport } from "../types/analysis";

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
      submit: submitSpy,
      cancel: cancelSpy,
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

const getClearCacheButton = (container: HTMLElement): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll("button"));
  const button = buttons.find((candidate) =>
    (candidate.textContent ?? "").toLowerCase().includes("clear cache"),
  );
  if (!button) {
    throw new Error("Expected clear cache button to be rendered.");
  }
  return button as HTMLButtonElement;
};

const cachedConfig: AnalysisConfig = {
  testIds: [101, 202],
  resolve: false,
  decodeAll: false,
};

const cachedReport: AnalysisReport = {
  results: [
    {
      testId: 101,
      testName: "SpamAssassin Rule Hits",
      headerName: "X-Spam-Status",
      headerValue: "Yes",
      analysis: "Hits: 6.2",
      description: "Spam scoring summary.",
      severity: "spam",
      status: "success",
      error: null,
    },
  ],
  hopChain: [],
  securityAppliances: [],
  metadata: {
    totalTests: 1,
    passedTests: 1,
    failedTests: 0,
    skippedTests: 0,
    elapsedMs: 1200,
    timedOut: false,
    incompleteTests: [],
  },
};

const seedCache = (headers: string) => {
  localStorage.setItem("wha:headers", headers);
  localStorage.setItem("wha:config", JSON.stringify(cachedConfig));
  localStorage.setItem("wha:result", JSON.stringify(cachedReport));
  localStorage.setItem("wha:timestamp", "1700000000000");
};

const resetUseAnalysisState = (): void => {
  useAnalysisState.status = "idle";
  useAnalysisState.progress = null;
  useAnalysisState.result = null;
  useAnalysisState.error = null;
};

beforeEach(() => {
  localStorage.clear();
  resetUseAnalysisState();
});

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
  submitSpy.mockClear();
  cancelSpy.mockClear();
  localStorage.clear();
});

describe("Home page cache", () => {
  it("restores cached analysis on mount", () => {
    seedCache("Received: from mail.example.com");

    const { container } = render(<Home />);
    const textarea = getTextarea(container);

    expect(textarea.value).toBe("Received: from mail.example.com");
    const report = container.querySelector('[data-testid="report-container"]');
    expect(report).not.toBeNull();
  });

  it("clears cached data and resets the view", () => {
    seedCache("Received: from mail.example.com");

    const { container } = render(<Home />);
    const button = getClearCacheButton(container);

    act(() => {
      button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(localStorage.getItem("wha:headers")).toBeNull();
    expect(localStorage.getItem("wha:config")).toBeNull();
    expect(localStorage.getItem("wha:result")).toBeNull();
    expect(localStorage.getItem("wha:timestamp")).toBeNull();
    expect(getTextarea(container).value).toBe("");
    expect(container.querySelector('[data-testid="report-container"]')).toBeNull();
  });
});
