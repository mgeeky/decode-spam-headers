import type { ReactElement } from "react";
import { useState } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { AnalysisConfig, AnalysisReport } from "../types/analysis";
import useAnalysisCache from "../hooks/useAnalysisCache";

type RenderResult = {
  container: HTMLDivElement;
};

type CachedPayload = {
  headers: string;
  config: AnalysisConfig;
  result: AnalysisReport;
};

type CachedData = CachedPayload & {
  timestamp: number;
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

const baseConfig: AnalysisConfig = {
  testIds: [101, 202],
  resolve: false,
  decodeAll: true,
};

const baseReport: AnalysisReport = {
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
    totalTests: 3,
    passedTests: 2,
    failedTests: 1,
    skippedTests: 0,
    elapsedMs: 1200,
    timedOut: false,
    incompleteTests: [],
  },
};

const basePayload: CachedPayload = {
  headers: "Received: from mail.example.com",
  config: baseConfig,
  result: baseReport,
};

const CacheHarness = ({ payload }: { payload: CachedPayload }) => {
  const { save, load, clear, hasCachedData, isNearLimit } = useAnalysisCache();
  const [loaded, setLoaded] = useState<CachedData | null>(null);
  const [hasCache, setHasCache] = useState(false);

  return (
    <div>
      <span data-testid="has-cache">{hasCache ? "true" : "false"}</span>
      <span data-testid="loaded-headers">{loaded?.headers ?? ""}</span>
      <span data-testid="loaded-test-count">{loaded?.result.metadata.totalTests ?? ""}</span>
      <span data-testid="loaded-test-ids">{loaded ? loaded.config.testIds.join(",") : ""}</span>
      <span data-testid="near-limit">{isNearLimit ? "true" : "false"}</span>
      <button type="button" data-testid="save" onClick={() => save(payload)}>
        Save
      </button>
      <button type="button" data-testid="load" onClick={() => setLoaded(load())}>
        Load
      </button>
      <button type="button" data-testid="check" onClick={() => setHasCache(hasCachedData())}>
        Check
      </button>
      <button type="button" data-testid="clear" onClick={() => clear()}>
        Clear
      </button>
    </div>
  );
};

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
  localStorage.clear();
});

describe("useAnalysisCache", () => {
  it("saves, loads, and clears cached analysis data", () => {
    const { container } = render(<CacheHarness payload={basePayload} />);

    act(() => {
      getByTestId(container, "check").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(getByTestId(container, "has-cache").textContent).toBe("false");

    act(() => {
      getByTestId(container, "save").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(localStorage.getItem("wha:headers")).toBe(basePayload.headers);
    expect(localStorage.getItem("wha:config")).toBe(JSON.stringify(basePayload.config));
    expect(localStorage.getItem("wha:result")).toBe(JSON.stringify(basePayload.result));
    const timestampValue = localStorage.getItem("wha:timestamp");
    expect(timestampValue).not.toBeNull();
    expect(Number.isNaN(Number(timestampValue))).toBe(false);

    act(() => {
      getByTestId(container, "check").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(getByTestId(container, "has-cache").textContent).toBe("true");

    act(() => {
      getByTestId(container, "load").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(getByTestId(container, "loaded-headers").textContent).toBe(basePayload.headers);
    expect(getByTestId(container, "loaded-test-count").textContent).toBe("3");
    expect(getByTestId(container, "loaded-test-ids").textContent).toBe("101,202");

    act(() => {
      getByTestId(container, "clear").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(localStorage.getItem("wha:headers")).toBeNull();
    expect(localStorage.getItem("wha:config")).toBeNull();
    expect(localStorage.getItem("wha:result")).toBeNull();
    expect(localStorage.getItem("wha:timestamp")).toBeNull();

    act(() => {
      getByTestId(container, "check").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(getByTestId(container, "has-cache").textContent).toBe("false");
  });

  it("flags when cache usage is near the localStorage limit", () => {
    const storageLimitBytes = 5 * 1024 * 1024;
    const warningThresholdBytes = Math.floor(storageLimitBytes * 0.9) + 1024;
    const largeHeaders = "a".repeat(warningThresholdBytes);
    const payload: CachedPayload = {
      ...basePayload,
      headers: largeHeaders,
    };

    const { container } = render(<CacheHarness payload={payload} />);

    act(() => {
      getByTestId(container, "save").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(getByTestId(container, "near-limit").textContent).toBe("true");
  });
});
