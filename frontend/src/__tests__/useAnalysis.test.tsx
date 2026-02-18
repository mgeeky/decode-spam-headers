import type { ReactElement } from "react";
import { useEffect } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiClient } from "../lib/api-client";
import type { AnalysisConfig, AnalysisProgress, AnalysisReport } from "../types/analysis";
import useAnalysis from "../hooks/useAnalysis";

type RenderResult = {
  container: HTMLDivElement;
};

type AnalysisRequest = {
  headers: string;
  config: AnalysisConfig;
};

type HarnessProps = {
  request: AnalysisRequest;
  onStatusChange?: (status: string) => void;
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

const flushPromises = async (): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, 0));
};

const getByTestId = (container: HTMLElement, testId: string): HTMLElement => {
  const element = container.querySelector(`[data-testid="${testId}"]`);
  if (!element) {
    throw new Error(`Expected element ${testId} to be rendered.`);
  }
  return element as HTMLElement;
};

const baseConfig: AnalysisConfig = {
  testIds: [101],
  resolve: true,
  decodeAll: false,
};

const baseRequest: AnalysisRequest = {
  headers: "X-Test: value",
  config: baseConfig,
};

const progressEvent: AnalysisProgress = {
  currentIndex: 0,
  totalTests: 3,
  currentTest: "SpamAssassin Rule Hits",
  elapsedMs: 500,
  percentage: 33,
};

const completeReport: AnalysisReport = {
  results: [],
  hopChain: [],
  securityAppliances: [],
  metadata: {
    totalTests: 3,
    passedTests: 3,
    failedTests: 0,
    skippedTests: 0,
    elapsedMs: 1500,
    timedOut: false,
    incompleteTests: [],
  },
};

const timeoutReport: AnalysisReport = {
  results: [],
  hopChain: [],
  securityAppliances: [],
  metadata: {
    totalTests: 5,
    passedTests: 2,
    failedTests: 1,
    skippedTests: 0,
    elapsedMs: 30000,
    timedOut: true,
    incompleteTests: ["Mimecast Fingerprint", "Proofpoint TAP"],
  },
};

const AnalysisHarness = ({ request, onStatusChange }: HarnessProps) => {
  const {
    status,
    progress,
    result,
    error,
    submit,
    cancel,
    captchaChallenge,
    clearCaptchaChallenge,
  } = useAnalysis();

  useEffect(() => {
    onStatusChange?.(status);
  }, [status, onStatusChange]);

  return (
    <div>
      <span data-testid="status">{status}</span>
      <span data-testid="current-test">{progress?.currentTest ?? ""}</span>
      <span data-testid="percentage">{progress?.percentage ?? ""}</span>
      <span data-testid="result-total">{result?.metadata.totalTests ?? ""}</span>
      <span data-testid="error">{error ?? ""}</span>
      <span data-testid="captcha-token">{captchaChallenge?.challengeToken ?? ""}</span>
      <button data-testid="submit" onClick={() => submit(request)}>
        Submit
      </button>
      <button data-testid="cancel" onClick={() => cancel()}>
        Cancel
      </button>
      <button data-testid="clear-captcha" onClick={() => clearCaptchaChallenge()}>
        Clear Captcha
      </button>
    </div>
  );
};

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
  vi.restoreAllMocks();
});

describe("useAnalysis", () => {
  it("starts in the idle state", () => {
    const { container } = render(<AnalysisHarness request={baseRequest} />);

    expect(getByTestId(container, "status").textContent).toBe("idle");
    expect(getByTestId(container, "current-test").textContent).toBe("");
    expect(getByTestId(container, "error").textContent).toBe("");
  });

  it("submits analysis and handles SSE progress + result", async () => {
    const streamSpy = vi.spyOn(apiClient, "stream").mockImplementation(async (_path, options) => {
      options.onEvent({ event: "progress", data: progressEvent, raw: "" });
      options.onEvent({ event: "result", data: completeReport, raw: "" });
    });

    const statuses: string[] = [];
    const { container } = render(
      <AnalysisHarness request={baseRequest} onStatusChange={(status) => statuses.push(status)} />,
    );

    act(() => {
      getByTestId(container, "submit").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    await act(async () => {
      await flushPromises();
    });

    expect(streamSpy).toHaveBeenCalledWith(
      "/api/analyse",
      expect.objectContaining({
        body: baseRequest,
        onEvent: expect.any(Function),
        signal: expect.any(AbortSignal),
      }),
    );

    expect(statuses).toEqual(["idle", "submitting", "analysing", "complete"]);
    expect(getByTestId(container, "current-test").textContent).toMatch(/SpamAssassin Rule Hits/);
    expect(getByTestId(container, "percentage").textContent).toBe("33");
    expect(getByTestId(container, "result-total").textContent).toBe("3");
  });

  it("marks the analysis as timed out when the report indicates timeout", async () => {
    vi.spyOn(apiClient, "stream").mockImplementation(async (_path, options) => {
      options.onEvent({ event: "result", data: timeoutReport, raw: "" });
    });

    const statuses: string[] = [];
    const { container } = render(
      <AnalysisHarness request={baseRequest} onStatusChange={(status) => statuses.push(status)} />,
    );

    act(() => {
      getByTestId(container, "submit").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    await act(async () => {
      await flushPromises();
    });

    expect(statuses).toEqual(["idle", "submitting", "timeout"]);
    expect(getByTestId(container, "result-total").textContent).toBe("5");
  });

  it("surfaces stream errors and moves to error state", async () => {
    vi.spyOn(apiClient, "stream").mockRejectedValue(new Error("Network error"));

    const statuses: string[] = [];
    const { container } = render(
      <AnalysisHarness request={baseRequest} onStatusChange={(status) => statuses.push(status)} />,
    );

    act(() => {
      getByTestId(container, "submit").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    await act(async () => {
      await flushPromises();
    });

    expect(statuses).toEqual(["idle", "submitting", "error"]);
    expect(getByTestId(container, "error").textContent ?? "").toMatch(/Network error/);
  });

  it("cancels an in-flight analysis request", async () => {
    let abortSignal: AbortSignal | undefined;
    vi.spyOn(apiClient, "stream").mockImplementation(async (_path, options) => {
      abortSignal = options.signal;
      await new Promise<void>((resolve) => {
        if (abortSignal?.aborted) {
          resolve();
          return;
        }
        abortSignal?.addEventListener("abort", () => resolve(), { once: true });
      });
    });

    const statuses: string[] = [];
    const { container } = render(
      <AnalysisHarness request={baseRequest} onStatusChange={(status) => statuses.push(status)} />,
    );

    act(() => {
      getByTestId(container, "submit").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    await act(async () => {
      await flushPromises();
    });

    act(() => {
      getByTestId(container, "cancel").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    await act(async () => {
      await flushPromises();
    });

    expect(abortSignal?.aborted).toBe(true);
    expect(statuses).toContain("idle");
  });

  it("captures captcha challenges on rate limit errors", async () => {
    vi.spyOn(apiClient, "stream").mockRejectedValue(
      new ApiError("Too many requests", 429, {
        captchaChallenge: { challengeToken: "abc123", imageBase64: "image-data" },
      }),
    );

    const { container } = render(<AnalysisHarness request={baseRequest} />);

    act(() => {
      getByTestId(container, "submit").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    await act(async () => {
      await flushPromises();
    });

    expect(getByTestId(container, "captcha-token").textContent).toBe("abc123");
  });
});
