import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ReportExport from "../../components/report/ReportExport";
import type { AnalysisReport } from "../../types/analysis";

type RenderResult = {
  container: HTMLDivElement;
};

type UrlStatics = {
  createObjectURL?: (blob: Blob) => string;
  revokeObjectURL?: (url: string) => void;
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
      description: "SpamAssassin rules matched during analysis.",
      severity: "spam",
      status: "error",
      error: "Timeout",
    },
  ],
  hopChain: [],
  securityAppliances: [],
  metadata: {
    totalTests: 1,
    passedTests: 0,
    failedTests: 1,
    skippedTests: 0,
    elapsedMs: 1200,
    timedOut: false,
    incompleteTests: [],
  },
};

let createObjectUrlSpy: ReturnType<typeof vi.spyOn> | null = null;
let revokeObjectUrlSpy: ReturnType<typeof vi.spyOn> | null = null;
let clickSpy: ReturnType<typeof vi.spyOn> | null = null;

const originalUrlStatics: UrlStatics = {
  createObjectURL: (URL as unknown as UrlStatics).createObjectURL,
  revokeObjectURL: (URL as unknown as UrlStatics).revokeObjectURL,
};

beforeEach(() => {
  const urlStatics = URL as unknown as UrlStatics;

  if (!urlStatics.createObjectURL) {
    urlStatics.createObjectURL = () => "blob:report";
  }
  if (!urlStatics.revokeObjectURL) {
    urlStatics.revokeObjectURL = () => undefined;
  }

  createObjectUrlSpy = vi
    .spyOn(URL, "createObjectURL")
    .mockReturnValue("blob:report");
  revokeObjectUrlSpy = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {
    return undefined;
  });
  clickSpy = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => undefined);
});

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }

  createObjectUrlSpy?.mockRestore();
  revokeObjectUrlSpy?.mockRestore();
  clickSpy?.mockRestore();

  const urlStatics = URL as unknown as UrlStatics;
  urlStatics.createObjectURL = originalUrlStatics.createObjectURL;
  urlStatics.revokeObjectURL = originalUrlStatics.revokeObjectURL;
});

describe("ReportExport", () => {
  it("triggers a JSON download", () => {
    const { container } = render(<ReportExport report={report} />);

    const jsonButton = getByTestId(container, "report-export-json");

    act(() => {
      jsonButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(createObjectUrlSpy).toHaveBeenCalled();
    expect(clickSpy).toHaveBeenCalled();
  });

  it("triggers an HTML download", () => {
    const { container } = render(<ReportExport report={report} />);

    const htmlButton = getByTestId(container, "report-export-html");

    act(() => {
      htmlButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(createObjectUrlSpy).toHaveBeenCalled();
    expect(clickSpy).toHaveBeenCalled();
  });
});
