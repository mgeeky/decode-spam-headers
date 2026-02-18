import type { ReactElement } from "react";
import { useState } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import ReportSearchBar from "../../components/report/ReportSearchBar";
import type { TestResult } from "../../types/analysis";

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

const sampleResults: TestResult[] = [
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
];

const filterResults = (query: string, results: TestResult[]): TestResult[] => {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return results;
  }
  return results.filter((result) => {
    return (
      result.testName.toLowerCase().includes(normalizedQuery) ||
      result.headerName.toLowerCase().includes(normalizedQuery) ||
      result.analysis.toLowerCase().includes(normalizedQuery)
    );
  });
};

const ReportSearchHarness = () => {
  const [query, setQuery] = useState("");
  const filtered = filterResults(query, sampleResults);

  return (
    <div>
      <ReportSearchBar
        query={query}
        matchCount={filtered.length}
        totalCount={sampleResults.length}
        onQueryChange={setQuery}
      />
      <ul data-testid="filtered-results">
        {filtered.map((result) => (
          <li key={result.testId}>{result.testName}</li>
        ))}
      </ul>
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
});

describe("ReportSearchBar", () => {
  it("filters results when the search query changes", () => {
    const { container } = render(<ReportSearchHarness />);

    const input = getByTestId(container, "report-search-input") as HTMLInputElement;

    act(() => {
      input.value = "mime";
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const filteredList = getByTestId(container, "filtered-results");
    expect(filteredList.textContent ?? "").toContain("Mimecast Fingerprint");
    expect(filteredList.textContent ?? "").not.toContain("SpamAssassin Rule Hits");

    const count = getByTestId(container, "report-search-count");
    expect(count.textContent ?? "").toMatch(/1/);
  });

  it("clears the query on Escape", () => {
    const { container } = render(<ReportSearchHarness />);

    const input = getByTestId(container, "report-search-input") as HTMLInputElement;

    act(() => {
      input.value = "spam";
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    act(() => {
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });

    expect(input.value).toBe("");
    const filteredList = getByTestId(container, "filtered-results");
    expect(filteredList.textContent ?? "").toContain("SpamAssassin Rule Hits");
    expect(filteredList.textContent ?? "").toContain("Mimecast Fingerprint");
  });
});
