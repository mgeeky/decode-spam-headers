import type { ReactElement } from "react";
import { useState } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import AnalysisControls from "../components/AnalysisControls";
import type { AnalysisConfig } from "../types/analysis";

type RenderResult = {
  container: HTMLDivElement;
};

type TestInfo = {
  id: number;
  name: string;
  category: string;
};

const cleanups: Array<() => void> = [];
let restoreFetch: (() => void) | null = null;

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

const setupFetchMock = (tests: TestInfo[]): void => {
  const originalFetch = globalThis.fetch;
  const fetchMock = vi.fn(async () => {
    return new Response(JSON.stringify({ tests, totalCount: tests.length }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });

  globalThis.fetch = fetchMock as unknown as typeof fetch;

  restoreFetch = () => {
    globalThis.fetch = originalFetch;
  };
};

const flushPromises = async (): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, 0));
};

const getToggle = (container: HTMLElement, testId: string): HTMLElement => {
  const toggle = container.querySelector(`[data-testid="${testId}"]`);
  if (!toggle) {
    throw new Error(`Expected toggle ${testId} to be rendered.`);
  }
  return toggle as HTMLElement;
};

const getTestSelector = (container: HTMLElement): HTMLElement => {
  const selector = container.querySelector('[data-testid="test-selector"]');
  if (!selector) {
    throw new Error("Expected test selector to be rendered.");
  }
  return selector as HTMLElement;
};

const sampleTests: TestInfo[] = [
  { id: 101, name: "SpamAssassin Rule Hits", category: "SpamAssassin" },
  { id: 202, name: "Mimecast Fingerprint", category: "Mimecast" },
];

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
  if (restoreFetch) {
    restoreFetch();
    restoreFetch = null;
  }
});

describe("AnalysisControls", () => {
  it("renders toggles with default off state", async () => {
    setupFetchMock(sampleTests);
    const config: AnalysisConfig = { testIds: [], resolve: false, decodeAll: false };

    const { container } = render(
      <AnalysisControls config={config} onChange={() => undefined} />,
    );

    await act(async () => {
      await flushPromises();
    });

    getTestSelector(container);
    expect(getToggle(container, "toggle-resolve").getAttribute("aria-checked")).toBe("false");
    expect(getToggle(container, "toggle-decode-all").getAttribute("aria-checked")).toBe(
      "false",
    );
  });

  it("updates toggles on click and keyboard", async () => {
    setupFetchMock(sampleTests);
    const handleChange = vi.fn();

    const AnalysisControlsHarness = () => {
      const [config, setConfig] = useState<AnalysisConfig>({
        testIds: [],
        resolve: false,
        decodeAll: false,
      });

      const updateConfig = (next: AnalysisConfig) => {
        setConfig(next);
        handleChange(next);
      };

      return <AnalysisControls config={config} onChange={updateConfig} />;
    };

    const { container } = render(<AnalysisControlsHarness />);

    await act(async () => {
      await flushPromises();
    });

    const resolveToggle = getToggle(container, "toggle-resolve");
    act(() => {
      resolveToggle.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(resolveToggle.getAttribute("aria-checked")).toBe("true");
    expect(handleChange).toHaveBeenCalledWith(
      expect.objectContaining({ resolve: true, decodeAll: false }),
    );

    const decodeToggle = getToggle(container, "toggle-decode-all");
    act(() => {
      decodeToggle.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
      );
    });

    expect(decodeToggle.getAttribute("aria-checked")).toBe("true");
    expect(handleChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ resolve: true, decodeAll: true }),
    );
  });
});
