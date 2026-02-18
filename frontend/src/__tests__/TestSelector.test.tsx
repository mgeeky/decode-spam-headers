import type { ReactElement } from "react";
import { useState } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import TestSelector from "../components/TestSelector";

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

const getSearchInput = (container: HTMLElement): HTMLInputElement => {
  const input = container.querySelector('[data-testid="test-search-input"]');
  if (!input) {
    throw new Error("Expected test search input to be rendered.");
  }
  return input as HTMLInputElement;
};

const getSelectAllButton = (container: HTMLElement): HTMLButtonElement => {
  const button = container.querySelector('[data-testid="select-all-tests"]');
  if (!button) {
    throw new Error("Expected select all button to be rendered.");
  }
  return button as HTMLButtonElement;
};

const getDeselectAllButton = (container: HTMLElement): HTMLButtonElement => {
  const button = container.querySelector('[data-testid="deselect-all-tests"]');
  if (!button) {
    throw new Error("Expected deselect all button to be rendered.");
  }
  return button as HTMLButtonElement;
};

const getCheckbox = (container: HTMLElement, id: number): HTMLInputElement => {
  const checkbox = container.querySelector(`[data-testid="test-checkbox-${id}"]`);
  if (!checkbox) {
    throw new Error(`Expected checkbox for test ${id} to be rendered.`);
  }
  return checkbox as HTMLInputElement;
};

const queryCheckbox = (container: HTMLElement, id: number): HTMLInputElement | null => {
  return container.querySelector(`[data-testid="test-checkbox-${id}"]`) as HTMLInputElement | null;
};

const sampleTests: TestInfo[] = [
  { id: 101, name: "SpamAssassin Rule Hits", category: "SpamAssassin" },
  { id: 202, name: "Mimecast Fingerprint", category: "Mimecast" },
  { id: 303, name: "Barracuda Reputation", category: "Barracuda" },
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

describe("TestSelector", () => {
  it("renders fetched tests with checkboxes", async () => {
    setupFetchMock(sampleTests);
    const { container } = render(
      <TestSelector selectedTestIds={[]} onSelectionChange={() => undefined} />,
    );

    await act(async () => {
      await flushPromises();
    });

    sampleTests.forEach((test) => {
      const checkbox = getCheckbox(container, test.id);
      expect(checkbox).toBeTruthy();
      expect(container.textContent ?? "").toContain(test.name);
    });
  });

  it("selects and deselects all tests", async () => {
    setupFetchMock(sampleTests);

    const TestSelectorHarness = () => {
      const [selected, setSelected] = useState<number[]>([]);
      return <TestSelector selectedTestIds={selected} onSelectionChange={setSelected} />;
    };

    const { container } = render(<TestSelectorHarness />);

    await act(async () => {
      await flushPromises();
    });

    const selectAllButton = getSelectAllButton(container);
    act(() => {
      selectAllButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    sampleTests.forEach((test) => {
      expect(getCheckbox(container, test.id).checked).toBe(true);
    });

    const deselectAllButton = getDeselectAllButton(container);
    act(() => {
      deselectAllButton.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    sampleTests.forEach((test) => {
      expect(getCheckbox(container, test.id).checked).toBe(false);
    });
  });

  it("supports keyboard activation for select and deselect", async () => {
    setupFetchMock(sampleTests);

    const TestSelectorHarness = () => {
      const [selected, setSelected] = useState<number[]>([]);
      return <TestSelector selectedTestIds={selected} onSelectionChange={setSelected} />;
    };

    const { container } = render(<TestSelectorHarness />);

    await act(async () => {
      await flushPromises();
    });

    const selectAllButton = getSelectAllButton(container);
    act(() => {
      selectAllButton.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });

    sampleTests.forEach((test) => {
      expect(getCheckbox(container, test.id).checked).toBe(true);
    });

    const deselectAllButton = getDeselectAllButton(container);
    act(() => {
      deselectAllButton.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    });

    sampleTests.forEach((test) => {
      expect(getCheckbox(container, test.id).checked).toBe(false);
    });
  });

  it("filters tests by search text", async () => {
    setupFetchMock(sampleTests);

    const { container } = render(
      <TestSelector selectedTestIds={[]} onSelectionChange={() => undefined} />,
    );

    await act(async () => {
      await flushPromises();
    });

    const searchInput = getSearchInput(container);
    act(() => {
      searchInput.value = "mime";
      searchInput.dispatchEvent(new Event("input", { bubbles: true }));
    });

    expect(getCheckbox(container, 202)).toBeTruthy();
    expect(queryCheckbox(container, 101)).toBeNull();
    expect(queryCheckbox(container, 303)).toBeNull();
  });
});
