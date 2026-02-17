import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import AnalyseButton from "../components/AnalyseButton";

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

const getButton = (container: HTMLElement): HTMLButtonElement => {
  const button = container.querySelector("button");
  if (!button) {
    throw new Error("Expected analyse button to be rendered.");
  }
  return button as HTMLButtonElement;
};

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
});

describe("AnalyseButton", () => {
  it("renders an analyse button", () => {
    const { container } = render(<AnalyseButton hasInput onAnalyse={() => undefined} />);
    const button = getButton(container);
    expect(button.textContent ?? "").toMatch(/analyse/i);
  });

  it("disables itself when input is empty", () => {
    const { container } = render(<AnalyseButton hasInput={false} onAnalyse={() => undefined} />);
    const button = getButton(container);
    expect(button.disabled).toBe(true);
  });

  it("triggers analyse on Ctrl+Enter", () => {
    const handleAnalyse = vi.fn();
    render(<AnalyseButton hasInput onAnalyse={handleAnalyse} />);

    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", ctrlKey: true }));
    });

    expect(handleAnalyse).toHaveBeenCalledTimes(1);
  });
});
