import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import Home from "../app/page";

const { submitSpy, cancelSpy } = vi.hoisted(() => ({
  submitSpy: vi.fn().mockResolvedValue(undefined),
  cancelSpy: vi.fn(),
}));

vi.mock("../hooks/useAnalysis", () => ({
  __esModule: true,
  default: () => ({
    status: "idle",
    progress: null,
    result: null,
    error: null,
    submit: submitSpy,
    cancel: cancelSpy,
  }),
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

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
  submitSpy.mockClear();
  cancelSpy.mockClear();
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
});
