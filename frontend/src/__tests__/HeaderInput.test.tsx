import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import HeaderInput from "../components/HeaderInput";

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
    throw new Error("Expected textarea to be rendered.");
  }
  return textarea as HTMLTextAreaElement;
};

const getAlert = (container: HTMLElement): HTMLElement | null =>
  container.querySelector("[role=\"alert\"]");

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
});

describe("HeaderInput", () => {
  it("renders a textarea for SMTP headers", () => {
    const { container } = render(<HeaderInput value="" onChange={() => undefined} />);
    expect(getTextarea(container)).toBeTruthy();
  });

  it("accepts pasted header text", () => {
    const handleChange = vi.fn();
    const { container } = render(<HeaderInput value="" onChange={handleChange} />);
    const textarea = getTextarea(container);
    const pasted = "Received: from mail.example.com by mx.example.net";

    act(() => {
      const pasteEvent = new Event("paste", { bubbles: true });
      Object.defineProperty(pasteEvent, "clipboardData", {
        value: {
          getData: () => pasted,
        },
      });
      textarea.value = pasted;
      textarea.dispatchEvent(pasteEvent);
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
    });

    expect(handleChange).toHaveBeenCalledWith(pasted);
  });

  it("shows a validation error when left empty", () => {
    const { container } = render(<HeaderInput value="" onChange={() => undefined} />);
    const textarea = getTextarea(container);

    act(() => {
      textarea.dispatchEvent(new Event("blur", { bubbles: true }));
    });

    const alert = getAlert(container);
    expect(alert).not.toBeNull();
    expect(alert?.textContent ?? "").toMatch(/empty|required/i);
    expect(textarea.getAttribute("aria-invalid")).toBe("true");
  });

  it("shows a validation error when input exceeds 1 MB", () => {
    const oversized = "a".repeat(1024 * 1024 + 1);
    const { container } = render(<HeaderInput value={oversized} onChange={() => undefined} />);
    const textarea = getTextarea(container);

    act(() => {
      textarea.dispatchEvent(new Event("blur", { bubbles: true }));
    });

    const alert = getAlert(container);
    expect(alert).not.toBeNull();
    expect(alert?.textContent ?? "").toMatch(/1\s?mb/i);
    expect(textarea.getAttribute("aria-invalid")).toBe("true");
  });
});
