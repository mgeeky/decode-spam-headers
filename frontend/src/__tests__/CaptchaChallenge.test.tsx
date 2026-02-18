import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import CaptchaChallenge from "../components/CaptchaChallenge";

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

const sampleChallenge = {
  challengeToken: "challenge-token",
  imageBase64:
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFgwJ/l0pNqQAAAABJRU5ErkJggg==",
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

describe("CaptchaChallenge", () => {
  it("renders the modal with the captcha image and input", () => {
    const { container } = render(
      <CaptchaChallenge
        isOpen
        challenge={sampleChallenge}
        onVerify={vi.fn()}
        onSuccess={vi.fn()}
        onRetry={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    const modal = getByTestId(container, "captcha-challenge");
    expect(modal.getAttribute("role")).toBe("dialog");

    const image = getByTestId(container, "captcha-image") as HTMLImageElement;
    expect(image.src).toContain(sampleChallenge.imageBase64);
    expect(image.alt).toBeTruthy();

    const input = getByTestId(container, "captcha-input") as HTMLInputElement;
    expect(input.value).toBe("");

    input.focus();
    expect(document.activeElement).toBe(input);

    const closeButton = getByTestId(container, "captcha-close") as HTMLButtonElement;
    closeButton.focus();
    expect(document.activeElement).toBe(closeButton);
  });

  it("submits the answer and handles success", async () => {
    const onVerify = vi.fn(async () => "bypass-token");
    const onSuccess = vi.fn();
    const onRetry = vi.fn();
    const onClose = vi.fn();

    const { container } = render(
      <CaptchaChallenge
        isOpen
        challenge={sampleChallenge}
        onVerify={onVerify}
        onSuccess={onSuccess}
        onRetry={onRetry}
        onClose={onClose}
      />,
    );

    const input = getByTestId(container, "captcha-input") as HTMLInputElement;
    act(() => {
      input.value = "abc123";
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const submit = getByTestId(container, "captcha-submit") as HTMLButtonElement;
    await act(async () => {
      submit.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await flushPromises();
    });

    expect(onVerify).toHaveBeenCalledWith({
      challengeToken: sampleChallenge.challengeToken,
      answer: "abc123",
    });
    expect(onSuccess).toHaveBeenCalledWith("bypass-token");
    expect(onRetry).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("shows an error when verification fails", async () => {
    const onVerify = vi.fn(async () => {
      throw new Error("Invalid captcha");
    });

    const { container } = render(
      <CaptchaChallenge
        isOpen
        challenge={sampleChallenge}
        onVerify={onVerify}
        onSuccess={vi.fn()}
        onRetry={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    const input = getByTestId(container, "captcha-input") as HTMLInputElement;
    act(() => {
      input.value = "wrong";
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const submit = getByTestId(container, "captcha-submit") as HTMLButtonElement;
    await act(async () => {
      submit.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await flushPromises();
    });

    const error = getByTestId(container, "captcha-error");
    expect(error.textContent).toMatch(/invalid|failed|try again/i);
  });

  it("supports keyboard submission and escape to close", async () => {
    const onVerify = vi.fn(async () => "bypass-token");
    const onClose = vi.fn();

    const { container } = render(
      <CaptchaChallenge
        isOpen
        challenge={sampleChallenge}
        onVerify={onVerify}
        onSuccess={vi.fn()}
        onRetry={vi.fn()}
        onClose={onClose}
      />,
    );

    const input = getByTestId(container, "captcha-input") as HTMLInputElement;
    act(() => {
      input.value = "keyboard";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });

    await act(async () => {
      await flushPromises();
    });

    expect(onVerify).toHaveBeenCalled();

    const modal = getByTestId(container, "captcha-challenge");
    act(() => {
      modal.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });

    expect(onClose).toHaveBeenCalled();
  });

  it("keeps focus trapped within the modal when tabbing", () => {
    const { container } = render(
      <CaptchaChallenge
        isOpen
        challenge={sampleChallenge}
        onVerify={vi.fn()}
        onSuccess={vi.fn()}
        onRetry={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    const closeButton = getByTestId(container, "captcha-close") as HTMLButtonElement;
    const submit = getByTestId(container, "captcha-submit") as HTMLButtonElement;

    submit.focus();
    expect(document.activeElement).toBe(submit);

    act(() => {
      submit.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true }));
    });

    expect(document.activeElement).toBe(closeButton);

    closeButton.focus();
    expect(document.activeElement).toBe(closeButton);

    act(() => {
      closeButton.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Tab", shiftKey: true, bubbles: true }),
      );
    });

    expect(document.activeElement).toBe(submit);
  });
});
