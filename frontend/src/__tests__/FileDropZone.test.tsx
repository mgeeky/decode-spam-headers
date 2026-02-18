import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import FileDropZone from "../components/FileDropZone";

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

const getDropZone = (container: HTMLElement): HTMLElement => {
  const zone = container.querySelector('[data-testid="file-drop-zone"]');
  if (!zone) {
    throw new Error("Expected file drop zone to be rendered.");
  }
  return zone as HTMLElement;
};

const createDropEvent = (files: File[]): Event => {
  const event = new Event("drop", { bubbles: true });
  const items = files.map((file) => ({
    kind: "file",
    type: file.type,
    getAsFile: () => file,
  }));

  Object.defineProperty(event, "dataTransfer", {
    value: {
      files,
      items,
      types: ["Files"],
    },
  });

  return event;
};

const mockFileReader = (result: string): (() => void) => {
  const original = globalThis.FileReader;

  class MockFileReader {
    result: string | ArrayBuffer | null = null;
    onload: ((this: FileReader, ev: ProgressEvent<FileReader>) => void) | null = null;
    onerror: ((this: FileReader, ev: ProgressEvent<FileReader>) => void) | null = null;

    readAsText() {
      this.result = result;
      if (this.onload) {
        this.onload(new ProgressEvent("load"));
      }
    }
  }

  globalThis.FileReader = MockFileReader as unknown as typeof FileReader;

  return () => {
    globalThis.FileReader = original;
  };
};

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
});

describe("FileDropZone", () => {
  it("renders a drop zone for EML/TXT files", () => {
    const { container } = render(<FileDropZone onFileContent={() => undefined} />);
    expect(getDropZone(container)).toBeTruthy();
  });

  it("reads dropped EML/TXT file content", () => {
    const handleContent = vi.fn();
    const restore = mockFileReader("Header from file");
    const { container } = render(<FileDropZone onFileContent={handleContent} />);
    const dropZone = getDropZone(container);
    const file = new File(["Header from file"], "sample.eml", { type: "message/rfc822" });

    act(() => {
      dropZone.dispatchEvent(createDropEvent([file]));
    });

    restore();

    expect(handleContent).toHaveBeenCalledWith("Header from file");
  });

  it("rejects unsupported file types with feedback", () => {
    const handleContent = vi.fn();
    const { container } = render(<FileDropZone onFileContent={handleContent} />);
    const dropZone = getDropZone(container);
    const file = new File(["irrelevant"], "payload.pdf", { type: "application/pdf" });

    act(() => {
      dropZone.dispatchEvent(createDropEvent([file]));
    });

    expect(handleContent).not.toHaveBeenCalled();

    const alert = container.querySelector('[role="alert"]');
    expect(alert).not.toBeNull();
    expect(alert?.textContent ?? "").toMatch(/\.eml/i);
    expect(alert?.textContent ?? "").toMatch(/\.txt/i);
  });

  it("opens the file picker on keyboard activation", () => {
    const { container } = render(<FileDropZone onFileContent={() => undefined} />);
    const dropZone = getDropZone(container);
    const input = container.querySelector('input[type="file"]') as HTMLInputElement | null;
    expect(input).not.toBeNull();
    if (!input) {
      return;
    }

    const clickSpy = vi.spyOn(input, "click");

    act(() => {
      dropZone.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });

    expect(clickSpy).toHaveBeenCalled();
    clickSpy.mockRestore();
  });

  it("reads selected file content from the file picker", () => {
    const handleContent = vi.fn();
    const restore = mockFileReader("Header from input");
    const { container } = render(<FileDropZone onFileContent={handleContent} />);
    const input = container.querySelector('input[type="file"]') as HTMLInputElement | null;
    expect(input).not.toBeNull();
    if (!input) {
      restore();
      return;
    }

    const file = new File(["Header from input"], "sample.eml", { type: "message/rfc822" });
    Object.defineProperty(input, "files", {
      value: [file],
      writable: false,
    });

    act(() => {
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });

    restore();

    expect(handleContent).toHaveBeenCalledWith("Header from input");
  });
});
