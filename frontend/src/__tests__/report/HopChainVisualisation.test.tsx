import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import HopChainVisualisation from "../../components/report/HopChainVisualisation";
import type { HopChainNode } from "../../types/analysis";

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

const hopChain: HopChainNode[] = [
  {
    index: 0,
    hostname: "mail.sender.example",
    ip: "192.0.2.10",
    timestamp: "2026-02-17 10:00:01",
    serverInfo: "Postfix",
  },
  {
    index: 1,
    hostname: "mx.receiver.example",
    ip: "203.0.113.5",
    timestamp: "2026-02-17 10:00:04",
    serverInfo: "Exchange 2019",
  },
];

afterEach(() => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      cleanup();
    }
  }
});

describe("HopChainVisualisation", () => {
  it("renders hop nodes with server details", () => {
    const { container } = render(<HopChainVisualisation hopChain={hopChain} />);

    const root = getByTestId(container, "hop-chain-visualisation");
    expect(root).toBeTruthy();

    const firstHop = getByTestId(container, "hop-chain-node-0");
    expect(firstHop.textContent ?? "").toContain("mail.sender.example");
    expect(firstHop.textContent ?? "").toContain("192.0.2.10");

    const secondHop = getByTestId(container, "hop-chain-node-1");
    expect(secondHop.textContent ?? "").toContain("mx.receiver.example");
    expect(secondHop.textContent ?? "").toContain("203.0.113.5");
  });

  it("renders connectors between hop nodes", () => {
    const { container } = render(<HopChainVisualisation hopChain={hopChain} />);

    const connectors = container.querySelectorAll('[data-testid^="hop-chain-connector-"]');

    expect(connectors.length).toBe(hopChain.length - 1);
  });

  it("adds wrapping classes for long hostnames and IPs", () => {
    const { container } = render(<HopChainVisualisation hopChain={hopChain} />);

    const firstHop = getByTestId(container, "hop-chain-node-0");
    const spanNodes = Array.from(firstHop.querySelectorAll("span"));
    const hostnameNode = spanNodes.find((node) => node.textContent === "mail.sender.example");
    const ipNode = spanNodes.find((node) => node.textContent === "192.0.2.10");

    expect(hostnameNode?.className ?? "").toContain("break-words");
    expect(ipNode?.className ?? "").toContain("break-all");
  });
});
