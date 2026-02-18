import type { ReactElement } from "react";
import { act } from "react-dom/test-utils";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import SecurityAppliancesSummary from "../../components/report/SecurityAppliancesSummary";
import type { SecurityAppliance } from "../../types/analysis";

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

const sampleAppliances: SecurityAppliance[] = [
  {
    name: "Mimecast Email Security",
    vendor: "Mimecast",
    headers: ["X-Mimecast-Spam-Info"],
  },
  {
    name: "Proofpoint Protection",
    vendor: "Proofpoint",
    headers: ["X-Proofpoint-Verdict"],
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

describe("SecurityAppliancesSummary", () => {
  it("renders detected security appliances as badges", () => {
    const { container } = render(
      <SecurityAppliancesSummary appliances={sampleAppliances} />,
    );

    const summary = getByTestId(container, "security-appliances-summary");
    expect(summary.textContent ?? "").toContain("Mimecast Email Security");
    expect(summary.textContent ?? "").toContain("Proofpoint Protection");

    const firstBadge = getByTestId(container, "security-appliance-0");
    expect(firstBadge.textContent ?? "").toContain("Mimecast");
  });

  it("renders an empty state when no appliances are detected", () => {
    const { container } = render(<SecurityAppliancesSummary appliances={[]} />);

    const emptyState = getByTestId(container, "security-appliances-empty");
    expect(emptyState.textContent ?? "").toMatch(/No security appliances detected/i);
  });
});
