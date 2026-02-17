import { describe, expect, it } from "vitest";

import { colors, fontFamilies, radii, spacing } from "./design-tokens";

describe("design tokens", () => {
  it("exposes the expected color palette", () => {
    expect(colors).toEqual({
      background: "#1e1e2e",
      surface: "#282a36",
      text: "#f8f8f2",
      spam: "#ff5555",
      suspicious: "#ffb86c",
      clean: "#50fa7b",
      accent: "#bd93f9",
      info: "#8be9fd",
    });
  });

  it("includes core font, spacing, and radius tokens", () => {
    expect(fontFamilies.sans).toContain("var(--font-geist-sans)");
    expect(fontFamilies.mono).toContain("var(--font-geist-mono)");
    expect(spacing.md).toBe("12px");
    expect(radii.md).toBe("8px");
  });
});
