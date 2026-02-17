export const colors = {
  background: "#1e1e2e",
  surface: "#282a36",
  text: "#f8f8f2",
  spam: "#ff5555",
  suspicious: "#ffb86c",
  clean: "#50fa7b",
  accent: "#bd93f9",
  info: "#8be9fd",
} as const;

export const fontFamilies = {
  sans: "var(--font-geist-sans), ui-sans-serif, system-ui, sans-serif",
  mono: "var(--font-geist-mono), ui-monospace, SFMono-Regular, Menlo, monospace",
} as const;

export const spacing = {
  none: "0px",
  xs: "4px",
  sm: "8px",
  md: "12px",
  lg: "16px",
  xl: "24px",
  "2xl": "32px",
  "3xl": "48px",
  "4xl": "64px",
} as const;

export const radii = {
  none: "0px",
  sm: "4px",
  md: "8px",
  lg: "12px",
  xl: "16px",
  full: "9999px",
} as const;

export const designTokens = {
  colors,
  fontFamilies,
  spacing,
  radii,
} as const;
