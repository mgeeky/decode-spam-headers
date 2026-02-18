import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    exclude: ["**/e2e/**", "**/node_modules/**", "**/.next/**", "**/dist/**"],
  },
});
