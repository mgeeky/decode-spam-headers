import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");

const parsePercentage = (value: string | null): number => {
  if (!value) {
    return 0;
  }
  const numeric = Number(value.replace("%", "").trim());
  return Number.isFinite(numeric) ? numeric : 0;
};

test("paste headers and analyse renders progress and report", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);
  await analyzer.clickAnalyse();

  const progressIndicator = page.getByTestId("progress-indicator");
  await expect(progressIndicator).toBeVisible({ timeout: 30000 });

  const currentTest = page.getByTestId("progress-current-test");
  await expect(currentTest).toBeVisible();
  await expect(currentTest).not.toHaveText(/^\s*$/);
  await expect(currentTest).not.toHaveText(/Preparing analysis/i);

  const firstTestName = (await currentTest.textContent())?.trim() ?? "";
  await page.waitForFunction(
    ({ testId, previous }) => {
      const node = document.querySelector(`[data-testid="${testId}"]`);
      if (!node) {
        return false;
      }
      const nextValue = (node.textContent ?? "").trim();
      return nextValue.length > 0 && nextValue !== previous;
    },
    { testId: "progress-current-test", previous: firstTestName },
  );

  const progressPercentage = page.getByTestId("progress-percentage");
  const initialPercentage = parsePercentage(await progressPercentage.textContent());
  expect(initialPercentage).toBeGreaterThanOrEqual(0);

  await analyzer.waitForResults();

  const resultCards = analyzer.getResultCards();
  await expect(resultCards.first()).toBeVisible();

  const severityBadge = page.locator('[data-testid^="test-result-severity-"]').first();
  await expect(severityBadge).toBeVisible();
  const severityClass = await severityBadge.getAttribute("class");
  expect(severityClass ?? "").toMatch(/text-(spam|suspicious|clean|accent)/);

  const firstToggle = resultCards.first().locator('[data-testid^="test-result-toggle-"]');
  await expect(firstToggle).toHaveAttribute("aria-expanded", "false");
  await analyzer.expandCard(0);
  await expect(firstToggle).toHaveAttribute("aria-expanded", "true");
  await analyzer.collapseCard(0);
  await expect(firstToggle).toHaveAttribute("aria-expanded", "false");

  await expect(page.getByTestId("hop-chain-visualisation")).toBeVisible();
});

test("Ctrl+Enter triggers analysis", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);

  const analysisResponse = page.waitForResponse(
    (response) => response.url().includes("/api/analyse") && response.status() === 200,
  );

  await analyzer.pressCtrlEnter();
  await analysisResponse;
  await analyzer.waitForResults();

  await expect(page.getByTestId("report-container")).toBeVisible();
});
