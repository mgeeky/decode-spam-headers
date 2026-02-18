import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");

const extractSearchQuery = (label: string): string => {
  const trimmed = label.trim();
  if (!trimmed) {
    return "";
  }
  const firstToken = trimmed.split(/\s+/)[0] ?? "";
  if (firstToken.length >= 4) {
    return firstToken;
  }
  return trimmed.length > 4 ? trimmed.slice(0, 4) : trimmed;
};

test("test selection filters and limits analysis results", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();

  const checkboxLocator = page.locator('[data-testid^="test-checkbox-"]');
  await expect.poll(async () => checkboxLocator.count()).toBeGreaterThanOrEqual(106);
  const totalCount = await checkboxLocator.count();
  expect(totalCount).toBeGreaterThanOrEqual(106);

  const firstCheckbox = checkboxLocator.first();
  await firstCheckbox.waitFor({ state: "visible" });
  const firstLabel = await firstCheckbox.getAttribute("aria-label");
  if (!firstLabel) {
    throw new Error("Expected test checkbox to have an aria-label.");
  }

  const searchInput = page.getByTestId("test-search-input");
  const searchQuery = extractSearchQuery(firstLabel);
  if (!searchQuery) {
    throw new Error("Unable to derive search query from test label.");
  }

  await searchInput.fill(searchQuery);
  await expect
    .poll(async () => checkboxLocator.count())
    .toBeLessThan(totalCount);
  const filteredCount = await checkboxLocator.count();
  expect(filteredCount).toBeGreaterThan(0);

  await searchInput.fill("");
  await expect.poll(async () => checkboxLocator.count()).toBe(totalCount);

  const resolveToggle = page.getByTestId("toggle-resolve");
  const decodeToggle = page.getByTestId("toggle-decode-all");

  if ((await resolveToggle.getAttribute("aria-checked")) !== "true") {
    await resolveToggle.click();
  }
  if ((await decodeToggle.getAttribute("aria-checked")) !== "true") {
    await decodeToggle.click();
  }

  await expect(resolveToggle).toHaveAttribute("aria-checked", "true");
  await expect(decodeToggle).toHaveAttribute("aria-checked", "true");

  await analyzer.deselectAll();

  const selectedIds = await checkboxLocator.evaluateAll((nodes) => {
    const ids: number[] = [];
    for (const node of nodes) {
      if (ids.length >= 3) {
        break;
      }
      const testId = node.getAttribute("data-testid") ?? "";
      const numeric = Number(testId.replace("test-checkbox-", ""));
      if (Number.isFinite(numeric)) {
        ids.push(numeric);
      }
    }
    return ids;
  });

  if (selectedIds.length < 3) {
    throw new Error("Expected at least three tests to select.");
  }

  await analyzer.selectTests(selectedIds);
  await analyzer.pasteHeaders(headers);

  const analysisResponse = page.waitForResponse(
    (response) => response.url().includes("/api/analyse") && response.status() === 200,
  );

  await analyzer.clickAnalyse();
  await analysisResponse;
  await analyzer.waitForResults();

  const resultCards = analyzer.getResultCards();
  await expect(resultCards).toHaveCount(3, { timeout: 30000 });

  for (const id of selectedIds) {
    await expect(page.getByTestId(`test-result-card-${id}`)).toBeVisible();
  }

  await expect(resolveToggle).toHaveAttribute("aria-checked", "true");
  await expect(decodeToggle).toHaveAttribute("aria-checked", "true");
});
