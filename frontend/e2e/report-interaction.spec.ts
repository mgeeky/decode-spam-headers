import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");

const parseCount = (value: string | null): { match: number; total: number } => {
  if (!value) {
    return { match: 0, total: 0 };
  }
  const [matchRaw, totalRaw] = value.split("/").map((part) => part.trim());
  const match = Number(matchRaw);
  const total = Number(totalRaw);
  return {
    match: Number.isFinite(match) ? match : 0,
    total: Number.isFinite(total) ? total : 0,
  };
};

const deriveSearchQuery = (value: string | null): string => {
  const trimmed = (value ?? "").trim();
  if (!trimmed) {
    return "";
  }
  return trimmed.length > 120 ? trimmed.slice(0, 120).trim() : trimmed;
};

test("report interactions allow expand/collapse, search, and export", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);
  await analyzer.clickAnalyse();
  await analyzer.waitForResults();

  const resultCards = analyzer.getResultCards();
  const totalCount = await resultCards.count();
  expect(totalCount).toBeGreaterThan(0);

  await page.evaluate(() => {
    document.querySelectorAll('[data-testid^="test-result-toggle-"]').forEach((node) => {
      if (node.getAttribute("aria-expanded") !== "true") {
        (node as HTMLButtonElement).click();
      }
    });
  });

  const toggleLocator = page.locator('[data-testid^="test-result-toggle-"]');
  await expect.poll(async () => {
    return toggleLocator.evaluateAll((nodes) => {
      return nodes.filter((node) => node.getAttribute("aria-expanded") === "true").length;
    });
  }).toBe(totalCount);

  await page.evaluate(() => {
    document.querySelectorAll('[data-testid^="test-result-toggle-"]').forEach((node) => {
      if (node.getAttribute("aria-expanded") === "true") {
        (node as HTMLButtonElement).click();
      }
    });
  });

  await expect.poll(async () => {
    return toggleLocator.evaluateAll((nodes) => {
      return nodes.filter((node) => node.getAttribute("aria-expanded") === "true").length;
    });
  }).toBe(0);

  const firstTestName = await resultCards.first().locator("button span").first().textContent();
  const query = deriveSearchQuery(firstTestName);
  if (!query) {
    throw new Error("Unable to derive report search query.");
  }

  const searchInput = page.getByTestId("report-search-input");
  const searchCount = page.getByTestId("report-search-count");
  const initialCounts = parseCount(await searchCount.textContent());
  expect(initialCounts.match).toBe(totalCount);
  expect(initialCounts.total).toBe(totalCount);

  await searchInput.fill(query);

  await expect.poll(async () => resultCards.count()).toBeGreaterThan(0);
  const filteredCount = await resultCards.count();
  const filteredCounts = parseCount(await searchCount.textContent());

  expect(filteredCounts.total).toBeGreaterThan(0);
  expect(filteredCounts.match).toBe(filteredCount);
  expect(filteredCounts.total).toBe(totalCount);
  if (totalCount > 1) {
    expect(filteredCount).toBeLessThan(totalCount);
    expect(filteredCounts.match).not.toBe(initialCounts.match);
  }

  await page.getByRole("button", { name: "Clear search" }).click();

  await expect.poll(async () => resultCards.count()).toBe(totalCount);
  const clearedCounts = parseCount(await searchCount.textContent());
  expect(clearedCounts.match).toBe(totalCount);

  const jsonDownload = await analyzer.exportJson();
  expect(jsonDownload.suggestedFilename()).toBe("analysis-report.json");
  const jsonPath = await jsonDownload.path();
  if (!jsonPath) {
    throw new Error("JSON export did not provide a download path.");
  }
  const jsonContents = await fs.readFile(jsonPath, "utf8");
  const parsed = JSON.parse(jsonContents) as { metadata?: Record<string, unknown> };
  expect(parsed.metadata).toBeTruthy();

  const htmlDownload = await analyzer.exportHtml();
  expect(htmlDownload.suggestedFilename()).toBe("analysis-report.html");
  const htmlPath = await htmlDownload.path();
  if (!htmlPath) {
    throw new Error("HTML export did not provide a download path.");
  }
  const htmlContents = await fs.readFile(htmlPath, "utf8");
  expect(htmlContents).toContain("<title>Email Header Analysis Report</title>");
  expect(htmlContents).toContain("<style>");
  expect(htmlContents).toContain("summary-grid");
});
