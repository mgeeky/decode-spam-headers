import { test, expect, type Locator, type Page } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");

const viewports = [
  { width: 320, height: 900, label: "320" },
  { width: 768, height: 900, label: "768" },
  { width: 1024, height: 900, label: "1024" },
  { width: 1440, height: 900, label: "1440" },
  { width: 2560, height: 1200, label: "2560" },
];

const assertNoHorizontalOverflow = async (page: Page, label: string) => {
  const metrics = await page.evaluate(() => {
    const docEl = document.documentElement;
    const body = document.body;
    return {
      docScrollWidth: docEl.scrollWidth,
      docClientWidth: docEl.clientWidth,
      bodyScrollWidth: body.scrollWidth,
      bodyClientWidth: body.clientWidth,
    };
  });

  expect(metrics.docScrollWidth, `document overflow at ${label}px`).toBeLessThanOrEqual(
    metrics.docClientWidth,
  );
  expect(metrics.bodyScrollWidth, `body overflow at ${label}px`).toBeLessThanOrEqual(
    metrics.bodyClientWidth,
  );
};

const assertActionable = async (locator: Locator, label: string, viewportWidth: number) => {
  await locator.scrollIntoViewIfNeeded();
  await expect(locator, `${label} should be visible`).toBeVisible();
  await expect(locator, `${label} should be enabled`).toBeEnabled();
  await locator.click({ trial: true });

  const box = await locator.boundingBox();
  expect(box, `${label} missing layout box`).not.toBeNull();
  if (box) {
    expect(box.x, `${label} clipped on left`).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width, `${label} clipped on right`).toBeLessThanOrEqual(
      viewportWidth + 1,
    );
  }
};

const assertReadableText = async (page: Page, label: string) => {
  const overflowIds = await page.evaluate(() => {
    const selectors = [
      '[data-testid="test-selector"]',
      '[data-testid="report-container"]',
      '[data-testid="report-export"]',
      '[data-testid="report-search-bar"]',
    ];

    const offenders: string[] = [];
    for (const selector of selectors) {
      const element = document.querySelector(selector) as HTMLElement | null;
      if (!element) {
        continue;
      }
      if (element.scrollWidth > element.clientWidth + 1) {
        offenders.push(selector);
      }
    }

    const cards = Array.from(
      document.querySelectorAll('[data-testid^="test-result-card-"]'),
    ).slice(0, 3);
    cards.forEach((card, index) => {
      const element = card as HTMLElement;
      if (element.scrollWidth > element.clientWidth + 1) {
        offenders.push(`test-result-card-${index}`);
      }
    });

    return offenders;
  });

  expect(overflowIds, `text overflow detected at ${label}px`).toEqual([]);
};

const assertCardsStacked = async (page: Page, label: string, viewportWidth: number) => {
  const cards = page.locator('[data-testid^="test-result-card-"]');
  const count = await cards.count();
  if (count < 2) {
    throw new Error("Need at least 2 report cards to validate stacking.");
  }

  const firstBox = await cards.nth(0).boundingBox();
  const secondBox = await cards.nth(1).boundingBox();

  if (!firstBox || !secondBox) {
    throw new Error("Unable to read report card layout bounds.");
  }

  expect(
    secondBox.y,
    `report cards should stack vertically at ${label}px`,
  ).toBeGreaterThan(firstBox.y + firstBox.height - 4);

  const xDelta = Math.abs(secondBox.x - firstBox.x);
  expect(xDelta, `report cards should align at ${label}px`).toBeLessThanOrEqual(12);
  expect(firstBox.width, `report cards should use available width at ${label}px`).toBeGreaterThan(
    viewportWidth * 0.6,
  );
};

test("responsive layout remains usable across key breakpoints", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);
  await analyzer.clickAnalyse();
  await analyzer.waitForResults();

  const firstCheckbox = page.locator('[data-testid^="test-checkbox-"]').first();
  await expect(firstCheckbox).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole("button", { name: "Clear Cache" })).toBeEnabled();

  const reportContainer = page.getByTestId("report-container");
  await expect(reportContainer).toBeVisible();

  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.waitForTimeout(200);

    await assertNoHorizontalOverflow(page, viewport.label);
    await assertReadableText(page, viewport.label);

    await assertActionable(page.getByRole("textbox", { name: "Header Input" }), "Header input", viewport.width);
    await assertActionable(page.getByRole("button", { name: "Clear header input" }), "Clear header input", viewport.width);
    await assertActionable(page.getByRole("button", { name: "Analyse Headers" }), "Analyse button", viewport.width);
    await assertActionable(page.getByTestId("toggle-resolve"), "DNS toggle", viewport.width);
    await assertActionable(page.getByTestId("toggle-decode-all"), "Decode all toggle", viewport.width);
    await assertActionable(page.getByTestId("test-search-input"), "Test search input", viewport.width);
    await assertActionable(page.getByTestId("select-all-tests"), "Select all tests", viewport.width);
    await assertActionable(page.getByTestId("deselect-all-tests"), "Deselect all tests", viewport.width);
    await assertActionable(firstCheckbox, "First test checkbox", viewport.width);
    await assertActionable(page.getByTestId("report-search-input"), "Report search input", viewport.width);
    await assertActionable(page.getByTestId("report-export-json"), "Export JSON", viewport.width);
    await assertActionable(page.getByTestId("report-export-html"), "Export HTML", viewport.width);
    await assertActionable(page.getByRole("button", { name: "Clear Cache" }), "Clear cache button", viewport.width);

    if (viewport.width <= 768) {
      await assertCardsStacked(page, viewport.label, viewport.width);
    }
  }
});
