import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");

const viewports = [
  { width: 320, height: 568, label: "320x568" },
  { width: 768, height: 1024, label: "768x1024" },
  { width: 1280, height: 720, label: "1280x720" },
  { width: 2560, height: 1080, label: "2560x1080" },
];

const baseScreenshotOptions = {
  animations: "disabled" as const,
  fullPage: true,
};

test.describe("visual regression snapshots", () => {
  for (const viewport of viewports) {
    test(`visual baselines at ${viewport.label}`, async ({ page }) => {
      const headers = await fs.readFile(headersPath, "utf8");
      const analyzer = new AnalyzerPage(page);

      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await analyzer.goto();

      const headerInput = page.getByRole("textbox", { name: "Header Input" });
      await headerInput.waitFor({ state: "visible" });

      await page.evaluate(() => window.scrollTo(0, 0));
      await expect(page).toHaveScreenshot(
        `landing-empty-${viewport.label}.png`,
        baseScreenshotOptions,
      );

      await analyzer.pasteHeaders(headers);
      await page.evaluate(() => window.scrollTo(0, 0));
      await expect(page).toHaveScreenshot(
        `landing-filled-${viewport.label}.png`,
        baseScreenshotOptions,
      );

      await analyzer.clickAnalyse();
      const progressIndicator = page.getByTestId("progress-indicator");
      await expect(progressIndicator).toBeVisible({ timeout: 30000 });

      await page.waitForFunction(() => {
        const node = document.querySelector('[data-testid="progress-percentage"]');
        if (!node) {
          return false;
        }
        const value = Number((node.textContent ?? "").replace("%", "").trim());
        return Number.isFinite(value) && value >= 1;
      });

      await page.evaluate(() => window.scrollTo(0, 0));
      await expect(page).toHaveScreenshot(`progress-${viewport.label}.png`, {
        ...baseScreenshotOptions,
        mask: [
          page.getByTestId("progress-elapsed"),
          page.getByTestId("progress-remaining"),
          page.getByTestId("progress-percentage"),
          page.getByTestId("progress-current-test"),
        ],
      });

      await analyzer.waitForResults();

      const resultCards = analyzer.getResultCards();
      const totalCards = await resultCards.count();
      const expandCount = Math.min(totalCards, 3);

      for (let index = 0; index < expandCount; index += 1) {
        await analyzer.expandCard(index);
      }

      await page.waitForTimeout(200);
      await page.evaluate(() => window.scrollTo(0, 0));
      await expect(page).toHaveScreenshot(
        `report-expanded-${viewport.label}.png`,
        baseScreenshotOptions,
      );

      const hopChain = page.getByTestId("hop-chain-visualisation");
      await hopChain.scrollIntoViewIfNeeded();
      await expect(hopChain).toBeVisible();
      await expect(hopChain).toHaveScreenshot(`hop-chain-${viewport.label}.png`, {
        animations: "disabled",
      });
    });
  }
});
