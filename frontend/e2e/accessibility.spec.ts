import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");
const axeTags = ["wcag2a", "wcag2aa", "wcag21aa"];

const runAxeAudit = async (page: Page) => {
  const results = await new AxeBuilder({ page }).withTags(axeTags).analyze();
  expect(results.violations).toEqual([]);
};

test("accessibility audit covers landing page states", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();
  await expect(page.getByRole("textbox", { name: "Header Input" })).toBeVisible();
  await runAxeAudit(page);

  await analyzer.pasteHeaders(headers);
  await runAxeAudit(page);
});

test("accessibility audit covers report view", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);
  await analyzer.clickAnalyse();
  await analyzer.waitForResults();

  await runAxeAudit(page);
});

test("accessibility audit covers captcha modal", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  const captchaChallenge = {
    challengeToken: "playwright-challenge-token",
    imageBase64:
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFgwJ/l0pNqQAAAABJRU5ErkJggg==",
  };

  const corsHeaders = {
    "access-control-allow-origin": "http://localhost:3100",
    "access-control-allow-credentials": "true",
  };

  await page.route("**/api/analyse", async (route) => {
    await route.fulfill({
      status: 429,
      contentType: "application/json",
      headers: {
        ...corsHeaders,
        "retry-after": "60",
      },
      body: JSON.stringify({
        error: "Too many requests",
        retryAfter: 60,
        captchaChallenge,
      }),
    });
  });

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);
  await analyzer.clickAnalyse();

  await expect(analyzer.getCaptchaModal()).toBeVisible();
  await runAxeAudit(page);
});
