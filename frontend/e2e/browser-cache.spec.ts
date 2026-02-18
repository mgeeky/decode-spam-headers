import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");

test("browser cache restores analysis and clears on demand", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);
  await analyzer.clickAnalyse();
  await analyzer.waitForResults();

  const headerInput = page.getByRole("textbox", { name: "Header Input" });
  const reportContainer = page.getByTestId("report-container");

  await expect(headerInput).toHaveValue(headers);
  await expect(reportContainer).toBeVisible();

  await page.reload();

  await expect(headerInput).toHaveValue(headers);
  await expect(reportContainer).toBeVisible();
  await expect(page.getByText("Cached Result")).toBeVisible();

  const clearCacheButton = page.getByRole("button", { name: "Clear Cache" });
  await expect(clearCacheButton).toBeEnabled();
  await analyzer.clearCache();

  await expect(headerInput).toHaveValue("");
  await expect(page.getByTestId("report-container")).toHaveCount(0);
  await expect(page.getByText("Cached Result")).toHaveCount(0);
  await expect(clearCacheButton).toBeDisabled();
  await expect(
    page.getByText("No cached analysis yet. Run an analysis to save this session."),
  ).toBeVisible();

  await page.reload();

  await expect(headerInput).toHaveValue("");
  await expect(page.getByTestId("report-container")).toHaveCount(0);
  await expect(page.getByText("Cached Result")).toHaveCount(0);
});
