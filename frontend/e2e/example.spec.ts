import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

const headersPath = path.resolve(__dirname, "../../backend/tests/fixtures/sample_headers.txt");

test("complete analysis flow from paste to export", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");

  await page.goto("http://localhost:3100");

  const headerInput = page.getByRole("textbox", { name: "Header Input" });
  await headerInput.fill(headers);

  const decodeToggle = page.getByTestId("toggle-decode-all");
  await decodeToggle.click();
  await expect(decodeToggle).toHaveAttribute("aria-checked", "true");

  const firstCheckbox = page.locator('[data-testid^="test-checkbox-"]').first();
  await firstCheckbox.scrollIntoViewIfNeeded();
  await firstCheckbox.waitFor({ state: "visible" });
  await firstCheckbox.check();

  const checkboxTestId = await firstCheckbox.getAttribute("data-testid");
  const testId = checkboxTestId?.replace("test-checkbox-", "");
  expect(testId).toBeTruthy();

  await page.getByRole("button", { name: "Analyse Headers" }).click();

  const reportContainer = page.getByTestId("report-container");
  await reportContainer.waitFor({ state: "visible", timeout: 30000 });

  if (testId) {
    await expect(page.getByTestId(`test-result-card-${testId}`)).toBeVisible();
  }

  const [jsonDownload] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("report-export-json").click(),
  ]);
  expect(jsonDownload.suggestedFilename()).toBe("analysis-report.json");
  const jsonPath = await jsonDownload.path();
  if (!jsonPath) {
    throw new Error("JSON export did not provide a download path.");
  }
  const jsonContents = await fs.readFile(jsonPath, "utf8");
  const parsed = JSON.parse(jsonContents) as { metadata?: Record<string, unknown> };
  expect(parsed.metadata).toBeTruthy();

  const [htmlDownload] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("report-export-html").click(),
  ]);
  expect(htmlDownload.suggestedFilename()).toBe("analysis-report.html");
  const htmlPath = await htmlDownload.path();
  if (!htmlPath) {
    throw new Error("HTML export did not provide a download path.");
  }
  const htmlContents = await fs.readFile(htmlPath, "utf8");
  expect(htmlContents).toContain("<title>Email Header Analysis Report</title>");
});

test("cache flow persists report across reloads and clears on demand", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");

  await page.goto("http://localhost:3100");

  const headerInput = page.getByRole("textbox", { name: "Header Input" });
  await headerInput.fill(headers);

  await page.getByRole("button", { name: "Analyse Headers" }).click();

  const reportContainer = page.getByTestId("report-container");
  await reportContainer.waitFor({ state: "visible", timeout: 30000 });

  await page.reload();

  await expect(page.getByTestId("report-container")).toBeVisible();
  await expect(page.getByText("Cached Result")).toBeVisible();

  const clearCacheButton = page.getByRole("button", { name: "Clear Cache" });
  await clearCacheButton.click();

  await expect(page.getByTestId("report-container")).toHaveCount(0);
  await expect(headerInput).toHaveValue("");
});
