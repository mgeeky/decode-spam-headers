import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

const headersPath = path.resolve(__dirname, "../../backend/tests/fixtures/sample_headers.txt");

const viewports = [
  { width: 320, height: 900, label: "320" },
  { width: 768, height: 900, label: "768" },
  { width: 1024, height: 900, label: "1024" },
  { width: 1440, height: 900, label: "1440" },
  { width: 2560, height: 1200, label: "2560" },
];

test("responsive layout has no horizontal overflow at key breakpoints", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");

  await page.goto("http://localhost:3100");

  const headerInput = page.getByRole("textbox", { name: "Header Input" });
  await headerInput.fill(headers);

  await page.getByRole("button", { name: "Analyse Headers" }).click();

  const reportContainer = page.getByTestId("report-container");
  await reportContainer.waitFor({ state: "visible", timeout: 30000 });

  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.waitForTimeout(200);

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

    expect(
      metrics.docScrollWidth,
      `documentElement overflow at ${viewport.label}px width`,
    ).toBeLessThanOrEqual(metrics.docClientWidth);

    expect(
      metrics.bodyScrollWidth,
      `body overflow at ${viewport.label}px width`,
    ).toBeLessThanOrEqual(metrics.bodyClientWidth);

    await expect(headerInput).toBeVisible();
    await expect(reportContainer).toBeVisible();
  }
});
