import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const emlPath = path.resolve(__dirname, "fixtures/sample.eml");

const extractHeaderBlock = (content: string): string => {
  const normalized = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalized.split("\n");
  const headerLines: string[] = [];

  for (const line of lines) {
    if (line.trim() === "") {
      break;
    }
    headerLines.push(line);
  }

  if (headerLines.length === 0) {
    return normalized.trim();
  }

  return headerLines.join("\n").trimEnd();
};

test("drop eml file populates headers and renders report", async ({ page }) => {
  const analyzer = new AnalyzerPage(page);
  const emlContents = await fs.readFile(emlPath, "utf8");
  const expectedHeaders = extractHeaderBlock(emlContents);

  await analyzer.goto();
  await analyzer.dropFile(emlPath);

  const headerInput = page.getByRole("textbox", { name: "Header Input" });
  await expect(headerInput).toHaveValue(expectedHeaders);

  await analyzer.clickAnalyse();
  await analyzer.waitForResults();

  await expect(analyzer.getResultCards().first()).toBeVisible();
});

test("rejects unsupported file types", async ({ page }, testInfo) => {
  const analyzer = new AnalyzerPage(page);
  const invalidPath = testInfo.outputPath("unsupported.pdf");
  await fs.writeFile(invalidPath, "%PDF-1.4 fake pdf content");

  await analyzer.goto();
  await analyzer.dropFile(invalidPath, "application/pdf");

  const alert = page
    .locator('p[role="alert"]')
    .filter({ hasText: "Only .eml or .txt files are supported." });
  await expect(alert).toBeVisible();

  const headerInput = page.getByRole("textbox", { name: "Header Input" });
  await expect(headerInput).toHaveValue("");
});
