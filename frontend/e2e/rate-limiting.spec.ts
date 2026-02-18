import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

import { AnalyzerPage } from "./pages/analyzer-page";

const headersPath = path.resolve(__dirname, "fixtures/sample-headers.txt");
const rateLimit = 3;
const bypassToken = "playwright-bypass-token";
const captchaChallenge = {
  challengeToken: "playwright-challenge-token",
  imageBase64:
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFgwJ/l0pNqQAAAABJRU5ErkJggg==",
};
const successReport = {
  results: [],
  hopChain: [],
  securityAppliances: [],
  metadata: {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    elapsedMs: 1,
    timedOut: false,
    incompleteTests: [] as string[],
  },
};

const corsHeaders = {
  "access-control-allow-origin": "http://localhost:3100",
  "access-control-allow-credentials": "true",
};

const successSseBody = `event: result\ndata: ${JSON.stringify(successReport)}\n\n`;

test("rate limiting shows captcha and retries successfully", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  const analyzer = new AnalyzerPage(page);
  let analyseCount = 0;
  const bypassTokens: string[] = [];

  await page.route("**/api/analyse", async (route) => {
    analyseCount += 1;
    const bypassHeader = route.request().headers()["x-captcha-bypass-token"];
    if (bypassHeader) {
      bypassTokens.push(bypassHeader);
    }

    if (analyseCount === rateLimit + 1) {
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
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      headers: corsHeaders,
      body: successSseBody,
    });
  });

  await page.route("**/api/captcha/verify", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: corsHeaders,
      body: JSON.stringify({ success: true, bypassToken }),
    });
  });

  await analyzer.goto();
  await analyzer.pasteHeaders(headers);

  const analyseButton = page.getByRole("button", { name: "Analyse Headers" });

  const runAnalysis = async () => {
    const responsePromise = page.waitForResponse(
      (response) => response.url().includes("/api/analyse") && response.status() === 200,
    );
    await expect(analyseButton).toBeEnabled({ timeout: 30000 });
    await analyseButton.click();
    await responsePromise;
    await expect(analyseButton).toBeEnabled({ timeout: 30000 });
  };

  for (let attempt = 0; attempt < rateLimit; attempt += 1) {
    await runAnalysis();
  }

  const [rateLimitResponse] = await Promise.all([
    page.waitForResponse(
      (response) => response.url().includes("/api/analyse") && response.status() === 429,
    ),
    analyseButton.click(),
  ]);

  expect(rateLimitResponse.status()).toBe(429);

  const captchaModal = analyzer.getCaptchaModal();
  await expect(captchaModal).toBeVisible();

  const captchaTitle = page.getByRole("heading", { name: "Security Check Required" });
  const captchaImage = page.getByTestId("captcha-image");
  const captchaInput = page.getByTestId("captcha-input");
  const captchaClose = page.getByTestId("captcha-close");
  const captchaSubmit = page.getByTestId("captcha-submit");

  await expect(captchaTitle).toBeVisible();
  await expect(captchaImage).toBeVisible();
  await expect(captchaImage).toHaveAttribute("src", /^data:image\/png;base64,/);
  await expect(captchaClose).toBeVisible();
  await expect(captchaSubmit).toBeVisible();
  await expect(captchaInput).toBeFocused();

  await page.keyboard.press("Shift+Tab");
  await expect(captchaClose).toBeFocused();

  await page.keyboard.press("Shift+Tab");
  await expect(captchaSubmit).toBeFocused();

  await page.keyboard.press("Tab");
  await expect(captchaClose).toBeFocused();

  await captchaInput.focus();
  await captchaInput.fill("12345");

  const retryResponsePromise = page.waitForResponse((response) => {
    if (!response.url().includes("/api/analyse")) {
      return false;
    }
    if (response.status() !== 200) {
      return false;
    }
    const bypassHeader = response.request().headers()["x-captcha-bypass-token"];
    return bypassHeader === bypassToken;
  });

  await page.keyboard.press("Enter");

  const retryResponse = await retryResponsePromise;
  expect(retryResponse.status()).toBe(200);

  await expect(captchaModal).toBeHidden({ timeout: 30000 });
  await expect(analyseButton).toBeEnabled({ timeout: 30000 });

  const followUpResponsePromise = page.waitForResponse((response) => {
    if (!response.url().includes("/api/analyse")) {
      return false;
    }
    if (response.status() !== 200) {
      return false;
    }
    const bypassHeader = response.request().headers()["x-captcha-bypass-token"];
    return bypassHeader === bypassToken;
  });

  await analyseButton.click();
  await followUpResponsePromise;

  const bypassHits = bypassTokens.filter((token) => token === bypassToken);
  expect(bypassHits.length).toBeGreaterThanOrEqual(2);
  await expect(analyseButton).toBeEnabled({ timeout: 30000 });
});
