import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

const headersPath = path.resolve(__dirname, "../../backend/tests/fixtures/sample_headers.txt");
const rateLimit = 3;
const bypassToken = "playwright-bypass-token";
const captchaChallenge = {
  challengeToken: "playwright-challenge-token",
  imageBase64:
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFgwJ/l0pNqQAAAABJRU5ErkJggg==",
};

test("rate limiting shows captcha and retries successfully", async ({ page }) => {
  const headers = await fs.readFile(headersPath, "utf8");
  let analyseCount = 0;

  await page.route("**/api/analyse", async (route) => {
    analyseCount += 1;
    if (analyseCount === rateLimit + 1) {
      await route.fulfill({
        status: 429,
        contentType: "application/json",
        headers: {
          "access-control-allow-origin": "http://localhost:3100",
          "access-control-allow-credentials": "true",
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
    await route.continue();
  });

  await page.route("**/api/captcha/verify", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: {
        "access-control-allow-origin": "http://localhost:3100",
        "access-control-allow-credentials": "true",
      },
      body: JSON.stringify({ success: true, bypassToken }),
    });
  });

  await page.goto("http://localhost:3100");

  const headerInput = page.getByRole("textbox", { name: "Header Input" });
  await headerInput.fill(headers);

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

  const captchaModal = page.getByTestId("captcha-challenge");
  await expect(captchaModal).toBeVisible();

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

  await page.getByTestId("captcha-input").fill("12345");
  await page.getByTestId("captcha-submit").click();

  const retryResponse = await retryResponsePromise;
  expect(retryResponse.status()).toBe(200);

  await expect(captchaModal).toBeHidden({ timeout: 30000 });
  await expect(analyseButton).toBeEnabled({ timeout: 30000 });
});
