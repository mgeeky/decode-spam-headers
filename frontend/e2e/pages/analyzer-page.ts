import type { Download, Locator, Page } from "@playwright/test";
import fs from "fs/promises";
import path from "path";

const resolveMimeType = (fileName: string): string => {
  const extension = path.extname(fileName).toLowerCase();
  if (extension === ".eml") {
    return "message/rfc822";
  }
  return "text/plain";
};

export class AnalyzerPage {
  readonly page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  async goto(): Promise<void> {
    await this.page.goto("http://localhost:3100");
  }

  async pasteHeaders(text: string): Promise<void> {
    await this.headerInput().fill(text);
  }

  async dropFile(filePath: string): Promise<void> {
    const resolvedPath = path.resolve(filePath);
    const fileName = path.basename(resolvedPath);
    const mimeType = resolveMimeType(fileName);
    const fileBuffer = await fs.readFile(resolvedPath);
    const base64 = fileBuffer.toString("base64");

    await this.page.evaluate(
      ({ base64Data, name, type }) => {
        const binary = atob(base64Data);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
          bytes[index] = binary.charCodeAt(index);
        }
        const file = new File([bytes], name, { type });
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);

        const dropZone = document.querySelector('[data-testid="file-drop-zone"]');
        if (!dropZone) {
          throw new Error("File drop zone not found");
        }

        const dragOver = new DragEvent("dragover", {
          dataTransfer,
          bubbles: true,
          cancelable: true,
        });
        dropZone.dispatchEvent(dragOver);

        const drop = new DragEvent("drop", {
          dataTransfer,
          bubbles: true,
          cancelable: true,
        });
        dropZone.dispatchEvent(drop);
      },
      { base64Data: base64, name: fileName, type: mimeType },
    );
  }

  async clickAnalyse(): Promise<void> {
    await this.analyseButton().click();
  }

  async pressCtrlEnter(): Promise<void> {
    await this.page.keyboard.press("Control+Enter");
  }

  async selectTests(ids: number[]): Promise<void> {
    await this.page.getByTestId("test-selector").waitFor({ state: "visible" });
    for (const id of ids) {
      const checkbox = this.page.getByTestId(`test-checkbox-${id}`);
      await checkbox.scrollIntoViewIfNeeded();
      if (!(await checkbox.isChecked())) {
        await checkbox.check();
      }
    }
  }

  async deselectAll(): Promise<void> {
    await this.page.getByTestId("deselect-all-tests").click();
  }

  async selectAll(): Promise<void> {
    await this.page.getByTestId("select-all-tests").click();
  }

  async toggleDns(): Promise<void> {
    await this.page.getByTestId("toggle-resolve").click();
  }

  async toggleDecodeAll(): Promise<void> {
    await this.page.getByTestId("toggle-decode-all").click();
  }

  async waitForResults(): Promise<void> {
    await this.page.getByTestId("report-container").waitFor({
      state: "visible",
      timeout: 30000,
    });
  }

  getResultCards(): Locator {
    return this.page.locator('[data-testid^="test-result-card-"]');
  }

  async expandCard(index: number): Promise<void> {
    const toggle = this.getResultCards()
      .nth(index)
      .locator('[data-testid^="test-result-toggle-"]');
    await toggle.waitFor({ state: "visible" });
    const expanded = await toggle.getAttribute("aria-expanded");
    if (expanded !== "true") {
      await toggle.click();
    }
  }

  async collapseCard(index: number): Promise<void> {
    const toggle = this.getResultCards()
      .nth(index)
      .locator('[data-testid^="test-result-toggle-"]');
    await toggle.waitFor({ state: "visible" });
    const expanded = await toggle.getAttribute("aria-expanded");
    if (expanded === "true") {
      await toggle.click();
    }
  }

  async searchReport(query: string): Promise<void> {
    await this.page.getByTestId("report-search-input").fill(query);
  }

  async exportJson(): Promise<Download> {
    const [download] = await Promise.all([
      this.page.waitForEvent("download"),
      this.page.getByTestId("report-export-json").click(),
    ]);
    return download;
  }

  async exportHtml(): Promise<Download> {
    const [download] = await Promise.all([
      this.page.waitForEvent("download"),
      this.page.getByTestId("report-export-html").click(),
    ]);
    return download;
  }

  async clearCache(): Promise<void> {
    await this.page.getByRole("button", { name: "Clear Cache" }).click();
  }

  getCaptchaModal(): Locator {
    return this.page.getByTestId("captcha-challenge");
  }

  private headerInput(): Locator {
    return this.page.getByRole("textbox", { name: "Header Input" });
  }

  private analyseButton(): Locator {
    return this.page.getByRole("button", { name: "Analyse Headers" });
  }
}
