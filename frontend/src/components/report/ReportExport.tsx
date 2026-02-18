"use client";

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload, faFileCode } from "@fortawesome/free-solid-svg-icons";

import type { AnalysisReport, TestResult, TestSeverity } from "../../types/analysis";

type ReportExportProps = {
  report: AnalysisReport;
};

const severityStyles: Record<TestSeverity, { label: string; color: string }> = {
  spam: { label: "Spam", color: "#ff5555" },
  suspicious: { label: "Suspicious", color: "#ffb86c" },
  clean: { label: "Clean", color: "#50fa7b" },
  info: { label: "Info", color: "#bd93f9" },
};

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");

const getErrorMessage = (result: TestResult): string => {
  const message = result.error?.trim();
  return message && message.length > 0 ? message : "Unknown failure.";
};

const formatElapsed = (elapsedMs: number): string => {
  if (Number.isNaN(elapsedMs)) {
    return "-";
  }
  return `${(elapsedMs / 1000).toFixed(2)}s`;
};

const countBySeverity = (results: TestResult[]): Record<TestSeverity, number> =>
  results.reduce(
    (accumulator, result) => {
      accumulator[result.severity] += 1;
      return accumulator;
    },
    { spam: 0, suspicious: 0, clean: 0, info: 0 },
  );

const buildHtmlReport = (report: AnalysisReport): string => {
  const severityCounts = countBySeverity(report.results);
  const generatedAt = new Date().toISOString();

  const renderResult = (result: TestResult): string => {
    const severity = severityStyles[result.severity];

    return `
      <article class="card">
        <header class="card-header">
          <div class="title-block">
            <span class="badge" style="color: ${severity.color}; border-color: ${severity.color}33;">
              ${severity.label}
            </span>
            <span class="test-name">${escapeHtml(result.testName)}</span>
            <span class="test-meta">Test #${result.testId}</span>
          </div>
          <span class="status ${result.status === "error" ? "status-error" : "status-ok"}">
            ${escapeHtml(result.status)}
          </span>
        </header>
        <section class="card-body">
          <div class="header-block">
            <span class="label">Header</span>
            <span class="header-name">${escapeHtml(result.headerName)}</span>
            <pre class="header-value">${escapeHtml(result.headerValue)}</pre>
          </div>
          ${result.analysis ? `<p class="analysis">${escapeHtml(result.analysis)}</p>` : ""}
          ${result.description ? `<p class="description">${escapeHtml(result.description)}</p>` : ""}
          ${
            result.status === "error"
              ? `<div class="error">Error: ${escapeHtml(getErrorMessage(result))}</div>`
              : ""
          }
        </section>
      </article>
    `;
  };

  const renderHopChain = (): string => {
    if (report.hopChain.length === 0) {
      return '<p class="muted">No hop chain data available.</p>';
    }

    const items = report.hopChain
      .map((node) => {
        const parts = [
          escapeHtml(node.hostname),
          node.ip ? `<span class=\"mono\">${escapeHtml(node.ip)}</span>` : "",
          node.timestamp ? `<span>${escapeHtml(node.timestamp)}</span>` : "",
          node.serverInfo ? `<span>${escapeHtml(node.serverInfo)}</span>` : "",
        ]
          .filter((part) => part.length > 0)
          .join(" · ");
        return `<li>${parts}</li>`;
      })
      .join("");

    return `<ol class=\"hop-chain\">${items}</ol>`;
  };

  const renderSecurityAppliances = (): string => {
    if (report.securityAppliances.length === 0) {
      return '<p class="muted">No security appliances detected.</p>';
    }

    const items = report.securityAppliances
      .map((appliance) => {
        return `<span class=\"pill\">${escapeHtml(appliance.name)}</span>`;
      })
      .join("");

    return `<div class=\"pill-row\">${items}</div>`;
  };

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Email Header Analysis Report</title>
    <style>
      :root {
        color-scheme: dark;
        --background: #1e1e2e;
        --surface: #282a36;
        --text: #f8f8f2;
        --muted: rgba(248, 248, 242, 0.6);
        --border: rgba(139, 233, 253, 0.2);
        --accent: #8be9fd;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        padding: 32px 20px;
        background: var(--background);
        color: var(--text);
        font-family: "Geist", "Segoe UI", system-ui, sans-serif;
        line-height: 1.5;
      }

      main {
        max-width: 960px;
        margin: 0 auto;
        display: flex;
        flex-direction: column;
        gap: 24px;
      }

      h1 {
        font-size: 26px;
        margin: 0 0 4px;
      }

      h2 {
        font-size: 18px;
        margin: 0 0 12px;
      }

      .muted {
        color: var(--muted);
        font-size: 13px;
      }

      .section {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 20px;
      }

      .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 12px;
      }

      .summary-item {
        border-radius: 12px;
        padding: 12px;
        background: rgba(30, 30, 46, 0.7);
        border: 1px solid rgba(139, 233, 253, 0.15);
      }

      .summary-item span {
        display: block;
        font-size: 12px;
        color: var(--muted);
        margin-bottom: 6px;
      }

      .summary-item strong {
        font-size: 18px;
      }

      .card {
        border-radius: 16px;
        padding: 16px;
        background: rgba(30, 30, 46, 0.7);
        border: 1px solid rgba(139, 233, 253, 0.15);
        display: flex;
        flex-direction: column;
        gap: 12px;
      }

      .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        flex-wrap: wrap;
      }

      .title-block {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        align-items: center;
      }

      .badge {
        padding: 4px 10px;
        border-radius: 999px;
        border: 1px solid;
        font-size: 11px;
        letter-spacing: 0.2em;
        text-transform: uppercase;
      }

      .test-name {
        font-weight: 600;
      }

      .test-meta {
        font-size: 12px;
        color: var(--muted);
      }

      .status {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.2em;
        padding: 4px 10px;
        border-radius: 999px;
        border: 1px solid;
      }

      .status-ok {
        color: #50fa7b;
        border-color: rgba(80, 250, 123, 0.4);
      }

      .status-error {
        color: #ff5555;
        border-color: rgba(255, 85, 85, 0.4);
      }

      .header-block {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .label {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.2em;
        color: var(--muted);
      }

      .header-name {
        font-size: 13px;
        color: var(--muted);
      }

      .header-value {
        margin: 0;
        padding: 10px;
        border-radius: 10px;
        background: rgba(40, 42, 54, 0.9);
        color: var(--text);
        font-family: "Geist Mono", "Consolas", monospace;
        white-space: pre-wrap;
        font-size: 13px;
      }

      .analysis,
      .description {
        margin: 0;
        font-size: 13px;
        color: var(--muted);
        white-space: pre-wrap;
      }

      .error {
        background: rgba(255, 85, 85, 0.12);
        border: 1px solid rgba(255, 85, 85, 0.4);
        color: #ff9c9c;
        padding: 10px 12px;
        border-radius: 12px;
        font-size: 12px;
      }

      .hop-chain {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      .hop-chain li {
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid rgba(139, 233, 253, 0.15);
        background: rgba(30, 30, 46, 0.6);
        font-size: 13px;
      }

      .pill-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .pill {
        padding: 6px 12px;
        border-radius: 999px;
        border: 1px solid rgba(139, 233, 253, 0.3);
        font-size: 12px;
        background: rgba(139, 233, 253, 0.1);
      }

      .mono {
        font-family: "Geist Mono", "Consolas", monospace;
      }

      @media (max-width: 600px) {
        body {
          padding: 20px 12px;
        }
      }
    </style>
  </head>
  <body>
    <main>
      <header class="section">
        <h1>Email Header Analysis Report</h1>
        <p class="muted">Generated at ${escapeHtml(generatedAt)}</p>
      </header>

      <section class="section">
        <h2>Summary</h2>
        <div class="summary-grid">
          <div class="summary-item">
            <span>Total tests</span>
            <strong>${report.metadata.totalTests}</strong>
          </div>
          <div class="summary-item">
            <span>Passed</span>
            <strong>${report.metadata.passedTests}</strong>
          </div>
          <div class="summary-item">
            <span>Failed</span>
            <strong>${report.metadata.failedTests}</strong>
          </div>
          <div class="summary-item">
            <span>Skipped</span>
            <strong>${report.metadata.skippedTests}</strong>
          </div>
          <div class="summary-item">
            <span>Elapsed</span>
            <strong>${formatElapsed(report.metadata.elapsedMs)}</strong>
          </div>
          <div class="summary-item">
            <span>Spam</span>
            <strong>${severityCounts.spam}</strong>
          </div>
          <div class="summary-item">
            <span>Suspicious</span>
            <strong>${severityCounts.suspicious}</strong>
          </div>
          <div class="summary-item">
            <span>Clean</span>
            <strong>${severityCounts.clean}</strong>
          </div>
          <div class="summary-item">
            <span>Info</span>
            <strong>${severityCounts.info}</strong>
          </div>
        </div>
      </section>

      <section class="section">
        <h2>Security Appliances</h2>
        ${renderSecurityAppliances()}
      </section>

      <section class="section">
        <h2>Hop Chain</h2>
        ${renderHopChain()}
      </section>

      <section class="section">
        <h2>Test Results</h2>
        ${report.results.map(renderResult).join("")}
      </section>
    </main>
  </body>
</html>`;
};

const downloadBlob = (content: string, mimeType: string, fileName: string) => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = "noopener";
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
};

export default function ReportExport({ report }: ReportExportProps) {
  const handleJsonExport = () => {
    downloadBlob(
      JSON.stringify(report, null, 2),
      "application/json;charset=utf-8",
      "analysis-report.json",
    );
  };

  const handleHtmlExport = () => {
    downloadBlob(buildHtmlReport(report), "text/html;charset=utf-8", "analysis-report.html");
  };

  return (
    <section
      data-testid="report-export"
      className="rounded-2xl border border-info/10 bg-surface/50 p-4 shadow-[0_0_30px_rgba(15,23,42,0.18)]"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-text/90">Export Report</h3>
          <p className="text-xs text-text/50">
            Download a standalone HTML snapshot or raw JSON data.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            data-testid="report-export-json"
            onClick={handleJsonExport}
            className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/40 px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
            aria-label="Export report as JSON"
          >
            <FontAwesomeIcon icon={faFileCode} className="text-[10px]" />
            JSON
          </button>
          <button
            type="button"
            data-testid="report-export-html"
            onClick={handleHtmlExport}
            className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/40 px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
            aria-label="Export report as HTML"
          >
            <FontAwesomeIcon icon={faDownload} className="text-[10px]" />
            HTML
          </button>
        </div>
      </div>
    </section>
  );
}
