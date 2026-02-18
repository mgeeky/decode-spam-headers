"use client";

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTriangleExclamation } from "@fortawesome/free-solid-svg-icons";

import type { AnalysisReport, TestResult, TestSeverity, TestStatus } from "../types/analysis";

type AnalysisResultsProps = {
  report: AnalysisReport;
};

const severityStyles: Record<TestSeverity, { label: string; className: string }> = {
  spam: { label: "Spam", className: "text-spam border-spam/40" },
  suspicious: { label: "Suspicious", className: "text-suspicious border-suspicious/40" },
  clean: { label: "Clean", className: "text-clean border-clean/40" },
  info: { label: "Info", className: "text-accent border-accent/40" },
};

const statusStyles: Record<TestStatus, { label: string; className: string }> = {
  success: { label: "Success", className: "text-clean border-clean/40" },
  error: { label: "Error", className: "text-spam border-spam/40" },
  skipped: { label: "Skipped", className: "text-suspicious border-suspicious/40" },
};

const getErrorMessage = (result: TestResult): string => {
  const message = result.error?.trim();
  return message && message.length > 0 ? message : "Unknown failure.";
};

export default function AnalysisResults({ report }: AnalysisResultsProps) {
  return (
    <section
      data-testid="analysis-results"
      className="rounded-2xl border border-info/10 bg-surface p-6 shadow-[0_0_40px_rgba(15,23,42,0.25)]"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs uppercase tracking-[0.2em] text-info/90">Analysis Report</span>
        <span className="font-mono text-[10px] text-text/50">
          {report.metadata.passedTests} passed / {report.metadata.failedTests} failed
        </span>
      </div>

      <ul className="mt-4 space-y-4">
        {report.results.map((result) => {
          const statusStyle = statusStyles[result.status];
          const severityStyle = severityStyles[result.severity];

          return (
            <li
              key={result.testId}
              data-testid={`analysis-result-${result.testId}`}
              className="rounded-2xl border border-info/10 bg-background/40 p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-col">
                  <span className="text-sm font-semibold text-text/90">{result.testName}</span>
                  <span className="text-xs text-text/50">
                    Test #{result.testId} · {result.headerName}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-[11px] uppercase tracking-[0.2em]">
                  <span className={`rounded-full border px-2 py-1 ${statusStyle.className}`}>
                    {statusStyle.label}
                  </span>
                  <span className={`rounded-full border px-2 py-1 ${severityStyle.className}`}>
                    {severityStyle.label}
                  </span>
                </div>
              </div>

              {result.analysis ? (
                <p className="mt-3 text-sm text-text/70">{result.analysis}</p>
              ) : null}
              {result.description ? (
                <p className="mt-1 text-xs text-text/50">{result.description}</p>
              ) : null}

              {result.status === "error" ? (
                <div
                  role="alert"
                  data-testid={`analysis-error-${result.testId}`}
                  className="mt-3 flex items-start gap-2 rounded-xl border border-spam/30 bg-spam/10 p-3 text-xs text-spam"
                >
                  <FontAwesomeIcon icon={faTriangleExclamation} className="mt-0.5" />
                  <span>
                    <span className="font-semibold">Error:</span> {getErrorMessage(result)}
                  </span>
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
