"use client";

import { useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faBan,
  faCheck,
  faCircleInfo,
  faTriangleExclamation,
  faChevronDown,
} from "@fortawesome/free-solid-svg-icons";

import type { TestResult, TestSeverity } from "../../types/analysis";

const severityStyles: Record<
  TestSeverity,
  { label: string; className: string; icon: typeof faBan }
> = {
  spam: { label: "Spam", className: "text-spam border-spam/40", icon: faBan },
  suspicious: {
    label: "Suspicious",
    className: "text-suspicious border-suspicious/40",
    icon: faTriangleExclamation,
  },
  clean: { label: "Clean", className: "text-clean border-clean/40", icon: faCheck },
  info: { label: "Info", className: "text-accent border-accent/40", icon: faCircleInfo },
};

const getErrorMessage = (result: TestResult): string => {
  const message = result.error?.trim();
  return message && message.length > 0 ? message : "Unknown failure.";
};

type TestResultCardProps = {
  result: TestResult;
};

export default function TestResultCard({ result }: TestResultCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const severityStyle = severityStyles[result.severity];
  const detailsId = `test-result-details-${result.testId}`;

  const toggle = () => {
    setIsExpanded((previous) => !previous);
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle();
    }
  };

  return (
    <article
      data-testid={`test-result-${result.testId}`}
      className="rounded-2xl border border-info/10 bg-surface/50 p-4 shadow-[0_0_30px_rgba(15,23,42,0.18)]"
    >
      <button
        type="button"
        data-testid={`test-result-toggle-${result.testId}`}
        aria-expanded={isExpanded}
        aria-controls={detailsId}
        onClick={toggle}
        onKeyDown={handleKeyDown}
        className="flex w-full items-center justify-between gap-4 text-left"
      >
        <div className="flex flex-col">
          <span className="text-sm font-semibold text-text/90">{result.testName}</span>
          <span className="text-xs text-text/50">Test #{result.testId}</span>
        </div>
        <div className="flex items-center gap-3">
          <span
            data-testid={`test-result-severity-${result.testId}`}
            className={`flex items-center gap-2 rounded-full border px-2 py-1 text-[11px] uppercase tracking-[0.2em] ${severityStyle.className}`}
          >
            <FontAwesomeIcon icon={severityStyle.icon} className="text-[10px]" />
            {severityStyle.label}
          </span>
          <FontAwesomeIcon
            icon={faChevronDown}
            className={`text-xs text-text/60 transition-transform duration-300 ${
              isExpanded ? "rotate-180" : "rotate-0"
            }`}
          />
        </div>
      </button>

      <div
        id={detailsId}
        className={`mt-3 grid transition-[grid-template-rows,opacity] duration-300 ease-out ${
          isExpanded ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"
        }`}
      >
        <div className="overflow-hidden">
          <div className="rounded-xl border border-info/10 bg-background/40 p-3">
            <div className="flex flex-col gap-1">
              <span className="text-[10px] uppercase tracking-[0.2em] text-text/40">
                Header
              </span>
              <span className="text-xs text-text/60">{result.headerName}</span>
              <span className="font-mono text-sm text-text/80">{result.headerValue}</span>
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
                data-testid={`test-result-error-${result.testId}`}
                className="mt-3 flex items-start gap-2 rounded-xl border border-spam/30 bg-spam/10 p-3 text-xs text-spam"
              >
                <FontAwesomeIcon icon={faTriangleExclamation} className="mt-0.5" />
                <span>
                  <span className="font-semibold">Error:</span> {getErrorMessage(result)}
                </span>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </article>
  );
}
