"use client";

import { useMemo, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faBan,
  faCheck,
  faCircleInfo,
  faListCheck,
  faTriangleExclamation,
  faXmark,
} from "@fortawesome/free-solid-svg-icons";

import type { AnalysisReport, TestResult, TestSeverity } from "../../types/analysis";
import HopChainVisualisation from "./HopChainVisualisation";
import ReportExport from "./ReportExport";
import ReportSearchBar from "./ReportSearchBar";
import SecurityAppliancesSummary from "./SecurityAppliancesSummary";
import TestResultCard from "./TestResultCard";

type SummaryItem = {
  label: string;
  value: number;
  testId: string;
  icon: typeof faCheck;
  iconClassName: string;
};

const countBySeverity = (results: TestResult[]): Record<TestSeverity, number> =>
  results.reduce(
    (accumulator, result) => {
      accumulator[result.severity] += 1;
      return accumulator;
    },
    { spam: 0, suspicious: 0, clean: 0, info: 0 },
  );

const filterResults = (query: string, results: TestResult[]): TestResult[] => {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return results;
  }

  return results.filter((result) => {
    return (
      result.testName.toLowerCase().includes(normalizedQuery) ||
      result.headerName.toLowerCase().includes(normalizedQuery) ||
      result.analysis.toLowerCase().includes(normalizedQuery)
    );
  });
};

export default function ReportContainer({ report }: { report: AnalysisReport }) {
  const [query, setQuery] = useState("");

  const severityCounts = useMemo(() => countBySeverity(report.results), [report.results]);
  const filteredResults = useMemo(
    () => filterResults(query, report.results),
    [query, report.results],
  );

  const summaryItems: SummaryItem[] = [
    {
      label: "Total Tests",
      value: report.metadata.totalTests,
      testId: "report-summary-total",
      icon: faListCheck,
      iconClassName: "text-info",
    },
    {
      label: "Passed",
      value: report.metadata.passedTests,
      testId: "report-summary-passed",
      icon: faCheck,
      iconClassName: "text-clean",
    },
    {
      label: "Failed",
      value: report.metadata.failedTests,
      testId: "report-summary-failed",
      icon: faXmark,
      iconClassName: "text-spam",
    },
    {
      label: "Spam",
      value: severityCounts.spam,
      testId: "report-summary-severity-spam",
      icon: faBan,
      iconClassName: "text-spam",
    },
    {
      label: "Suspicious",
      value: severityCounts.suspicious,
      testId: "report-summary-severity-suspicious",
      icon: faTriangleExclamation,
      iconClassName: "text-suspicious",
    },
    {
      label: "Clean",
      value: severityCounts.clean,
      testId: "report-summary-severity-clean",
      icon: faCheck,
      iconClassName: "text-clean",
    },
    {
      label: "Info",
      value: severityCounts.info,
      testId: "report-summary-severity-info",
      icon: faCircleInfo,
      iconClassName: "text-accent",
    },
  ];

  return (
    <section
      data-testid="report-container"
      className="flex flex-col gap-6 rounded-3xl border border-info/10 bg-surface/70 p-6 shadow-[0_0_50px_rgba(15,23,42,0.3)]"
    >
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-info/80">Interactive Report</p>
          <h2 className="text-lg font-semibold text-text/90">Header Analysis Summary</h2>
        </div>
        <div className="rounded-full border border-info/20 bg-background/40 px-4 py-2 text-xs text-text/60">
          {report.metadata.passedTests} passed · {report.metadata.failedTests} failed
        </div>
      </header>

      <section className="rounded-2xl border border-info/10 bg-background/40 p-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-text/90">Summary Stats</h3>
          <span className="text-[10px] uppercase tracking-[0.2em] text-text/60">Totals</span>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {summaryItems.map((item) => (
            <div
              key={item.testId}
              data-testid={item.testId}
              className="rounded-xl border border-info/10 bg-surface/60 p-3"
            >
              <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.2em] text-text/50">
                <FontAwesomeIcon icon={item.icon} className={`text-[10px] ${item.iconClassName}`} />
                <span>{item.label}</span>
              </div>
              <div className="mt-2 text-lg font-semibold text-text/90">{item.value}</div>
            </div>
          ))}
        </div>
      </section>

      <ReportSearchBar
        query={query}
        matchCount={filteredResults.length}
        totalCount={report.results.length}
        onQueryChange={setQuery}
      />

      <ReportExport report={report} />

      <SecurityAppliancesSummary appliances={report.securityAppliances} />

      <HopChainVisualisation hopChain={report.hopChain} />

      <section className="rounded-2xl border border-info/10 bg-surface/50 p-4 shadow-[0_0_30px_rgba(15,23,42,0.18)]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-text/90">Test Results</h3>
            <p className="text-xs text-text/50">
              Detailed analysis per header test with severity context.
            </p>
          </div>
          <span className="rounded-full border border-info/20 bg-background/40 px-3 py-2 text-[11px] font-mono text-text/60">
            {filteredResults.length} / {report.results.length}
          </span>
        </div>

        <div className="mt-4 flex flex-col gap-4">
          {filteredResults.map((result) => (
            <div key={result.testId} data-testid={`test-result-card-${result.testId}`}>
              <TestResultCard result={result} highlightQuery={query} />
            </div>
          ))}
          {filteredResults.length === 0 ? (
            <p className="text-sm text-text/60">No results match the current search.</p>
          ) : null}
        </div>
      </section>
    </section>
  );
}
