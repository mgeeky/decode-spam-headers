"use client";

import { useEffect, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

import type { AnalysisProgress } from "../types/analysis";
import type { AnalysisStatus } from "../hooks/useAnalysis";

type ProgressIndicatorProps = {
  status: AnalysisStatus;
  progress: AnalysisProgress | null;
  timeoutSeconds: number;
  incompleteTests?: string[];
};

type ProgressVariant = "normal" | "warning" | "timeout";

const formatSeconds = (seconds: number): string => `${seconds}s`;

const getVariant = (
  status: AnalysisStatus,
  remainingSeconds: number,
  timeoutSeconds: number,
): ProgressVariant => {
  if (status === "timeout") {
    return "timeout";
  }

  if (status !== "analysing") {
    return "normal";
  }

  const warningThreshold = Math.max(5, Math.round(timeoutSeconds * 0.15));
  return remainingSeconds <= warningThreshold ? "warning" : "normal";
};

const variantStyles: Record<ProgressVariant, {
  bar: string;
  badge: string;
  track: string;
}> = {
  normal: {
    bar: "bg-clean",
    badge: "text-clean border-clean/40",
    track: "bg-clean/10",
  },
  warning: {
    bar: "bg-suspicious",
    badge: "text-suspicious border-suspicious/40",
    track: "bg-suspicious/10",
  },
  timeout: {
    bar: "bg-spam",
    badge: "text-spam border-spam/40",
    track: "bg-spam/10",
  },
};

export default function ProgressIndicator({
  status,
  progress,
  timeoutSeconds,
  incompleteTests = [],
}: ProgressIndicatorProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());
  const anchorRef = useRef<{ elapsedMs: number; timestamp: number } | null>(null);

  useEffect(() => {
    if (status !== "analysing") {
      return;
    }

    const interval = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);

    return () => {
      window.clearInterval(interval);
    };
  }, [status]);

  useEffect(() => {
    if (!progress || status !== "analysing") {
      anchorRef.current = null;
      return;
    }

    anchorRef.current = {
      elapsedMs: progress.elapsedMs,
      timestamp: Date.now(),
    };
  }, [progress?.elapsedMs, status]);

  const baseElapsedMs = progress?.elapsedMs ?? 0;
  const anchor = anchorRef.current;
  const elapsedMs =
    status === "analysing" && progress && anchor
      ? anchor.elapsedMs + Math.max(0, nowMs - anchor.timestamp)
      : baseElapsedMs;
  const elapsedSeconds = Math.floor(elapsedMs / 1000);
  const remainingSeconds = Math.max(0, timeoutSeconds - elapsedSeconds);
  const percentage = progress ? Math.round(progress.percentage) : 0;
  const variant = getVariant(status, remainingSeconds, timeoutSeconds);
  const styles = variantStyles[variant];

  return (
    <section
      data-testid="progress-indicator"
      data-status={status}
      data-variant={variant}
      className="rounded-2xl border border-info/10 bg-surface p-6 shadow-[0_0_40px_rgba(15,23,42,0.35)]"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] uppercase tracking-[0.2em] ${styles.badge}`}
          >
            {status === "analysing" ? "Analysing" : status}
          </span>
          {status === "analysing" ? (
            <FontAwesomeIcon
              icon={faSpinner}
              spin
              data-testid="progress-spinner"
              className="text-info"
            />
          ) : null}
        </div>
        <div className="flex items-center gap-4 text-xs text-text/60">
          <span data-testid="progress-elapsed">{formatSeconds(elapsedSeconds)}</span>
          <span className="text-text/30">/</span>
          <span data-testid="progress-remaining">{formatSeconds(remainingSeconds)}</span>
        </div>
      </div>

      <div className="mt-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span
            data-testid="progress-current-test"
            className="text-sm font-semibold text-text/80"
          >
            {progress?.currentTest ?? "Preparing analysis"}
          </span>
          <span
            data-testid="progress-percentage"
            className="text-sm font-semibold text-text/70"
          >
            {percentage}%
          </span>
        </div>
        <div
          role="progressbar"
          aria-valuenow={percentage}
          aria-valuemin={0}
          aria-valuemax={100}
          className={`h-2 w-full overflow-hidden rounded-full ${styles.track}`}
        >
          <div
            className={`h-full transition-all ${styles.bar}`}
            style={{ width: `${percentage}%` }}
          />
        </div>
      </div>

      {status === "timeout" ? (
        <div
          role="alert"
          className="mt-4 rounded-xl border border-spam/30 bg-spam/10 p-4 text-xs text-text/80"
        >
          <p className="font-semibold text-spam">
            Timeout reached at {timeoutSeconds} seconds.
          </p>
          <p className="mt-2 text-text/70">Incomplete tests:</p>
          <p data-testid="timeout-tests" className="mt-1 font-mono text-text/70">
            {incompleteTests.length > 0 ? incompleteTests.join(", ") : "None"}
          </p>
        </div>
      ) : null}
    </section>
  );
}
