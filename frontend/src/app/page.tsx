"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTrash } from "@fortawesome/free-solid-svg-icons";

import AnalyseButton from "../components/AnalyseButton";
import AnalysisControls from "../components/AnalysisControls";
import CaptchaChallenge from "../components/CaptchaChallenge";
import FileDropZone from "../components/FileDropZone";
import HeaderInput from "../components/HeaderInput";
import ProgressIndicator from "../components/ProgressIndicator";
import ReportContainer from "../components/report/ReportContainer";
import useAnalysis from "../hooks/useAnalysis";
import useAnalysisCache from "../hooks/useAnalysisCache";
import { apiClient } from "../lib/api-client";
import { MAX_HEADER_INPUT_BYTES } from "../lib/header-validation";
import type { AnalysisConfig, AnalysisReport } from "../types/analysis";
import type { CaptchaVerifyPayload, CaptchaVerifyResponse } from "../types/captcha";

const defaultConfig: AnalysisConfig = {
  testIds: [],
  resolve: false,
  decodeAll: false,
};

export default function Home() {
  const { status, progress, result, submit, cancel, captchaChallenge, clearCaptchaChallenge } =
    useAnalysis();
  const { save, load, clear, isNearLimit } = useAnalysisCache();
  const initialCache = useMemo(() => load(), [load]);
  const [headerInput, setHeaderInput] = useState(() => initialCache?.headers ?? "");
  const [analysisConfig, setAnalysisConfig] = useState<AnalysisConfig>(
    () => initialCache?.config ?? defaultConfig,
  );
  const [cachedReport, setCachedReport] = useState<AnalysisReport | null>(
    () => initialCache?.result ?? null,
  );
  const [cachedTimestamp, setCachedTimestamp] = useState<number | null>(
    () => initialCache?.timestamp ?? null,
  );
  const [isViewCleared, setIsViewCleared] = useState(false);
  const lastSubmissionRef = useRef<{ headers: string; config: AnalysisConfig } | null>(null);
  const bypassTokenRef = useRef<string | null>(null);

  useEffect(() => {
    if (!result) {
      return;
    }

    const payload = lastSubmissionRef.current ?? {
      headers: headerInput,
      config: analysisConfig,
    };

    save({ headers: payload.headers, config: payload.config, result });
  }, [analysisConfig, headerInput, result, save]);

  const hasHeaderInput = headerInput.trim().length > 0;
  const isOversized = headerInput.length > MAX_HEADER_INPUT_BYTES;
  const canAnalyse = hasHeaderInput && !isOversized;
  const isLoading = status === "submitting" || status === "analysing";
  const showProgress = status === "analysing" || status === "timeout";
  const incompleteTests = result?.metadata.incompleteTests ?? [];
  const allowCachedFallback =
    status === "idle" || status === "complete" || status === "error" || status === "timeout";
  const report = isViewCleared ? null : (result ?? (allowCachedFallback ? cachedReport : null));
  const isCachedView = Boolean(!isViewCleared && !result && allowCachedFallback && cachedReport);
  const hasCache = Boolean(result || cachedReport);
  const cacheTimestampLabel = useMemo(() => {
    if (!cachedTimestamp) {
      return null;
    }

    return new Date(cachedTimestamp).toLocaleString("en-US", {
      dateStyle: "medium",
      timeStyle: "short",
    });
  }, [cachedTimestamp]);

  const handleAnalyse = useCallback(() => {
    if (!canAnalyse) {
      return;
    }

    const payload = { headers: headerInput, config: analysisConfig };
    lastSubmissionRef.current = payload;
    setIsViewCleared(false);
    if (bypassTokenRef.current) {
      void submit(payload, { bypassToken: bypassTokenRef.current });
      return;
    }
    void submit(payload);
  }, [analysisConfig, canAnalyse, headerInput, submit]);

  const handleClearCache = useCallback(() => {
    clear();
    cancel();
    setHeaderInput("");
    setAnalysisConfig(defaultConfig);
    setCachedReport(null);
    setCachedTimestamp(null);
    setIsViewCleared(true);
    lastSubmissionRef.current = null;
    bypassTokenRef.current = null;
    clearCaptchaChallenge();
  }, [cancel, clear, clearCaptchaChallenge]);

  const handleCaptchaVerify = useCallback(
    async (payload: CaptchaVerifyPayload): Promise<string> => {
      const response = await apiClient.post<CaptchaVerifyResponse, CaptchaVerifyPayload>(
        "/api/captcha/verify",
        payload,
      );
      if (!response.bypassToken) {
        throw new Error("Captcha verification failed.");
      }
      return response.bypassToken;
    },
    [],
  );

  const handleCaptchaSuccess = useCallback((bypassToken: string) => {
    bypassTokenRef.current = bypassToken;
  }, []);

  const handleCaptchaRetry = useCallback(() => {
    const payload = lastSubmissionRef.current;
    if (!payload) {
      return;
    }
    setIsViewCleared(false);
    if (bypassTokenRef.current) {
      void submit(payload, { bypassToken: bypassTokenRef.current });
      return;
    }
    void submit(payload);
  }, [submit]);

  const handleCaptchaClose = useCallback(() => {
    clearCaptchaChallenge();
  }, [clearCaptchaChallenge]);

  return (
    <main className="min-h-screen bg-background text-text">
      <div className="min-h-screen bg-[radial-gradient(900px_circle_at_15%_10%,rgba(139,233,253,0.12),transparent_55%),radial-gradient(700px_circle_at_85%_80%,rgba(189,147,249,0.12),transparent_60%)]">
        <div className="mx-auto flex min-h-screen max-w-6xl flex-col gap-10 px-4 py-10 sm:px-6 lg:px-12">
          <header className="flex flex-col gap-4">
            <p className="text-xs font-semibold uppercase tracking-[0.3em] text-info">
              Decode Suite
            </p>
            <div className="flex flex-col gap-3">
              <h1 className="text-3xl font-semibold sm:text-4xl">Decode Spam Headers</h1>
              <p className="max-w-2xl text-sm text-text/70 sm:text-base">
                Paste SMTP headers or drop an EML/TXT file to reveal the anti-spam signals baked
                into your message path.
              </p>
            </div>
          </header>

          <section className="grid gap-6 lg:grid-cols-[2fr_1fr]">
            <div className="flex min-w-0 flex-col gap-6">
              <HeaderInput value={headerInput} onChange={setHeaderInput} />
              <AnalysisControls config={analysisConfig} onChange={setAnalysisConfig} />
            </div>

            <div className="flex min-w-0 flex-col gap-6">
              <FileDropZone onFileContent={setHeaderInput} />

              <div className="rounded-2xl border border-info/10 bg-surface p-6">
                <p className="text-xs uppercase tracking-[0.2em] text-info/80">Ready To Analyse</p>
                <p className="mt-2 text-sm text-text/70">
                  Once input is provided, run the analysis to reveal scoring, heuristics, and
                  delivery path insights.
                </p>
                <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
                  <AnalyseButton
                    hasInput={canAnalyse}
                    onAnalyse={handleAnalyse}
                    isLoading={isLoading}
                  />
                  <div className="flex items-center gap-2 text-xs text-text/60">
                    <kbd className="rounded-md border border-info/30 bg-background/40 px-2 py-1 font-mono">
                      Ctrl
                    </kbd>
                    <span>+</span>
                    <kbd className="rounded-md border border-info/30 bg-background/40 px-2 py-1 font-mono">
                      Enter
                    </kbd>
                  </div>
                </div>
              </div>

              {showProgress ? (
                <ProgressIndicator
                  status={status}
                  progress={progress}
                  timeoutSeconds={30}
                  incompleteTests={incompleteTests}
                />
              ) : null}

              <div className="rounded-2xl border border-info/10 bg-surface p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="text-xs uppercase tracking-[0.2em] text-info/80">Browser Cache</p>
                  <button
                    type="button"
                    className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/40 px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info disabled:cursor-not-allowed disabled:opacity-50"
                    onClick={handleClearCache}
                    disabled={!hasCache}
                  >
                    <FontAwesomeIcon icon={faTrash} className="text-xs" />
                    Clear Cache
                  </button>
                </div>
                <p className="mt-2 text-xs text-text/60">
                  {result
                    ? "Latest analysis cached for this session."
                    : hasCache
                      ? `Cached analysis saved ${cacheTimestampLabel ?? "recently"}.`
                      : "No cached analysis yet. Run an analysis to save this session."}
                </p>
                {isNearLimit ? (
                  <p className="mt-2 text-xs text-suspicious">
                    Local storage is nearly full. Consider clearing cached data.
                  </p>
                ) : null}
              </div>
            </div>
          </section>

          {report ? (
            <section className="flex flex-col gap-3">
              {isCachedView ? (
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-text/60">
                  <span className="rounded-full border border-info/20 bg-background/40 px-3 py-1 uppercase tracking-[0.2em] text-info/70">
                    Cached Result
                  </span>
                  {cacheTimestampLabel ? (
                    <span>Saved {cacheTimestampLabel}</span>
                  ) : (
                    <span>Saved recently</span>
                  )}
                </div>
              ) : null}
              <ReportContainer report={report} />
            </section>
          ) : null}
        </div>
      </div>
      <CaptchaChallenge
        isOpen={Boolean(captchaChallenge)}
        challenge={captchaChallenge}
        onVerify={handleCaptchaVerify}
        onSuccess={handleCaptchaSuccess}
        onRetry={handleCaptchaRetry}
        onClose={handleCaptchaClose}
      />
    </main>
  );
}
