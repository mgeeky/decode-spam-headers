import { useCallback, useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";

import { apiClient, type SseEvent } from "../lib/api-client";
import type { AnalysisConfig, AnalysisProgress, AnalysisReport } from "../types/analysis";

export type AnalysisStatus =
  | "idle"
  | "submitting"
  | "analysing"
  | "complete"
  | "error"
  | "timeout";

export interface AnalysisRequest {
  headers: string;
  config: AnalysisConfig;
}

export interface UseAnalysisState {
  status: AnalysisStatus;
  progress: AnalysisProgress | null;
  result: AnalysisReport | null;
  error: string | null;
  submit: (request: AnalysisRequest) => Promise<void>;
  cancel: () => void;
}

const scheduleTask = (handler: () => void): void => {
  setTimeout(handler, 0);
};

const useAnalysis = (): UseAnalysisState => {
  const [status, setStatus] = useState<AnalysisStatus>("idle");
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [result, setResult] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const requestIdRef = useRef(0);
  const inFlightRef = useRef(false);
  const mountedRef = useRef(true);
  const hasProgressRef = useRef(false);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
    };
  }, []);

  const resetState = useCallback(() => {
    setProgress(null);
    setResult(null);
    setError(null);
  }, []);

  const handleEvent = useCallback(
    (
      event: SseEvent<AnalysisProgress | AnalysisReport>,
      requestId: number,
      signal: AbortSignal,
    ) => {
      scheduleTask(() => {
        if (!mountedRef.current) {
          return;
        }
        if (!inFlightRef.current || requestIdRef.current !== requestId) {
          return;
        }
        if (signal.aborted) {
          return;
        }

        if (event.event === "progress") {
          const payload = event.data as AnalysisProgress;
          if (!hasProgressRef.current) {
            hasProgressRef.current = true;
            flushSync(() => {
              setProgress(payload);
              setStatus("analysing");
            });
            return;
          }
          setProgress(payload);
          return;
        }

        if (event.event === "result") {
          const report = event.data as AnalysisReport;
          setResult(report);
          inFlightRef.current = false;
          setStatus(report.metadata.timedOut ? "timeout" : "complete");
        }
      });
    },
    [],
  );

  const submit = useCallback(
    async (request: AnalysisRequest): Promise<void> => {
      requestIdRef.current += 1;
      const requestId = requestIdRef.current;

      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      inFlightRef.current = true;

      setStatus("submitting");
      resetState();
      hasProgressRef.current = false;

      try {
        await apiClient.stream<AnalysisRequest, AnalysisProgress | AnalysisReport>(
          "/api/analyse",
          {
            body: request,
            signal: controller.signal,
            onEvent: (event) => handleEvent(event, requestId, controller.signal),
          },
        );
      } catch (err) {
        if (!mountedRef.current || controller.signal.aborted) {
          return;
        }
        if (requestIdRef.current !== requestId) {
          return;
        }

        inFlightRef.current = false;
        const message = err instanceof Error ? err.message : "Unknown error";
        setError(message);
        setStatus("error");
      }
    },
    [handleEvent, resetState],
  );

  const cancel = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort();
    }
    inFlightRef.current = false;
    setStatus("idle");
    resetState();
    hasProgressRef.current = false;
  }, [resetState]);

  return {
    status,
    progress,
    result,
    error,
    submit,
    cancel,
  };
};

export default useAnalysis;
