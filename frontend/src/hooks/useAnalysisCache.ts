import { useCallback, useState } from "react";

import type { AnalysisConfig, AnalysisReport } from "../types/analysis";

export interface CachedAnalysisPayload {
  headers: string;
  config: AnalysisConfig;
  result: AnalysisReport;
}

export interface CachedAnalysisData extends CachedAnalysisPayload {
  timestamp: number;
}

export interface UseAnalysisCacheState {
  save: (payload: CachedAnalysisPayload) => void;
  load: () => CachedAnalysisData | null;
  clear: () => void;
  hasCachedData: () => boolean;
  isNearLimit: boolean;
}

const STORAGE_LIMIT_BYTES = 5 * 1024 * 1024;
const WARNING_THRESHOLD_RATIO = 0.9;

const HEADER_KEY = "wha:headers";
const CONFIG_KEY = "wha:config";
const RESULT_KEY = "wha:result";
const TIMESTAMP_KEY = "wha:timestamp";

const canUseStorage = (): boolean => {
  if (typeof window === "undefined") {
    return false;
  }
  if (!window.localStorage) {
    return false;
  }

  try {
    const probeKey = "wha:probe";
    window.localStorage.setItem(probeKey, probeKey);
    window.localStorage.removeItem(probeKey);
    return true;
  } catch {
    return false;
  }
};

const estimateBytes = (value: string): number => {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(value).length;
  }

  return value.length;
};

const estimateStorageSize = (): number => {
  if (!canUseStorage()) {
    return 0;
  }

  let total = 0;
  for (let index = 0; index < localStorage.length; index += 1) {
    const key = localStorage.key(index);
    if (!key) {
      continue;
    }

    const value = localStorage.getItem(key) ?? "";
    total += estimateBytes(key);
    total += estimateBytes(value);
  }

  return total;
};

const parseJson = <T>(value: string | null): T | null => {
  if (!value) {
    return null;
  }

  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
};

const useAnalysisCache = (): UseAnalysisCacheState => {
  const [isNearLimit, setIsNearLimit] = useState(false);

  const save = useCallback((payload: CachedAnalysisPayload) => {
    if (!canUseStorage()) {
      setIsNearLimit(false);
      return;
    }

    const timestamp = Date.now();
    localStorage.setItem(HEADER_KEY, payload.headers);
    localStorage.setItem(CONFIG_KEY, JSON.stringify(payload.config));
    localStorage.setItem(RESULT_KEY, JSON.stringify(payload.result));
    localStorage.setItem(TIMESTAMP_KEY, String(timestamp));

    const usedBytes = estimateStorageSize();
    const warningThreshold = STORAGE_LIMIT_BYTES * WARNING_THRESHOLD_RATIO;
    setIsNearLimit(usedBytes >= warningThreshold);
  }, []);

  const load = useCallback((): CachedAnalysisData | null => {
    if (!canUseStorage()) {
      return null;
    }

    const headers = localStorage.getItem(HEADER_KEY);
    const config = parseJson<AnalysisConfig>(localStorage.getItem(CONFIG_KEY));
    const result = parseJson<AnalysisReport>(localStorage.getItem(RESULT_KEY));
    const timestampValue = localStorage.getItem(TIMESTAMP_KEY);

    if (!headers || !config || !result || !timestampValue) {
      return null;
    }

    const timestamp = Number(timestampValue);
    if (Number.isNaN(timestamp)) {
      return null;
    }

    return {
      headers,
      config,
      result,
      timestamp,
    };
  }, []);

  const clear = useCallback(() => {
    if (!canUseStorage()) {
      setIsNearLimit(false);
      return;
    }

    localStorage.removeItem(HEADER_KEY);
    localStorage.removeItem(CONFIG_KEY);
    localStorage.removeItem(RESULT_KEY);
    localStorage.removeItem(TIMESTAMP_KEY);
    setIsNearLimit(false);
  }, []);

  const hasCachedData = useCallback((): boolean => {
    if (!canUseStorage()) {
      return false;
    }

    return Boolean(
      localStorage.getItem(HEADER_KEY) &&
        localStorage.getItem(CONFIG_KEY) &&
        localStorage.getItem(RESULT_KEY) &&
        localStorage.getItem(TIMESTAMP_KEY),
    );
  }, []);

  return {
    save,
    load,
    clear,
    hasCachedData,
    isNearLimit,
  };
};

export default useAnalysisCache;
