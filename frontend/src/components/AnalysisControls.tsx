"use client";

import { useState, type KeyboardEvent } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faToggleOff, faToggleOn, faGlobe, faCode } from "@fortawesome/free-solid-svg-icons";

import type { AnalysisConfig } from "../types/analysis";
import TestSelector from "./TestSelector";

type AnalysisControlsProps = {
  config?: AnalysisConfig;
  onChange: (next: AnalysisConfig) => void;
};

const defaultConfig: AnalysisConfig = {
  testIds: [],
  resolve: false,
  decodeAll: false,
};

const handleToggleKeyDown = (
  event: KeyboardEvent<HTMLButtonElement>,
  onToggle: () => void,
): void => {
  if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
    event.preventDefault();
    onToggle();
  }
};

export default function AnalysisControls({ config, onChange }: AnalysisControlsProps) {
  const [internalConfig, setInternalConfig] = useState<AnalysisConfig>(defaultConfig);
  const resolvedConfig = config ?? internalConfig;

  const commitConfig = (nextConfig: AnalysisConfig) => {
    if (!config) {
      setInternalConfig(nextConfig);
    }
    onChange(nextConfig);
  };

  const updateTests = (nextTestIds: number[]) => {
    commitConfig({ ...resolvedConfig, testIds: nextTestIds });
  };

  const toggleResolve = () => {
    commitConfig({ ...resolvedConfig, resolve: !resolvedConfig.resolve });
  };

  const toggleDecodeAll = () => {
    commitConfig({ ...resolvedConfig, decodeAll: !resolvedConfig.decodeAll });
  };

  return (
    <section className="flex flex-col gap-6">
      <div className="rounded-2xl border border-info/10 bg-surface p-6 shadow-[0_0_40px_rgba(15,23,42,0.25)]">
        <div className="flex items-center justify-between text-xs uppercase tracking-[0.2em] text-info/90">
          <span>Analysis Controls</span>
          <span className="font-mono text-[10px] text-text/50">US2</span>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col items-start gap-3 rounded-xl border border-info/10 bg-background/40 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="mt-1 rounded-full border border-info/20 bg-background/60 p-2 text-xs text-info/80">
                <FontAwesomeIcon icon={faGlobe} />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-semibold text-text/80">DNS Resolution</span>
                <span className="text-xs text-text/50">Resolve hostnames while analyzing.</span>
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={resolvedConfig.resolve}
              aria-label="Toggle DNS resolution"
              data-testid="toggle-resolve"
              className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/60 px-3 py-2 text-xs text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
              onClick={toggleResolve}
              onKeyDown={(event) => handleToggleKeyDown(event, toggleResolve)}
            >
              <FontAwesomeIcon icon={resolvedConfig.resolve ? faToggleOn : faToggleOff} />
              {resolvedConfig.resolve ? "On" : "Off"}
            </button>
          </div>
          <div className="flex flex-col items-start gap-3 rounded-xl border border-info/10 bg-background/40 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="mt-1 rounded-full border border-info/20 bg-background/60 p-2 text-xs text-info/80">
                <FontAwesomeIcon icon={faCode} />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-semibold text-text/80">Decode All</span>
                <span className="text-xs text-text/50">Decode every encoded header value.</span>
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={resolvedConfig.decodeAll}
              aria-label="Toggle decode all"
              data-testid="toggle-decode-all"
              className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/60 px-3 py-2 text-xs text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
              onClick={toggleDecodeAll}
              onKeyDown={(event) => handleToggleKeyDown(event, toggleDecodeAll)}
            >
              <FontAwesomeIcon icon={resolvedConfig.decodeAll ? faToggleOn : faToggleOff} />
              {resolvedConfig.decodeAll ? "On" : "Off"}
            </button>
          </div>
        </div>
      </div>
      <TestSelector selectedTestIds={resolvedConfig.testIds} onSelectionChange={updateTests} />
    </section>
  );
}
