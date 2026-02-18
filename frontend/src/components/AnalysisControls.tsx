"use client";

import type { KeyboardEvent } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faToggleOff,
  faToggleOn,
  faGlobe,
  faCode,
} from "@fortawesome/free-solid-svg-icons";

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

export default function AnalysisControls({
  config = defaultConfig,
  onChange,
}: AnalysisControlsProps) {
  const updateTests = (nextTestIds: number[]) => {
    onChange({ ...config, testIds: nextTestIds });
  };

  const toggleResolve = () => {
    onChange({ ...config, resolve: !config.resolve });
  };

  const toggleDecodeAll = () => {
    onChange({ ...config, decodeAll: !config.decodeAll });
  };

  return (
    <section className="flex flex-col gap-6">
      <div className="rounded-2xl border border-info/10 bg-surface p-6 shadow-[0_0_40px_rgba(15,23,42,0.25)]">
        <div className="flex items-center justify-between text-xs uppercase tracking-[0.2em] text-info/90">
          <span>Analysis Controls</span>
          <span className="font-mono text-[10px] text-text/50">US2</span>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div className="flex items-center justify-between gap-4 rounded-xl border border-info/10 bg-background/40 p-4">
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
              aria-checked={config.resolve}
              aria-label="Toggle DNS resolution"
              data-testid="toggle-resolve"
              className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/60 px-3 py-2 text-xs text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
              onClick={toggleResolve}
              onKeyDown={(event) => handleToggleKeyDown(event, toggleResolve)}
            >
              <FontAwesomeIcon icon={config.resolve ? faToggleOn : faToggleOff} />
              {config.resolve ? "On" : "Off"}
            </button>
          </div>
          <div className="flex items-center justify-between gap-4 rounded-xl border border-info/10 bg-background/40 p-4">
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
              aria-checked={config.decodeAll}
              aria-label="Toggle decode all"
              data-testid="toggle-decode-all"
              className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/60 px-3 py-2 text-xs text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
              onClick={toggleDecodeAll}
              onKeyDown={(event) => handleToggleKeyDown(event, toggleDecodeAll)}
            >
              <FontAwesomeIcon icon={config.decodeAll ? faToggleOn : faToggleOff} />
              {config.decodeAll ? "On" : "Off"}
            </button>
          </div>
        </div>
      </div>
      <TestSelector selectedTestIds={config.testIds} onSelectionChange={updateTests} />
    </section>
  );
}
