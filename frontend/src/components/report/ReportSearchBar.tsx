"use client";

import type { FormEvent, KeyboardEvent } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMagnifyingGlass, faXmark } from "@fortawesome/free-solid-svg-icons";

type ReportSearchBarProps = {
  query: string;
  matchCount: number;
  totalCount: number;
  onQueryChange: (next: string) => void;
};

export default function ReportSearchBar({
  query,
  matchCount,
  totalCount,
  onQueryChange,
}: ReportSearchBarProps) {
  const handleInput = (event: FormEvent<HTMLInputElement>) => {
    onQueryChange(event.currentTarget.value);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      onQueryChange("");
    }
  };

  const handleClear = () => {
    onQueryChange("");
  };

  const hasQuery = query.trim().length > 0;

  return (
    <section
      data-testid="report-search-bar"
      className="rounded-2xl border border-info/10 bg-surface/50 p-4 shadow-[0_0_30px_rgba(15,23,42,0.18)]"
    >
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex flex-1 items-center gap-2 rounded-full border border-info/20 bg-background/40 px-3 py-2 text-sm text-text/70 focus-within:border-info/40 focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-info">
          <FontAwesomeIcon icon={faMagnifyingGlass} className="text-xs text-text/60" />
          <input
            type="text"
            value={query}
            onInput={handleInput}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent text-xs text-text/80 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
            placeholder="Search test names, headers, or analysis"
            data-testid="report-search-input"
            aria-label="Search report results"
          />
        </label>

        {hasQuery ? (
          <button
            type="button"
            className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/40 px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
            onClick={handleClear}
            aria-label="Clear search"
          >
            <FontAwesomeIcon icon={faXmark} className="text-[10px]" />
            Clear
          </button>
        ) : null}

        <span
          data-testid="report-search-count"
          aria-live="polite"
          className="rounded-full border border-info/20 bg-background/40 px-3 py-2 text-[11px] font-mono text-text/60"
        >
          {matchCount} / {totalCount}
        </span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-text/50">
        <span>{hasQuery ? "Matches for" : "Showing all results"}</span>
        {hasQuery ? (
          <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">
            {query}
          </span>
        ) : null}
      </div>
    </section>
  );
}
