"use client";

import { useEffect, useMemo } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMagnifyingGlass, faSpinner } from "@fortawesome/free-solid-svg-icons";

type AnalyseButtonProps = {
  hasInput: boolean;
  onAnalyse: () => void;
  isLoading?: boolean;
};

export default function AnalyseButton({
  hasInput,
  onAnalyse,
  isLoading = false,
}: AnalyseButtonProps) {
  const isDisabled = useMemo(() => !hasInput || isLoading, [hasInput, isLoading]);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if (!event.ctrlKey || event.key !== "Enter") {
        return;
      }

      if (isDisabled) {
        return;
      }

      event.preventDefault();
      onAnalyse();
    };

    window.addEventListener("keydown", handleShortcut);
    return () => {
      window.removeEventListener("keydown", handleShortcut);
    };
  }, [isDisabled, onAnalyse]);

  return (
    <button
      type="button"
      className="flex w-full items-center justify-center gap-2 rounded-full bg-accent px-5 py-3 text-sm font-semibold text-background transition hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
      onClick={onAnalyse}
      disabled={isDisabled}
      aria-busy={isLoading ? "true" : undefined}
    >
      <FontAwesomeIcon icon={isLoading ? faSpinner : faMagnifyingGlass} spin={isLoading} />
      {isLoading ? "Analysing..." : "Analyse Headers"}
    </button>
  );
}
