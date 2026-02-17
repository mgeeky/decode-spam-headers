"use client";

import { type FormEvent, useEffect, useId, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faXmark } from "@fortawesome/free-solid-svg-icons";

import {
  MAX_HEADER_INPUT_BYTES,
  validateHeaderInput,
} from "../lib/header-validation";

type HeaderInputProps = {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
};

const defaultPlaceholder =
  "Paste SMTP headers here. Each line is parsed for sender, authentication, and delivery hops.";

const formatCount = (count: number): string => count.toLocaleString("en-US");

export default function HeaderInput({
  value,
  onChange,
  placeholder = defaultPlaceholder,
}: HeaderInputProps) {
  const inputId = useId();
  const errorId = useId();
  const [touched, setTouched] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    const node = textareaRef.current;
    if (!node) {
      return;
    }

    const handleNativeBlur = () => {
      setTouched(true);
    };

    node.addEventListener("blur", handleNativeBlur);

    return () => {
      node.removeEventListener("blur", handleNativeBlur);
    };
  }, []);

  const handleInput = (event: FormEvent<HTMLTextAreaElement>) => {
    const nextValue = event.currentTarget.value;
    onChange(nextValue);
  };

  const handleClear = () => {
    onChange("");
    setTouched(true);
  };

  const isOversized = value.length > MAX_HEADER_INPUT_BYTES;
  const shouldShowError = touched || isOversized;
  const error = shouldShowError ? validateHeaderInput(value) : null;
  const hasError = Boolean(error);
  const hintText = `${formatCount(value.length)} / 1MB`;

  return (
    <section className="rounded-2xl border border-info/10 bg-surface p-6 shadow-[0_0_40px_rgba(15,23,42,0.45)]">
      <div className="flex items-center justify-between text-xs uppercase tracking-[0.2em] text-info/90">
        <label htmlFor={inputId}>Header Input</label>
        <span className="font-mono text-[10px] text-text/50">{hintText}</span>
      </div>
      <div className="mt-4 flex flex-col gap-3">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <textarea
            id={inputId}
            className="min-h-[180px] flex-1 resize-y rounded-xl border border-info/20 bg-background/60 p-4 font-mono text-sm text-text/80 shadow-inner focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info sm:text-base"
            placeholder={placeholder}
            spellCheck={false}
            value={value}
            onInput={handleInput}
            aria-invalid={hasError ? "true" : undefined}
            aria-describedby={hasError ? errorId : undefined}
            ref={textareaRef}
          />
          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-full border border-info/20 bg-background/40 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info disabled:cursor-not-allowed disabled:opacity-50"
            onClick={handleClear}
            aria-label="Clear header input"
            disabled={value.length === 0}
          >
            <FontAwesomeIcon icon={faXmark} className="text-xs" />
            Clear
          </button>
        </div>
        {hasError ? (
          <p role="alert" id={errorId} className="text-xs text-spam">
            {error}
          </p>
        ) : null}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-text/50">
        <span>Tip:</span>
        <span className="font-mono">Ctrl</span>
        <span>+</span>
        <span className="font-mono">Enter</span>
        <span>to analyse.</span>
      </div>
    </section>
  );
}
