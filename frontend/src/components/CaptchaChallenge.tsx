"use client";

import { useCallback, useId, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faLock, faUnlock } from "@fortawesome/free-solid-svg-icons";

export type CaptchaChallengeData = {
  challengeToken: string;
  imageBase64: string;
};

export type CaptchaVerifyPayload = {
  challengeToken: string;
  answer: string;
};

type CaptchaChallengeProps = {
  isOpen: boolean;
  challenge?: CaptchaChallengeData | null;
  onVerify: (payload: CaptchaVerifyPayload) => Promise<string>;
  onSuccess: (bypassToken: string) => void;
  onRetry: () => void | Promise<void>;
  onClose: () => void;
};

const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }
  return "Verification failed. Please try again.";
};

export default function CaptchaChallenge({
  isOpen,
  challenge,
  onVerify,
  onSuccess,
  onRetry,
  onClose,
}: CaptchaChallengeProps) {
  const [answer, setAnswer] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const titleId = useId();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const answerRef = useRef("");
  const modalRef = useRef<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    if (!isOpen) {
      return;
    }
    setAnswer("");
    setError(null);
    setIsSubmitting(false);
    answerRef.current = "";
  }, [isOpen, challenge?.challengeToken]);

  useLayoutEffect(() => {
    if (!isOpen) {
      return;
    }
    inputRef.current?.focus();
  }, [isOpen, challenge?.challengeToken]);

  const commitAnswer = useCallback((value: string) => {
    answerRef.current = value;
    setAnswer(value);
  }, []);

  const handleSubmit = useCallback(async () => {
    if (!challenge || isSubmitting) {
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const bypassToken = await onVerify({
        challengeToken: challenge.challengeToken,
        answer: (inputRef.current?.value ?? answerRef.current ?? answer).trim(),
      });
      onSuccess(bypassToken);
      await Promise.resolve(onRetry());
      onClose();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }, [answer, challenge, isSubmitting, onClose, onRetry, onSuccess, onVerify]);

  const handleKeyDown = useCallback(
    (event: KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }

      if (event.key !== "Tab") {
        return;
      }
      const container = modalRef.current;
      if (!container) {
        return;
      }
      const focusableElements = Array.from(
        container.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter(
        (element) =>
          !element.hasAttribute("disabled") &&
          element.getAttribute("aria-hidden") !== "true",
      );

      if (focusableElements.length === 0) {
        return;
      }

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];
      const activeElement = document.activeElement;

      if (event.shiftKey && activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
        return;
      }

      if (!event.shiftKey && activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
      }
    },
    [onClose],
  );

  const handleInputKeyDown = useCallback(
    (event: KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "Enter") {
        event.preventDefault();
        void handleSubmit();
      }
    },
    [handleSubmit],
  );

  if (!isOpen || !challenge) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4">
      <div
        className="w-full max-w-md rounded-2xl border border-info/20 bg-surface p-6 shadow-[0_0_45px_rgba(15,23,42,0.5)]"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="captcha-challenge"
        onKeyDown={handleKeyDown}
        tabIndex={-1}
        ref={modalRef}
      >
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="rounded-full border border-info/20 bg-background/50 p-2 text-xs text-info">
              <FontAwesomeIcon icon={faLock} />
            </span>
            <div className="flex flex-col">
              <h2 id={titleId} className="text-sm font-semibold text-text">
                Security Check Required
              </h2>
              <p className="text-xs text-text/60">Solve the CAPTCHA to continue analysis.</p>
            </div>
          </div>
          <button
            type="button"
            className="rounded-full border border-info/20 bg-background/40 px-3 py-2 text-xs text-text/70 transition hover:border-info/40 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
            onClick={onClose}
            data-testid="captcha-close"
            aria-label="Close captcha challenge"
          >
            Close
          </button>
        </div>

        <div className="mt-5 flex flex-col gap-4">
          <div className="rounded-xl border border-info/20 bg-background/50 p-4">
            <img
              src={`data:image/png;base64,${challenge.imageBase64}`}
              alt="CAPTCHA challenge"
              className="w-full rounded-lg"
              data-testid="captcha-image"
            />
          </div>

          <label className="flex flex-col gap-2 text-xs text-text/70">
            Enter the text shown above
            <input
              type="text"
              autoComplete="off"
              value={answer}
              onChange={(event) => commitAnswer(event.target.value)}
              onInput={(event) => commitAnswer(event.currentTarget.value)}
              onKeyDown={handleInputKeyDown}
              data-testid="captcha-input"
              ref={inputRef}
              className="rounded-xl border border-info/20 bg-background/50 px-4 py-3 text-sm text-text outline-none transition focus:border-info/60 focus:ring-2 focus:ring-info/30"
            />
          </label>

          {error ? (
            <p className="text-xs text-spam" data-testid="captcha-error">
              {error}
            </p>
          ) : null}

          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-info/30 bg-info/20 px-4 py-3 text-xs font-semibold uppercase tracking-[0.2em] text-info transition hover:border-info/50 hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info disabled:cursor-not-allowed disabled:opacity-60"
            onClick={() => void handleSubmit()}
            disabled={isSubmitting}
            data-testid="captcha-submit"
          >
            <FontAwesomeIcon icon={faUnlock} />
            {isSubmitting ? "Verifying" : "Verify"}
          </button>
        </div>
      </div>
    </div>
  );
}
