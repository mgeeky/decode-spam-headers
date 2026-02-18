"use client";

import {
  type ChangeEvent,
  type DragEventHandler,
  type KeyboardEvent,
  useId,
  useRef,
  useState,
} from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faArrowUpFromBracket } from "@fortawesome/free-solid-svg-icons";

import { MAX_HEADER_INPUT_BYTES } from "../lib/header-validation";

const MAX_FILE_BYTES = MAX_HEADER_INPUT_BYTES;
const ACCEPTED_EXTENSIONS = new Set([".eml", ".txt"]);
const ACCEPTED_MIME_TYPES = new Set(["message/rfc822", "text/plain"]);

type FileDropZoneProps = {
  onFileContent: (content: string) => void;
};

const getExtension = (fileName: string): string => {
  const index = fileName.lastIndexOf(".");
  if (index === -1) {
    return "";
  }
  return fileName.slice(index).toLowerCase();
};

const isSupportedFile = (file: File): boolean => {
  const extension = getExtension(file.name);
  if (ACCEPTED_EXTENSIONS.has(extension)) {
    return true;
  }

  return ACCEPTED_MIME_TYPES.has(file.type);
};

const getFirstFile = (transfer: DataTransfer | null): File | null => {
  if (!transfer) {
    return null;
  }

  if (transfer.items && transfer.items.length > 0) {
    for (const item of Array.from(transfer.items)) {
      if (item.kind === "file") {
        return item.getAsFile();
      }
    }
  }

  if (transfer.files && transfer.files.length > 0) {
    return transfer.files[0] ?? null;
  }

  return null;
};

export default function FileDropZone({ onFileContent }: FileDropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const helperTextId = useId();
  const errorTextId = useId();
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileSelection = (file: File) => {
    if (!isSupportedFile(file)) {
      setError("Only .eml or .txt files are supported.");
      return;
    }

    if (file.size > MAX_FILE_BYTES) {
      setError("File exceeds the 1 MB limit.");
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      const content = typeof result === "string" ? result : "";
      onFileContent(content);
    };
    reader.onerror = () => {
      setError("Unable to read the dropped file.");
    };
    reader.readAsText(file);
  };

  const handleDragOver: DragEventHandler<HTMLDivElement> = (event) => {
    event.preventDefault();
    if (!isDragging) {
      setIsDragging(true);
    }
    if (error) {
      setError(null);
    }
  };

  const handleDragLeave: DragEventHandler<HTMLDivElement> = (event) => {
    event.preventDefault();
    setIsDragging(false);
  };

  const handleDrop: DragEventHandler<HTMLDivElement> = (event) => {
    event.preventDefault();
    setIsDragging(false);
    if (error) {
      setError(null);
    }

    const file = getFirstFile(event.dataTransfer);
    if (!file) {
      return;
    }

    handleFileSelection(file);
  };

  const handleSelectFile = () => {
    fileInputRef.current?.click();
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
      event.preventDefault();
      handleSelectFile();
    }
  };

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const [file] = Array.from(event.currentTarget.files ?? []);
    if (file) {
      if (error) {
        setError(null);
      }
      handleFileSelection(file);
    }
    event.currentTarget.value = "";
  };

  const borderClass = error ? "border-spam/70" : isDragging ? "border-info" : "border-info/40";
  const surfaceClass = isDragging ? "bg-surface" : "bg-surface/70";
  const describedBy = `${helperTextId}${error ? ` ${errorTextId}` : ""}`;

  return (
    <section className="flex flex-col gap-3">
      <input
        ref={fileInputRef}
        type="file"
        accept=".eml,.txt,message/rfc822,text/plain"
        tabIndex={-1}
        onChange={handleInputChange}
        className="sr-only"
        aria-hidden="true"
      />
      <div
        className={`cursor-pointer rounded-2xl border border-dashed ${borderClass} ${surfaceClass} p-6 text-center transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info`}
        data-testid="file-drop-zone"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleSelectFile}
        onKeyDown={handleKeyDown}
        tabIndex={0}
        role="button"
        aria-label="Drop or select an EML or TXT file"
        aria-describedby={describedBy}
        aria-invalid={error ? "true" : undefined}
      >
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-info/30 bg-background/40">
          <FontAwesomeIcon icon={faArrowUpFromBracket} className="text-sm text-info" />
        </div>
        <p className="mt-4 text-sm text-text/80">
          Drop or click to choose an EML or TXT file to auto-populate the header field.
        </p>
        <p id={helperTextId} className="mt-2 font-mono text-xs text-text/50">
          Max size 1MB
        </p>
      </div>
      {error ? (
        <p role="alert" id={errorTextId} className="text-xs text-spam">
          {error}
        </p>
      ) : null}
    </section>
  );
}
