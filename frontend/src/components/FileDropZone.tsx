"use client";

import { type DragEventHandler, useState } from "react";
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

  const borderClass = error ? "border-spam/70" : isDragging ? "border-info" : "border-info/40";
  const surfaceClass = isDragging ? "bg-surface" : "bg-surface/70";

  return (
    <section className="flex flex-col gap-3">
      <div
        className={`rounded-2xl border border-dashed ${borderClass} ${surfaceClass} p-6 text-center transition-colors`}
        data-testid="file-drop-zone"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        tabIndex={0}
        role="button"
        aria-label="Drop an EML or TXT file"
      >
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-info/30 bg-background/40">
          <FontAwesomeIcon icon={faArrowUpFromBracket} className="text-sm text-info" />
        </div>
        <p className="mt-4 text-sm text-text/80">
          Drop an EML or TXT file to auto-populate the header field.
        </p>
        <p className="mt-2 font-mono text-xs text-text/50">Max size 1MB</p>
      </div>
      {error ? (
        <p role="alert" className="text-xs text-spam">
          {error}
        </p>
      ) : null}
    </section>
  );
}
