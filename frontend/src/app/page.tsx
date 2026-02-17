"use client";

import { useState } from "react";

import AnalyseButton from "../components/AnalyseButton";
import FileDropZone from "../components/FileDropZone";
import HeaderInput from "../components/HeaderInput";

export default function Home() {
  const [headerInput, setHeaderInput] = useState("");
  const hasHeaderInput = headerInput.trim().length > 0;

  return (
    <main className="min-h-screen bg-background text-text">
      <div className="min-h-screen bg-[radial-gradient(900px_circle_at_15%_10%,rgba(139,233,253,0.12),transparent_55%),radial-gradient(700px_circle_at_85%_80%,rgba(189,147,249,0.12),transparent_60%)]">
        <div className="mx-auto flex min-h-screen max-w-6xl flex-col gap-10 px-4 py-10 sm:px-6 lg:px-12">
          <header className="flex flex-col gap-4">
            <p className="text-xs font-semibold uppercase tracking-[0.3em] text-info">
              Decode Suite
            </p>
            <div className="flex flex-col gap-3">
              <h1 className="text-3xl font-semibold sm:text-4xl">
                Decode Spam Headers
              </h1>
              <p className="max-w-2xl text-sm text-text/70 sm:text-base">
                Paste SMTP headers or drop an EML/TXT file to reveal the
                anti-spam signals baked into your message path.
              </p>
            </div>
          </header>

          <section className="grid gap-6 lg:grid-cols-[2fr_1fr]">
            <HeaderInput value={headerInput} onChange={setHeaderInput} />

            <div className="flex flex-col gap-6">
              <FileDropZone onFileContent={setHeaderInput} />

              <div className="rounded-2xl border border-info/10 bg-surface p-6">
                <p className="text-xs uppercase tracking-[0.2em] text-info/80">
                  Ready To Analyse
                </p>
                <p className="mt-2 text-sm text-text/70">
                  Once input is provided, run the analysis to reveal scoring,
                  heuristics, and delivery path insights.
                </p>
                <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
                  <AnalyseButton hasInput={hasHeaderInput} onAnalyse={() => undefined} />
                  <div className="flex items-center gap-2 text-xs text-text/60">
                    <kbd className="rounded-md border border-info/30 bg-background/40 px-2 py-1 font-mono">
                      Ctrl
                    </kbd>
                    <span>+</span>
                    <kbd className="rounded-md border border-info/30 bg-background/40 px-2 py-1 font-mono">
                      Enter
                    </kbd>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
