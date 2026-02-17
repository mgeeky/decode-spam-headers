export default function Home() {
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
            <div className="rounded-2xl border border-info/10 bg-surface p-6 shadow-[0_0_40px_rgba(15,23,42,0.45)]">
              <div className="flex items-center justify-between text-xs uppercase tracking-[0.2em] text-info/90">
                <span>Header Input</span>
                <span className="font-mono text-[10px] text-text/50">
                  0 / 1MB
                </span>
              </div>
              <div className="mt-4 rounded-xl border border-info/20 bg-background/60 p-4 font-mono text-sm text-text/80 sm:text-base">
                Paste SMTP headers here. Each line is parsed for sender,
                authentication, and delivery hops.
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-text/50">
                <span>Tip:</span>
                <span className="font-mono">Ctrl</span>
                <span>+</span>
                <span className="font-mono">Enter</span>
                <span>to analyse.</span>
              </div>
            </div>

            <div className="flex flex-col gap-6">
              <div className="rounded-2xl border border-dashed border-info/40 bg-surface/70 p-6 text-center">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-info/30 bg-background/40">
                  <span className="font-mono text-xs text-info">.eml</span>
                </div>
                <p className="mt-4 text-sm text-text/80">
                  Drop an EML or TXT file to auto-populate the header field.
                </p>
                <p className="mt-2 font-mono text-xs text-text/50">
                  Max size 1MB
                </p>
              </div>

              <div className="rounded-2xl border border-info/10 bg-surface p-6">
                <p className="text-xs uppercase tracking-[0.2em] text-info/80">
                  Ready To Analyse
                </p>
                <p className="mt-2 text-sm text-text/70">
                  Once input is provided, run the analysis to reveal scoring,
                  heuristics, and delivery path insights.
                </p>
                <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
                  <button
                    type="button"
                    className="flex-1 rounded-full bg-accent px-5 py-3 text-sm font-semibold text-background transition hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
                  >
                    Analyse Headers
                  </button>
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
