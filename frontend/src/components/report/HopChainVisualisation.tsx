"use client";

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faArrowDown, faClock, faNetworkWired, faServer } from "@fortawesome/free-solid-svg-icons";

import type { HopChainNode } from "../../types/analysis";

type HopChainVisualisationProps = {
  hopChain: HopChainNode[];
};

const formatDelay = (delay?: number | null): string | null => {
  if (delay === null || delay === undefined || Number.isNaN(delay)) {
    return null;
  }
  return `${delay.toFixed(2)}s`;
};

export default function HopChainVisualisation({ hopChain }: HopChainVisualisationProps) {
  if (hopChain.length === 0) {
    return (
      <section
        data-testid="hop-chain-visualisation"
        className="rounded-2xl border border-info/10 bg-surface/50 p-4"
      >
        <p className="text-sm text-text/60">No hop chain data available.</p>
      </section>
    );
  }

  return (
    <section
      data-testid="hop-chain-visualisation"
      className="rounded-2xl border border-info/10 bg-surface/50 p-4"
    >
      <div className="flex flex-col gap-4">
        {hopChain.map((node, index) => {
          const delayLabel = formatDelay(node.delay);

          return (
            <div key={`${node.index}-${node.hostname}`} className="flex flex-col">
              <article
                data-testid={`hop-chain-node-${node.index}`}
                className="rounded-2xl border border-info/10 bg-background/40 p-4"
              >
                <div className="flex flex-wrap items-start gap-3">
                  <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-info/20 bg-info/10 text-info">
                    <FontAwesomeIcon icon={faServer} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="break-words text-sm font-semibold text-text/90">
                        {node.hostname}
                      </span>
                      {node.ip ? (
                        <span className="break-all font-mono text-xs text-text/60">{node.ip}</span>
                      ) : null}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-4 text-xs text-text/60">
                      {node.timestamp ? (
                        <span className="flex items-center gap-2 break-words">
                          <FontAwesomeIcon icon={faClock} className="text-[10px]" />
                          {node.timestamp}
                        </span>
                      ) : null}
                      {node.serverInfo ? (
                        <span className="flex items-center gap-2 break-words">
                          <FontAwesomeIcon icon={faNetworkWired} className="text-[10px]" />
                          {node.serverInfo}
                        </span>
                      ) : null}
                      {delayLabel ? (
                        <span className="flex items-center gap-2 font-mono text-[11px] text-text/50">
                          +{delayLabel}
                        </span>
                      ) : null}
                    </div>
                  </div>
                </div>
              </article>
              {index < hopChain.length - 1 ? (
                <div
                  data-testid={`hop-chain-connector-${node.index}`}
                  className="ml-5 flex items-center gap-3 py-2 text-text/60"
                >
                  <span className="h-8 w-px rounded-full bg-info/20" />
                  <FontAwesomeIcon icon={faArrowDown} className="text-xs" />
                  <span className="h-8 w-px rounded-full bg-info/20" />
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    </section>
  );
}
