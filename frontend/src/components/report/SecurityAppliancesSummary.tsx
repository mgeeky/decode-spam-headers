"use client";

import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faShield } from "@fortawesome/free-solid-svg-icons";

import type { SecurityAppliance } from "../../types/analysis";

type SecurityAppliancesSummaryProps = {
  appliances: SecurityAppliance[];
};

export default function SecurityAppliancesSummary({ appliances }: SecurityAppliancesSummaryProps) {
  const hasAppliances = appliances.length > 0;

  return (
    <section
      data-testid="security-appliances-summary"
      className="rounded-2xl border border-info/10 bg-surface/50 p-4 shadow-[0_0_30px_rgba(15,23,42,0.18)]"
    >
      <div className="flex items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-info/20 bg-info/10 text-info">
          <FontAwesomeIcon icon={faShield} className="text-xs" />
        </span>
        <div>
          <h3 className="text-sm font-semibold text-text/90">Security Appliances</h3>
          <p className="text-xs text-text/50">
            Detected email security vendors in the message path.
          </p>
        </div>
      </div>

      {hasAppliances ? (
        <div className="mt-4 flex flex-wrap gap-2">
          {appliances.map((appliance, index) => (
            <div
              key={`${appliance.vendor}-${appliance.name}`}
              data-testid={`security-appliance-${index}`}
              className="inline-flex items-center gap-2 rounded-full border border-info/20 bg-background/40 px-3 py-1 text-xs text-text/70"
            >
              <FontAwesomeIcon icon={faShield} className="text-[10px] text-info" />
              <span className="font-semibold">{appliance.vendor}</span>
              <span className="text-text/50">{appliance.name}</span>
            </div>
          ))}
        </div>
      ) : (
        <p data-testid="security-appliances-empty" className="mt-4 text-sm text-text/60">
          No security appliances detected.
        </p>
      )}
    </section>
  );
}
