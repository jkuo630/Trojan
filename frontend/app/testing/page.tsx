// src/app/testing/page.tsx
"use client";

import * as React from "react";
import { VulnerabilityCard } from "../../components/Vulnerability";
import { VulnerabilityPopUp } from "../../components/VulnerabilityPopUp";
import { mockFindings } from "./MockFindings";

export default function TestingPage() {
  const [selectedIndex, setSelectedIndex] = React.useState(0);
  const selected = mockFindings[selectedIndex];

  return (
    <main className="min-h-screen bg-slate-950 px-8 py-10">
      <div className="max-w-3xl space-y-10">
        {/* Pop-up preview (uses same mocked data) */}
        <div className="max-w-2xl">
          <VulnerabilityPopUp
            data={selected}
            onFix={() => {
              // mock action
              console.log("Fix clicked for:", selected);
            }}
          />
        </div>

        {/* Card list */}
        <div className="max-w-md space-y-6">
          {mockFindings.map((f, i) => (
            <VulnerabilityCard
              key={i}
              data={f}
              selected={i === selectedIndex}
              onClick={() => setSelectedIndex(i)}
            />
          ))}
        </div>
      </div>
    </main>
  );
}
