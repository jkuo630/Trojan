// src/app/testing/page.tsx
"use client";

import * as React from "react";
import { VulnerabilityCard } from "../../components/Vulnerability";
import { mockFindings } from "./MockFindings";

export default function TestingPage() {
  const [selectedIndex, setSelectedIndex] = React.useState(0);

  return (
    <main className="min-h-screen bg-slate-950 px-8 py-10">
      <div className="max-w-md space-y-6">
        {/* This wrapper just helps it resemble your screenshot */}
        <div className="space-y-6">
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
