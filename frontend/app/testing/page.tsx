// src/app/testing/page.tsx
"use client";

import * as React from "react";
import { VulnerabilityCard } from "../../components/Vulnerability";
import { VulnerabilityPopUp } from "../../components/VulnerabilityPopUp";
import { mockFindings } from "./MockFindings";

type FixState = "default" | "fixing" | "fixed";

function keyOf(f: { filePath: string; line: number; title: string }) {
  // stable per-vulnerability key without adding new backend fields
  return `${f.filePath}:${f.line}:${f.title}`;
}

export default function TestingPage() {
  const [selectedIndex, setSelectedIndex] = React.useState(0);

  // Store state PER vulnerability (so it persists when you navigate away)
  const [states, setStates] = React.useState<Record<string, FixState>>(() => {
    const init: Record<string, FixState> = {};
    for (const f of mockFindings) init[keyOf(f)] = "default";
    return init;
  });

  const selected = mockFindings[selectedIndex];
  const selectedKey = keyOf(selected);
  const selectedState: FixState = states[selectedKey] ?? "default";

  const goNext = React.useCallback(() => {
    setSelectedIndex((i) => (i + 1) % mockFindings.length);
  }, []);

  const onFix = React.useCallback(() => {
    // IMPORTANT: do NOT advance here
    setStates((prev) => ({
      ...prev,
      [selectedKey]: "fixing",
    }));

    // ---- BACKEND QUEUE PLACEHOLDER ----
    // When your backend says this vulnerability is fixed,
    // call setStates and flip it to "fixed".
    //
    // For now, you can simulate it like this (optional):
    // setTimeout(() => {
    //   setStates((prev) => ({ ...prev, [selectedKey]: "fixed" }));
    // }, 2000);
    // ----------------------------------
  }, [selectedKey]);

  // Example helper you can call once your backend queue comes in:
  // (Use filePath/line/title to locate which vuln got fixed.)
  const markFixedFromBackend = React.useCallback(
    (f: (typeof mockFindings)[number]) => {
      const k = keyOf(f);
      setStates((prev) => ({ ...prev, [k]: "fixed" }));
    },
    []
  );

  // (optional) expose for quick manual testing in devtools:
  // window.__markFixed = () => markFixedFromBackend(selected);
  React.useEffect(() => {
    // @ts-ignore
    window.__markFixed = () => markFixedFromBackend(selected);
  }, [markFixedFromBackend, selected]);

  return (
    <main className="min-h-screen bg-slate-950 px-8 py-10">
      <div className="max-w-4xl space-y-10">
        {/* PopUp mirrors the SELECTED card's state */}
        <div className="max-w-3xl">
          <VulnerabilityPopUp
            data={selected}
            state={selectedState}
            onFix={() => onFix()}
            onNext={goNext} // only used when state is fixing/fixed
          />
        </div>

        {/* Card list (each card uses its own stored state) */}
        <div className="max-w-md space-y-6">
          {mockFindings.map((f, i) => {
            const k = keyOf(f);
            const s: FixState = states[k] ?? "default";

            return (
              <VulnerabilityCard
                key={k}
                data={f}
                selected={i === selectedIndex}
                onClick={() => setSelectedIndex(i)}
                state={s}
              />
            );
          })}
        </div>
      </div>
    </main>
  );
}
