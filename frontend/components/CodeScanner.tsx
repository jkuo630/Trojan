"use client";

import React, { useEffect, useState, useRef, memo } from "react";
import { createHighlighter, type ThemedToken } from "shiki";
import { motion, AnimatePresence } from "framer-motion";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export interface CodeAnnotation {
  line: number;
  type: "success" | "error" | "warning";
  label?: string;
}

interface CodeScannerProps {
  code: string;
  language?: string;
  className?: string;
  annotations?: CodeAnnotation[];
  onScanLine?: (lineIndex: number) => void;
  onScanComplete?: () => void;
}

interface CodeLineProps {
  line: ThemedToken[];
  lineIndex: number;
  isScanned: boolean;
  isScanning: boolean;
  isPending: boolean;
  annotation?: CodeAnnotation;
}

const CodeLine = memo(function CodeLine({
  line,
  lineIndex,
  isScanned,
  isScanning,
  isPending,
  annotation,
}: CodeLineProps) {
  const lineNum = lineIndex + 1;

  return (
    <motion.tr
      id={`line-${lineIndex}`} // Add ID for scrolling
      initial={false}
      animate={{
        opacity: isPending ? 0.6 : 1,
        filter: isPending ? "blur(0.5px)" : "blur(0px)",
        backgroundColor:
          isScanned && annotation
            ? annotation.type === "error"
              ? "rgba(220, 38, 38, 0.15)"
              : annotation.type === "success"
              ? "rgba(22, 163, 74, 0.15)"
              : annotation.type === "warning"
              ? "rgba(234, 179, 8, 0.15)"
              : "transparent"
            : "transparent",
      }}
      transition={{ duration: 0.3 }}
      className={cn(
        "relative transition-all",
        // Border logic
        isScanned && annotation?.type === "error" && "border-l-2 border-red-500",
        isScanned && annotation?.type === "success" && "border-l-2 border-green-500",
        isScanned && annotation?.type === "warning" && "border-l-2 border-yellow-500",
        "border-l-2 border-transparent"
      )}
    >
      {/* Line Number */}
      <td
        className={cn(
          "w-12 select-none pr-4 text-right align-top text-xs opacity-70 whitespace-nowrap relative pt-[5px]",
          isScanning ? "text-cyan-400 font-bold" : "text-slate-600"
        )}
      >
        {lineNum}
      </td>

      {/* Code Line */}
      <td className="relative align-top whitespace-pre-wrap break-all leading-6 w-full">
        <span id={`code-span-${lineIndex}`} className="inline">
          {line.length === 0 ? (
            <span>&nbsp;</span>
          ) : (
            line.map((token, tokenIndex) => (
              <span key={tokenIndex} style={{ color: token.color }}>
                {token.content}
              </span>
            ))
          )}
        </span>

        {/* Inline Annotation Label */}
        <AnimatePresence>
          {isScanned && annotation?.label && (
            <motion.span
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className={cn(
                "ml-4 inline-flex items-center rounded px-2 py-0.5 text-xs font-medium",
                annotation.type === "error" && "bg-red-500/20 text-red-200",
                annotation.type === "success" && "bg-green-500/20 text-green-200",
                annotation.type === "warning" && "bg-yellow-500/20 text-yellow-200"
              )}
            >
              {annotation.label}
            </motion.span>
          )}
        </AnimatePresence>
      </td>
    </motion.tr>
  );
});

export function CodeScanner({
  code,
  language = "typescript",
  className,
  annotations = [],
  onScanLine,
  onScanComplete,
}: CodeScannerProps) {
  const [tokens, setTokens] = useState<ThemedToken[][]>([]);
  const [loading, setLoading] = useState(true);
  const [activeLineIndex, setActiveLineIndex] = useState(-1);
  const [visualScanRect, setVisualScanRect] = useState<{
    top: number;
    height: number;
  } | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    async function highlight() {
      if (code === null || code === undefined) return;

      const highlighter = await createHighlighter({
        themes: ["github-dark"],
        langs: [
          "typescript",
          "javascript",
          "tsx",
          "jsx",
          "html",
          "css",
          "json",
          language,
        ],
      });

      const result = highlighter.codeToTokens(code, {
        lang: language as any,
        theme: "github-dark",
      });

      setTokens(result.tokens);
      setLoading(false);
    }

    highlight();
  }, [code, language]);

  // Scanning Logic
  useEffect(() => {
    if (loading || tokens.length === 0) return;

    let currentLogicalLine = 0;
    let currentVisualLine = 0;
    let animationFrameId: number;

    const processFrame = () => {
      const LINES_PER_FRAME = 0.5; // Adjust for speed (higher = faster)
      
      const container = containerRef.current;
      if (!container) return; // Should not happen if mounted

      // Perform multiple scan steps per frame to increase speed
      for (let i = 0; i < LINES_PER_FRAME; i++) {
        // 1. Check completion
        if (currentLogicalLine >= tokens.length) {
          setVisualScanRect(null);
          setActiveLineIndex(tokens.length);
          onScanComplete?.();
          return; // Stop animation
        }

        // 2. Notify callback for new logical line start
        if (currentVisualLine === 0) {
            onScanLine?.(currentLogicalLine);
        }

        // 3. Logic to determine next step (wrap vs next line)
        const codeSpan = document.getElementById(`code-span-${currentLogicalLine}`);
        
        if (codeSpan) {
            const rects = codeSpan.getClientRects();
            
            // Check if we still have visual lines in this logical line
            if (currentVisualLine < rects.length - 1) {
                // Stay on this line, next visual segment
                currentVisualLine++;
            } else {
                // Done with this line, move to next
                currentLogicalLine++;
                currentVisualLine = 0;
            }
        } else {
            // Fallback if DOM missing
            currentLogicalLine++;
            currentVisualLine = 0;
        }
      }

      // 4. Update Visual State (ONCE per frame)
      // Use the *last* processed position for the UI update
      
      // Since the loop might have pushed currentLogicalLine past the end, clamp it or handle it
      if (currentLogicalLine < tokens.length) {
          setActiveLineIndex(currentLogicalLine);

          // Calculate Scroll Position & Visual Rect
          const codeSpan = document.getElementById(`code-span-${currentLogicalLine}`);
          const row = document.getElementById(`line-${currentLogicalLine}`);

          if (codeSpan && row) {
             const rects = codeSpan.getClientRects();
             // Safety check for index
             const safeVisualLine = Math.min(currentVisualLine, rects.length - 1);
             
             if (safeVisualLine >= 0) {
                 const currentRect = rects[safeVisualLine];
                 const containerRect = container.getBoundingClientRect();

                 const relativeTop = currentRect.top - containerRect.top + container.scrollTop;
                 
                 setVisualScanRect({
                     top: relativeTop,
                     height: currentRect.height
                 });

                 // Scroll
                 const scrollTarget = relativeTop - (container.clientHeight / 2) + (currentRect.height / 2);
                 container.scrollTo({ top: scrollTarget, behavior: "auto" });
             }
          }
      } else {
          // Final state if we overshot in the loop
           setVisualScanRect(null);
           setActiveLineIndex(tokens.length);
           onScanComplete?.();
           return;
      }

      // Schedule next frame
      animationFrameId = requestAnimationFrame(processFrame);
    };

    // Start scanning
    // Small timeout to allow initial render/paint
    const timeoutId = setTimeout(() => {
        animationFrameId = requestAnimationFrame(processFrame);
    }, 100);

    return () => {
        clearTimeout(timeoutId);
        cancelAnimationFrame(animationFrameId);
    };
  }, [loading, tokens, annotations]);

  if (loading && (code === null || code === undefined)) {
    return (
      <div
        className={cn(
          "relative overflow-hidden rounded-xl bg-[#0d1117] p-6 font-mono text-sm shadow-2xl h-full flex items-center justify-center",
          className
        )}
      >
        <div className="flex flex-col items-center gap-4">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
          <p className="text-gray-500 animate-pulse">Initializing Scanner...</p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl bg-[#0d1117] p-6 font-mono text-sm shadow-2xl",
        className
      )}
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-blue-900/10 via-transparent to-transparent opacity-40" />

      {/* Code Container */}
      <div
        ref={containerRef}
        id="code-container"
        className="relative z-10 overflow-auto h-full"
      >
        {/* Floating Scan Highlight */}
        {visualScanRect && (
          <motion.div
            initial={false}
            animate={{
              top: visualScanRect.top,
              height: visualScanRect.height,
            }}
            transition={{ duration: 0, ease: "linear" }}
            className="absolute left-0 w-full bg-cyan-400/15 border-l-2 border-cyan-400 z-0 pointer-events-none"
          />
        )}

        <table className="w-full border-collapse table-fixed">
          <tbody>
            {tokens.map((line, lineIndex) => {
              const lineNum = lineIndex + 1;
              const annotation = annotations.find((a) => a.line === lineNum);

              // State for this line
              const isScanned = lineIndex < activeLineIndex;
              const isScanning = lineIndex === activeLineIndex;
              const isPending = lineIndex > activeLineIndex;

              return (
                <CodeLine
                  key={lineIndex}
                  line={line}
                  lineIndex={lineIndex}
                  isScanned={isScanned}
                  isScanning={isScanning}
                  isPending={isPending}
                  annotation={annotation}
                />
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
