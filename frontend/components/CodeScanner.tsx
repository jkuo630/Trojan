"use client";

import React, { useEffect, useState } from "react";
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
}

export function CodeScanner({
  code,
  language = "typescript",
  className,
  annotations = [],
}: CodeScannerProps) {
  const [tokens, setTokens] = useState<ThemedToken[][]>([]);
  const [loading, setLoading] = useState(true);
  const [activeLineIndex, setActiveLineIndex] = useState(-1);

  useEffect(() => {
    async function highlight() {
      const highlighter = await createHighlighter({
        themes: ["github-dark"],
        langs: ["typescript", "javascript", "tsx", "jsx", "html", "css", "json", language],
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

    let currentLine = 0;
    let timeoutId: NodeJS.Timeout;

    const processNextLine = () => {
      if (currentLine >= tokens.length) {
        setActiveLineIndex(tokens.length); // All done
        return;
      }

      setActiveLineIndex(currentLine);

      // Dynamic speed: faster for empty lines, slower for dense code
      const lineTokens = tokens[currentLine];
      const hasContent = lineTokens.some(t => t.content.trim().length > 0);
      const isAnnotation = annotations.some(a => a.line === currentLine + 1);
      
      let delay = 5; // Base speed (super fast)
      if (hasContent) delay += 15; // Reading time
      if (isAnnotation) delay += 80; // Brief pause on findings
      
      // Random variance for "human/machine" feel
      delay += Math.random() * 10;

      currentLine++;
      timeoutId = setTimeout(processNextLine, delay);
    };

    // Start scanning after a brief initial pause
    timeoutId = setTimeout(processNextLine, 500);

    return () => clearTimeout(timeoutId);
  }, [loading, tokens, annotations]);

  if (loading) {
    return <div className="p-4 font-mono text-sm text-gray-500">Loading visualization...</div>;
  }

  return (
    <div className={cn("relative overflow-hidden rounded-xl bg-[#0d1117] p-6 font-mono text-sm shadow-2xl", className)}>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-blue-900/10 via-transparent to-transparent opacity-40" />
      
      {/* Code Container */}
      <div className="relative z-10 overflow-auto">
        <table className="w-full border-collapse">
          <tbody>
            {tokens.map((line, lineIndex) => {
              const lineNum = lineIndex + 1;
              const annotation = annotations.find(a => a.line === lineNum);
              
              // State for this line
              const isScanned = lineIndex < activeLineIndex;
              const isScanning = lineIndex === activeLineIndex;
              const isPending = lineIndex > activeLineIndex;

              return (
                <motion.tr
                  key={lineIndex}
                  initial={false}
                  animate={{
                    opacity: isPending ? 0.3 : 1,
                    filter: isPending ? "blur(1px)" : "blur(0px)",
                    backgroundColor: isScanning 
                      ? "rgba(56, 189, 248, 0.1)" // Active scan highlight (blue)
                      : isScanned && annotation
                        ? annotation.type === "error" ? "rgba(220, 38, 38, 0.15)"
                        : annotation.type === "success" ? "rgba(22, 163, 74, 0.15)"
                        : annotation.type === "warning" ? "rgba(234, 179, 8, 0.15)"
                        : "transparent"
                      : "transparent",
                  }}
                  transition={{ duration: 0.2 }}
                  className={cn(
                    "relative transition-all",
                    // Border logic
                    isScanned && annotation?.type === "error" && "border-l-2 border-red-500",
                    isScanned && annotation?.type === "success" && "border-l-2 border-green-500",
                    isScanned && annotation?.type === "warning" && "border-l-2 border-yellow-500",
                    // Active scan border
                    isScanning && "border-l-2 border-cyan-400"
                  )}
                >
                  {/* Line Number */}
                  <td className="w-12 select-none pr-4 text-right align-top text-xs text-slate-600 opacity-50">
                    {lineNum}
                  </td>
                  
                  {/* Code Line */}
                  <td className="relative align-top">
                    {line.length === 0 ? (
                      <span>&nbsp;</span>
                    ) : (
                      line.map((token, tokenIndex) => (
                        <span
                          key={tokenIndex}
                          style={{ color: token.color }}
                        >
                          {token.content}
                        </span>
                      ))
                    )}
                    
                    {/* Active Scan Laser/Glow Effect */}
                    {isScanning && (
                      <motion.div
                        layoutId="scan-laser"
                        className="absolute bottom-0 left-0 h-[2px] w-full bg-cyan-400 shadow-[0_0_10px_2px_rgba(34,211,238,0.8)]"
                        initial={{ opacity: 0, scaleX: 0 }}
                        animate={{ opacity: 1, scaleX: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.1 }}
                      />
                    )}

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
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
