"use client";

import React, { useEffect, useState, useRef, memo } from "react";
import { createHighlighter, type ThemedToken } from "shiki";
import { motion, AnimatePresence } from "framer-motion";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { VulnerabilityPopUp, type VulnerabilityCardData } from "@/components/VulnerabilityPopUp";

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
  onScanStart?: () => void; // Called when animation actually starts
  onScanComplete?: () => void;
  onScanProgress?: (scannedLineIndex: number) => void; // Called when a line is scanned
  skipAnimation?: boolean; // If true, skip animation and show all lines as scanned
  selectedLine?: number | null; // Line number (1-indexed) to show vulnerability popup for
  selectedVulnerability?: VulnerabilityCardData | null; // Vulnerability data to display in popup
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
          // Remove isScanning highlight - using visualScanRect instead
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
          "w-12 select-none pr-4 text-right align-top text-[10px] opacity-70 whitespace-nowrap relative pt-[2px]",
          isScanning ? "text-cyan-400 font-bold" : "text-slate-600"
        )}
      >
        {lineNum}
      </td>

      {/* Code Line */}
      <td className="relative align-top whitespace-pre-wrap break-all leading-4 w-full">
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
  onScanStart,
  onScanComplete,
  onScanProgress,
  skipAnimation = false,
  selectedLine = null,
  selectedVulnerability = null,
}: CodeScannerProps) {
  const [tokens, setTokens] = useState<ThemedToken[][]>([]);
  const [loading, setLoading] = useState(true);
  const [activeLineIndex, setActiveLineIndex] = useState(-1);
  const [visualScanRect, setVisualScanRect] = useState<{
    top: number;
    height: number;
  } | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animationStartedRef = useRef(false);
  const lastTokensKeyRef = useRef<string>('');
  const onScanProgressRef = useRef(onScanProgress);
  const onScanCompleteRef = useRef(onScanComplete);
  const onScanStartRef = useRef(onScanStart);
  const selectedLineRef = useRef<number | null>(null);
  
  // Update refs when callbacks change
  useEffect(() => {
    onScanProgressRef.current = onScanProgress;
    onScanCompleteRef.current = onScanComplete;
    onScanStartRef.current = onScanStart;
  }, [onScanProgress, onScanComplete, onScanStart]);

  useEffect(() => {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:130',message:'Code prop changed - highlight effect triggered',data:{codeIsNull:code===null,codeIsUndefined:code===undefined,codeLength:code?.length||0,codeHash:code?code.substring(0,20)+'...':null},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
    
    async function highlight() {
      if (code === null || code === undefined) {
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:131',message:'Code is null/undefined, skipping highlight',data:{codeIsNull:code===null,codeIsUndefined:code===undefined},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
        // #endregion
        return;
      }

      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:138',message:'Starting code highlight',data:{codeLength:code.length,codePreview:code.substring(0,50)},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
      // #endregion

      // Reset animation state when code changes
      animationStartedRef.current = false;
      lastTokensKeyRef.current = ''; // Reset token key to allow new animation
      setActiveLineIndex(-1);
      setVisualScanRect(null);

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

  // Scroll to selected line when it changes
  useEffect(() => {
    if (selectedLine !== null && selectedLine !== selectedLineRef.current && containerRef.current && tokens.length > 0) {
      selectedLineRef.current = selectedLine;
      const lineIndex = selectedLine - 1; // Convert to 0-indexed
      if (lineIndex >= 0 && lineIndex < tokens.length) {
        const lineElement = document.getElementById(`line-${lineIndex}`);
        if (lineElement && containerRef.current) {
          const containerRect = containerRef.current.getBoundingClientRect();
          const lineRect = lineElement.getBoundingClientRect();
          const relativeTop = lineRect.top - containerRect.top + containerRef.current.scrollTop;
          const scrollTarget = relativeTop - (containerRef.current.clientHeight / 2) + (lineRect.height / 2);
          containerRef.current.scrollTo({ top: scrollTarget, behavior: "smooth" });
        }
      }
    }
  }, [selectedLine, tokens.length]);

  // Scanning Logic
  useEffect(() => {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:159',message:'Scanning effect triggered',data:{loading,tokensLength:tokens.length,skipAnimation,annotationsCount:annotations.length,animationStarted:animationStartedRef.current},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
    // #endregion
    if (loading || tokens.length === 0) {
      // Reset animation state when code is loading or empty
      animationStartedRef.current = false;
      setActiveLineIndex(-1);
      setVisualScanRect(null);
      return;
    }

    // If skipAnimation is true, immediately set to completed state
    if (skipAnimation) {
      setActiveLineIndex(tokens.length);
      setVisualScanRect(null);
      onScanProgressRef.current?.(tokens.length - 1); // Notify that all lines are scanned
      onScanCompleteRef.current?.();
      animationStartedRef.current = true;
      return;
    }

    // Check if this is new code (tokens changed) - if so, reset animation
    const tokensKey = tokens.length > 0 ? `${tokens.length}-${tokens[0]?.length || 0}` : 'empty';
    
    if (tokensKey !== lastTokensKeyRef.current) {
      // New code loaded, reset animation
      animationStartedRef.current = false;
      setActiveLineIndex(-1);
      setVisualScanRect(null);
      lastTokensKeyRef.current = tokensKey;
    } else if (animationStartedRef.current) {
      // Same code, animation already running - don't restart
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:178',message:'Animation already started, skipping restart',data:{tokensKey},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
      // #endregion
      return;
    }

    let currentLogicalLine = 0;
    let currentVisualLine = 0;
    let animationFrameId: number;
    let accumulatedProgress = 0; // Track fractional line progress across frames
    let frameCount = 0; // Count frames to control speed

    const processFrame = () => {
      const LINES_PER_FRAME = 4; // Lines per frame (fractional = slower)
      const FRAME_DELAY = Math.ceil(1 / LINES_PER_FRAME); // Process one step every N frames
      
      const container = containerRef.current;
      if (!container) return; // Should not happen if mounted

      frameCount++;
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:184',message:'processFrame called',data:{frameCount,currentLogicalLine,currentVisualLine,tokensLength:tokens.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'D'})}).catch(()=>{});
      // #endregion
      
      // Only process one step every FRAME_DELAY frames (slows down animation)
      if (frameCount < FRAME_DELAY) {
        // Still update visual state but don't advance - keep the highlight visible
        // Update visual state for current position
        if (currentLogicalLine < tokens.length) {
          setActiveLineIndex(currentLogicalLine);
          const codeSpan = document.getElementById(`code-span-${currentLogicalLine}`);
          const row = document.getElementById(`line-${currentLogicalLine}`);
          if (codeSpan && row) {
            const rects = codeSpan.getClientRects();
            const safeVisualLine = Math.min(currentVisualLine, rects.length - 1);
            if (safeVisualLine >= 0) {
              const currentRect = rects[safeVisualLine];
              const containerRect = container.getBoundingClientRect();
              const relativeTop = currentRect.top - containerRect.top + container.scrollTop;
              setVisualScanRect({
                top: relativeTop,
                height: currentRect.height
              });
            }
          }
        }
        animationFrameId = requestAnimationFrame(processFrame);
        return;
      }
      
      frameCount = 0; // Reset counter

      // Process one step (advance by one line)
      // Process only once per FRAME_DELAY frames
      // 1. Check completion
        if (currentLogicalLine >= tokens.length) {
          setVisualScanRect(null);
          setActiveLineIndex(tokens.length);
          // Report final line as scanned
          onScanProgressRef.current?.(tokens.length - 1);
          onScanCompleteRef.current?.();
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
                // Report progress when we finish scanning a line
                // #region agent log
                fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:242',message:'Line scanned, calling onScanProgress',data:{lineIndex:currentLogicalLine,lineNumber:currentLogicalLine+1},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
                // #endregion
                onScanProgressRef.current?.(currentLogicalLine);
                currentLogicalLine++;
                currentVisualLine = 0;
            }
        } else {
            // Fallback if DOM missing
            currentLogicalLine++;
            currentVisualLine = 0;
        }

      // 4. Update Visual State (ONCE per frame)
      // Use the *last* processed position for the UI update
      
      // Since the loop might have pushed currentLogicalLine past the end, clamp it or handle it
      if (currentLogicalLine < tokens.length) {
          // #region agent log
          fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:257',message:'Setting activeLineIndex',data:{activeLineIndex:currentLogicalLine,lineNumber:currentLogicalLine+1},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
          // #endregion
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
           onScanCompleteRef.current?.();
           return;
      }

      // Schedule next frame
      animationFrameId = requestAnimationFrame(processFrame);
    };

    // Start scanning
    // Small timeout to allow initial render/paint
    const timeoutId = setTimeout(() => {
        animationStartedRef.current = true;
        onScanStartRef.current?.(); // Notify that animation is starting
        animationFrameId = requestAnimationFrame(processFrame);
    }, 100);

    return () => {
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:359',message:'Scanning effect cleanup - cancelling animation',data:{animationStarted:animationStartedRef.current,activeLineIndex,hasAnimationFrame:!!animationFrameId},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
        // #endregion
        clearTimeout(timeoutId);
        cancelAnimationFrame(animationFrameId);
        // Don't reset animationStartedRef here - let it persist across re-renders
        // Only reset when code actually changes (handled in the loading check above)
    };
  }, [loading, tokens, skipAnimation]); // Removed callbacks from deps to prevent effect re-runs

  if (loading && (code === null || code === undefined)) {
    return (
      <div
        className={cn(
          "relative overflow-hidden rounded-xl bg-[#0E141A] p-6 font-mono text-[10px] shadow-2xl h-full flex items-center justify-center",
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
          "relative overflow-hidden bg-[#0E141A] font-mono text-[10px] flex flex-col",
          className
        )}
      >

      {/* Code Container */}
      <div
        ref={containerRef}
        id="code-container"
        className="relative z-10 overflow-auto flex-1 min-h-0 scrollbar-hide px-4 py-4"
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
              const showVulnerabilityPopup = selectedLine === lineNum && selectedVulnerability !== null;

              // State for this line
              const isScanned = lineIndex < activeLineIndex;
              const isScanning = lineIndex === activeLineIndex;
              const isPending = lineIndex > activeLineIndex;
              
              // #region agent log
              if (annotation) {
                fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'CodeScanner.tsx:373',message:'Line rendered with annotation',data:{lineIndex,lineNum,activeLineIndex,isScanned,isScanning,annotationType:annotation.type},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
              }
              // #endregion

              return (
                <React.Fragment key={lineIndex}>
                  <CodeLine
                    line={line}
                    lineIndex={lineIndex}
                    isScanned={isScanned}
                    isScanning={isScanning}
                    isPending={isPending}
                    annotation={annotation}
                  />
                  {showVulnerabilityPopup && selectedVulnerability && (
                    <tr>
                      <td colSpan={2} className="px-0 py-0">
                        <div className="px-4 pt-3 pb-2">
                          <VulnerabilityPopUp
                            data={selectedVulnerability}
                            state="default"
                          />
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
