"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { CodeScanner, type CodeAnnotation } from "@/components/CodeScanner";
import { FileCode, ShieldAlert, CheckCircle, AlertTriangle, FileText, ChevronRight, Terminal, Cpu, Activity } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const scanLogs: { line: number; message: string }[] = [];

interface ScannerDemoProps {
  initialCode?: string | null;
  repoFiles?: { 
    name: string; 
    path: string; 
    functions?: string[];
    vulnerabilities?: CodeAnnotation[];
  }[];
  currentFileIndex?: number;
  onFileSelect?: (index: number) => void;
  onScanStart?: () => void; // Called when scan animation starts
  onScanComplete?: () => void;
  wsConnected?: boolean;
  authVulnerabilities?: any[]; // Auth vulnerabilities from the agent
  completedFiles?: Set<number>; // Set of completed file indices
  scanStatus?: string; // Current scan status message
  currentFilePath?: string; // Current file path for breadcrumb
}

export default function ScannerDemo({ 
  initialCode, 
  repoFiles, 
  currentFileIndex = 0,
  onFileSelect,
  onScanStart,
  onScanComplete,
  wsConnected = false,
  authVulnerabilities = [],
  completedFiles = new Set(),
  scanStatus = "",
  currentFilePath = ""
}: ScannerDemoProps) {
  const [foundIssues, setFoundIssues] = useState<CodeAnnotation[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const [severityFilter, setSeverityFilter] = useState<"all" | "low" | "medium" | "high">("all");
  const [vulnFilter, setVulnFilter] = useState<"all" | "low" | "medium" | "high">("all");
  const [scannedLineIndex, setScannedLineIndex] = useState(-1); // Track the highest scanned line
  
  // Track when initialCode prop changes
  useEffect(() => {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'ScannerDemo.tsx:47',message:'initialCode prop changed',data:{codeIsNull:initialCode===null,codeIsUndefined:initialCode===undefined,codeLength:initialCode?.length||0,codeHash:initialCode?initialCode.substring(0,20)+'...':null},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
  }, [initialCode]);
  
  // Wrapper to log scannedLineIndex updates - use useCallback to stabilize reference
  const handleScanProgress = useCallback((lineIndex: number) => {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'ScannerDemo.tsx:50',message:'handleScanProgress called',data:{lineIndex,lineNumber:lineIndex+1},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'E'})}).catch(()=>{});
    // #endregion
    setScannedLineIndex(prev => {
      // Only update if this is a higher line index
      if (lineIndex > prev) {
        return lineIndex;
      }
      return prev;
    });
  }, []);

  // Get current file annotations from repoFiles
  const fileAnnotations = repoFiles && repoFiles[currentFileIndex]?.vulnerabilities 
    ? repoFiles[currentFileIndex].vulnerabilities 
    : [];

  // Convert auth vulnerabilities to annotations for current file
  const currentFile = repoFiles?.[currentFileIndex];
  const filePath = currentFilePath || currentFile?.path || "";
  
  // Filter auth vulnerabilities for current file and convert to CodeAnnotation format
  const authAnnotations: CodeAnnotation[] = authVulnerabilities
    .filter((vuln: any) => {
      // Match vulnerabilities to current file by path
      const vulnPath = vuln.location || vuln.file_path || "";
      const fileName = filePath.split("/").pop() || currentFile?.name || "";
      const matchesFile = vulnPath.includes(fileName) || vulnPath === filePath || 
                         (vuln.file_index !== undefined && vuln.file_index === currentFileIndex);
      // Only create annotation if we have a line number (null/undefined means we can't highlight a specific line)
      return matchesFile && vuln.line !== null && vuln.line !== undefined;
    })
    .map((vuln: any): CodeAnnotation => {
      // Map severity to annotation type: high/medium/critical -> error (red), low -> warning (yellow)
      const annotationType: "error" | "warning" = 
        (vuln.severity === "high" || vuln.severity === "critical" || !vuln.severity) 
          ? "error"  // Red highlight for high severity
          : "warning"; // Yellow highlight for low severity
      
      return {
        line: vuln.line as number, // Line number is guaranteed from filter above
        type: annotationType,
        label: vuln.type || vuln.description || "Authentication vulnerability"
      };
    });

  // Combine file annotations with auth annotations (prioritize auth if duplicate line)
  const currentAnnotations = [...fileAnnotations, ...authAnnotations].reduce((acc: CodeAnnotation[], annotation: CodeAnnotation) => {
    // Remove duplicates based on line number, keep auth annotations (error) over file annotations
    const existing = acc.find(a => a.line === annotation.line);
    if (!existing) {
      acc.push(annotation);
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'ScannerDemo.tsx:96',message:'Annotation added',data:{line:annotation.line,type:annotation.type,annotationsCount:acc.length+1},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
      // #endregion
    } else if (annotation.type === "error" && existing.type !== "error") {
      // Replace with error type if it's more severe
      const index = acc.indexOf(existing);
      acc[index] = annotation;
    }
    return acc;
  }, []);
  
  // #region agent log
  useEffect(() => {
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'ScannerDemo.tsx:104',message:'currentAnnotations changed',data:{annotationsCount:currentAnnotations.length,annotations:currentAnnotations.map(a=>({line:a.line,type:a.type}))},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
  }, [currentAnnotations.length, JSON.stringify(currentAnnotations.map(a => `${a.line}-${a.type}`))]);
  // #endregion

  // Reset found issues and scan progress when file changes
  useEffect(() => {
    setFoundIssues([]);
    setScannedLineIndex(-1); // Always reset to -1, let animation progress naturally
  }, [currentFileIndex]);

  // Effect to log functions when a new file starts scanning
  useEffect(() => {
    if (repoFiles && repoFiles[currentFileIndex]) {
      const file = repoFiles[currentFileIndex] as any;
      const newLogs = [`Analyzing suspicious file: ${file.name}...`];
      
      if (file.riskLevel) {
        newLogs.push(`Risk Level: ${file.riskLevel.toUpperCase()}`);
      }
      
      if (file.reason) {
        newLogs.push(`Reason: ${file.reason}`);
      }
      
      if (file.functions && file.functions.length > 0) {
        newLogs.push(`Suspicious functions: ${file.functions.join(", ")}`);
      }

      if (file.vulnerabilities && file.vulnerabilities.length > 0) {
        newLogs.push(`Found ${file.vulnerabilities.length} potential issues during static analysis.`);
      }
      
      newLogs.forEach(msg => {
         setLogs(prev => [...prev, `[${new Date().toLocaleTimeString().split(' ')[0]}] ${msg}`]);
      });
    }
  }, [currentFileIndex, repoFiles]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const handleScanLine = (lineIndex: number) => {
    // Check if the current line (lineIndex + 1) has an annotation
    const found = currentAnnotations?.find(a => a.line === lineIndex + 1);
    if (found && found.label) {
      setFoundIssues(prev => {
        if (prev.find(p => p.line === found.line)) return prev;
        
        // Add log for the found issue
        setLogs(prevLogs => [...prevLogs, `[${new Date().toLocaleTimeString().split(' ')[0]}] ALERT: ${found.label} detected at line ${found.line}`]);
        
        return [...prev, found];
      });
    }

    // Check for hardcoded logs (if any)
    const log = scanLogs.find(l => l.line === lineIndex);
    if (log) {
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString().split(' ')[0]}] ${log.message}`]);
    }
  };

  const demoFiles: { name: string; status: string }[] = [];

  // Use repoFiles if available, otherwise fallback to demoFiles
  const displayFiles = repoFiles 
    ? repoFiles.map((f, i) => ({
        name: f.name,
        status: completedFiles.has(i) ? "completed" : i === currentFileIndex ? "scanning" : "pending"
      }))
    : demoFiles;

  const currentFileName = repoFiles ? repoFiles[currentFileIndex]?.name : "";

  // Filter vulnerabilities: only show ones that have been scanned AND match severity filter
  const filteredVulnerabilities = authVulnerabilities.filter((vuln: any) => {
    // Only show vulnerabilities for lines that have been scanned
    // Line numbers are 1-indexed, scannedLineIndex is 0-indexed
    if (vuln.line !== null && vuln.line !== undefined) {
      const vulnLineIndex = vuln.line - 1; // Convert to 0-indexed
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'ScannerDemo.tsx:180',message:'Filtering vulnerability',data:{vulnLine:vuln.line,vulnLineIndex,scannedLineIndex,willShow:vulnLineIndex<=scannedLineIndex},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'E'})}).catch(()=>{});
      // #endregion
      if (vulnLineIndex > scannedLineIndex) {
        return false; // Haven't scanned this line yet
      }
    }
    
    // Apply severity filter
    if (vulnFilter === "all") return true;
    const severity = (vuln.severity?.toLowerCase() || "medium");
    return severity === vulnFilter;
  });

  // Get agent activity message from scanStatus
  const getAgentMessage = () => {
    if (scanStatus.includes("reviewing") || scanStatus.includes("Analyzing")) {
      return scanStatus;
    }
    return "Agent currently reviewing file for any authorization-related vulnerabilities";
  };

  const getAgentSubMessage = () => {
    if (scanStatus.includes("password") || scanStatus.includes("username")) {
      return "Checking for password and username controls.";
    }
    return "Analyzing code for security vulnerabilities.";
  };

  return (
    <main className="flex h-full w-full bg-[#0E141A] text-white overflow-hidden flex-col">
      <div className="flex-1 flex min-h-0 items-start gap-6 pt-0 px-8 overflow-hidden" style={{ boxSizing: 'border-box' }}>
        <div className="flex flex-col flex-1 min-w-0 min-h-0" style={{ boxSizing: 'border-box' }}>
          {/* File Path Bar with Scanning Button and Severity - Above Code Box */}
          {currentFilePath && (
            <div className="h-7.5 bg-[#0E141A] flex items-center justify-between flex-shrink-0 mb-0">
              <div className="flex items-center gap-2">
                <div className="h-2.5 w-2.5 rounded-full bg-[#6699C9]"></div>
                <span className="text-sm bg-gradient-to-r from-[#6699C9] to-[#6699C9]/40 bg-clip-text text-transparent">{currentFilePath}</span>
                <div className="flex items-center gap-1.5 rounded-lg bg-[#344F67]/40 px-1.5 py-0.2">
                  <img src="/scan.svg" alt="scan" className="h-3 w-3" />
                  <span className="text-[12px] text-[#6699C9]">Scanning</span>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-xs text-[#D6D6D6] text-opacity-60 font-bold">Severity</span>
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-full bg-[#F1FA8C]"></div>
                    <span className="text-xs text-[#D6D6D6] text-opacity-60">Low</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-full bg-[#F1B24C]"></div>
                    <span className="text-xs text-[#D6D6D6] text-opacity-60">Medium</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-full bg-[#F14C4C]"></div>
                    <span className="text-xs text-[#D6D6D6] text-opacity-60">High</span>
                  </div>
                </div>
              </div>
            </div>
          )}
          {/* Left Sidebar and Code Section in One Box */}
          <div className="flex border border-[#D6D6D6] overflow-hidden" style={{ boxSizing: 'border-box', height: currentFilePath ? 'calc(100vh - 64px - 230px)' : 'calc(100vh - 96px - 234px)' }}>
          {/* Left Sidebar - Suspicious Files */}
          <div className="w-[150px] flex-shrink-0 bg-[#0E141A] flex flex-col">
            <div className="p-3 flex-shrink-0">
              <h2 className="text-xs font-semibold text-white flex items-center gap-2">
                <span>Suspicious</span>
              </h2>
            </div>

          {/* File List */}
          <div className="flex-1 overflow-y-auto scrollbar-hide p-1.5">
            <div className="space-y-0.5">
              {displayFiles.map((file, i) => {
                const isActive = i === currentFileIndex;
                const isCompleted = file.status === "completed";
                const isScanning = file.status === "scanning";
                
                return (
                  <div
                    key={file.name + i}
                    onClick={() => onFileSelect?.(i)}
                    className={`flex items-center gap-1.5 rounded px-1.5 py-1 text-xs cursor-pointer transition-colors ${
                      isActive
                        ? "bg-[#344F67] bg-opacity-40 text-[#6699C9]"
                        : isCompleted
                        ? "text-[#D6D6D6] text-opacity-60 hover:bg-white/5"
                        : "text-[#D6D6D6] text-opacity-40 hover:bg-white/5"
                    }`}
                  >
                    <img src="/file.svg" alt="file" className="h-3 w-3 flex-shrink-0" />
                    <span className="flex-1 truncate">{file.name}</span>
                    {isCompleted && (
                      <CheckCircle className="h-3 w-3 flex-shrink-0 text-[#4CF177]" />
                    )}
                    {isActive && !isCompleted && (
                      <div className="h-1.5 w-1.5 rounded-full bg-[#6699C9] flex-shrink-0"></div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

            {/* Center - Code Editor */}
            <div className="flex-1 flex flex-col min-w-0 min-h-0 bg-[#0E141A] border-l border-[#D6D6D6] overflow-hidden">

          {/* Code Area */}
          <div className="flex-1 overflow-hidden bg-[#0E141A] min-h-0 flex flex-col">
            <CodeScanner 
              code={initialCode || ""} 
              language="typescript" 
              className="bg-[#0E141A] flex-1 min-h-0"
              annotations={currentAnnotations || []}
              onScanLine={handleScanLine}
              onScanStart={onScanStart}
              onScanComplete={onScanComplete}
              onScanProgress={handleScanProgress}
              skipAnimation={false}
            />
          </div>
        </div>
        </div>
        </div>

        {/* Right Sidebar - Vulnerabilities */}
        <div className="w-[280px] flex-shrink-0 bg-[#0E141A] flex flex-col overflow-hidden">
          <div className="p-4 flex-shrink-0">
            <h2 className="text-xs font-semibold text-white">Vulnerabilities</h2>
          </div>

          {/* Filter Tabs */}
          <div className="px-4 py-2 flex items-center gap-2 flex-shrink-0">
            {(["all", "low", "medium", "high"] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setVulnFilter(filter)}
                className={`px-2 py-1 text-[10px] transition-colors ${
                  vulnFilter === filter
                    ? "text-white underline underline-offset-4 decoration-2"
                    : "text-[#D6D6D6] text-opacity-60 hover:text-opacity-100"
                }`}
              >
                {filter.charAt(0).toUpperCase() + filter.slice(1)}
              </button>
            ))}
          </div>

          {/* Vulnerabilities List */}
          <div className="flex-1 overflow-y-auto scrollbar-hide p-4">
            <div className="space-y-3">
              <AnimatePresence mode="popLayout">
                {filteredVulnerabilities.map((vuln: any, i: number) => {
                  const severity = (vuln.severity?.toLowerCase() || "medium");
                  const isHigh = severity === "high" || severity === "critical";
                  const isLow = severity === "low";
                  const isMedium = severity === "medium";
                  
                  const severityColor = isHigh ? "text-[#F14C4C]" : isLow ? "text-[#F1FA8C]" : "text-[#F1B24C]";
                  const severityText = isHigh ? "High" : isLow ? "Low" : "Medium";
                  
                  return (
                    <motion.div
                      key={`auth-${i}-${vuln.location}-${vuln.line || 0}`}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.95 }}
                      className="rounded-lg border border-[#D1D1D1] bg-[#0E141A] p-3"
                    >
                      <h3 className="text-xs font-medium text-white mb-2">
                        {vuln.type || "Authentication Vulnerability"}
                      </h3>
                      <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className={`h-3 w-3 ${isLow ? "text-[#F1FA8C]" : severityColor}`} />
                        <span className={`text-[10px] ${isLow ? "text-[#4CF177]" : severityColor}`}>
                          {severityText} Severity Vulnerability
                        </span>
                      </div>
                      <p className="text-[10px] text-[#D6D6D6] mb-2">
                        {vuln.description || "No description available"}
                      </p>
                      <div className="flex items-center gap-1.5 text-[10px] text-[#D6D6D6] text-opacity-60">
                        <FileText className="h-3 w-3" />
                        <span>
                          {vuln.location || vuln.file_path || "Unknown file"}
                          {vuln.line && ` (Line ${vuln.line})`}
                        </span>
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
              
              {filteredVulnerabilities.length === 0 && (
                <div className="py-8 text-center text-xs text-[#D6D6D6] text-opacity-40">
                  <div className="mb-2 flex justify-center">
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    >
                      <FileText className="h-8 w-8 opacity-20" />
                    </motion.div>
                  </div>
                  {vulnFilter === "all" ? "No vulnerabilities found" : `No ${vulnFilter} severity vulnerabilities`}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Footer - Agent Activity */}
      <div className="flex-shrink-0 min-h-[170px] py-8 flex items-center justify-between px-8">
        <div className="flex-1">
          <div className="flex items-center gap-2 text-sm text-[#D6D6D6]">
            <span>{getAgentMessage()}</span>
            <ChevronRight className="h-4 w-4 text-[#D6D6D6] text-opacity-60" />
          </div>
          <p className="text-xs text-[#D6D6D6] text-opacity-60 mt-2">{getAgentSubMessage()}</p>
        </div>
        <button className="text-sm text-[#D6D6D6] text-opacity-60 hover:text-[#D6D6D6] hover:opacity-100 transition-colors underline underline-offset-2">
          View Full Logs
        </button>
      </div>
    </main>
  );
}
