"use client";

import { useState, useRef, useEffect } from "react";
import type React from "react";
import { CodeScanner, type CodeAnnotation } from "@/components/CodeScanner";
import { FileCode, ShieldAlert, CheckCircle, AlertTriangle, FileText, ChevronRight, Terminal, Cpu, Activity, Key, Lock, Database, DatabaseZap, Code as CodeIcon, Shell, EyeOff, KeyRound, LockKeyhole } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { submitFixToBackend, type FileAnalysisData } from "@/types/security-fix";

const scanLogs: { line: number; message: string }[] = [];

// Map vulnerability types to icons based on agent/specialist type
function getVulnerabilityIcon(vulnType: string, vulnerabilityType?: string): React.ReactElement {
  const typeLower = (vulnType || "").toLowerCase();
  const vulnTypeLower = (vulnerabilityType || "").toLowerCase();
  
  // Check if it's an injection vulnerability (from backend event type or vuln type)
  if (vulnTypeLower === "injection_vulnerability" || typeLower.includes("sql injection") || 
      typeLower.includes("nosql injection") || typeLower.includes("command injection") ||
      typeLower.includes("code injection") || typeLower.includes("ldap injection") ||
      typeLower.includes("template injection") || typeLower.includes("xpath injection")) {
    if (typeLower.includes("sql")) {
      return <DatabaseZap className="h-4 w-4" />;
    } else if (typeLower.includes("command") || typeLower.includes("shell")) {
      return <Shell className="h-4 w-4" />;
    } else if (typeLower.includes("code")) {
      return <CodeIcon className="h-4 w-4" />;
    }
    return <Database className="h-4 w-4" />;
  }
  
  // Check if it's a sensitive data vulnerability
  if (vulnTypeLower === "sensitive_data_vulnerability" || typeLower.includes("hardcoded") ||
      typeLower.includes("api key") || typeLower.includes("password") || 
      typeLower.includes("secret") || typeLower.includes("credential") ||
      typeLower.includes("token") || typeLower.includes("exposed") ||
      typeLower.includes("plaintext") || typeLower.includes("pii")) {
    if (typeLower.includes("key") || typeLower.includes("credential")) {
      return <Key className="h-4 w-4" />;
    } else if (typeLower.includes("password")) {
      return <Lock className="h-4 w-4" />;
    }
    return <EyeOff className="h-4 w-4" />;
  }
  
  // Check if it's an authentication vulnerability
  if (vulnTypeLower === "auth_vulnerability" || typeLower.includes("auth") ||
      typeLower.includes("password policy") || typeLower.includes("session") ||
      typeLower.includes("jwt") || typeLower.includes("oauth") ||
      typeLower.includes("authentication")) {
    return <KeyRound className="h-4 w-4" />;
  }
  
  // Check if it's a cryptographic vulnerability
  if (vulnTypeLower === "cryptographic_vulnerability" || typeLower.includes("cryptographic") ||
      typeLower.includes("crypto") || typeLower.includes("hash") ||
      typeLower.includes("encryption") || typeLower.includes("ssl") ||
      typeLower.includes("tls") || typeLower.includes("certificate") ||
      typeLower.includes("md5") || typeLower.includes("sha1") ||
      typeLower.includes("weak key") || typeLower.includes("entropy")) {
    return <LockKeyhole className="h-4 w-4" />;
  }
  
  // Default to ShieldAlert for unknown types
  return <ShieldAlert className="h-4 w-4" />;
}

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
  repository?: string; // e.g., "owner/repo"
  suspiciousFiles?: any[]; // Full suspicious files data with risk_level, etc.
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
  repository,
  suspiciousFiles = []
}: ScannerDemoProps) {
  const [foundIssues, setFoundIssues] = useState<CodeAnnotation[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const [fixingVulnerability, setFixingVulnerability] = useState<number | null>(null);
  const [fixResults, setFixResults] = useState<Map<number, { success: boolean; message: string; pr_url?: string }>>(new Map());

  // Get current file annotations from repoFiles
  const fileAnnotations = repoFiles && repoFiles[currentFileIndex]?.vulnerabilities 
    ? repoFiles[currentFileIndex].vulnerabilities 
    : [];

  // Convert auth vulnerabilities to annotations for current file
  const currentFile = repoFiles?.[currentFileIndex];
  const currentFilePath = currentFile?.path || "";
  
  // Filter auth vulnerabilities for current file and convert to CodeAnnotation format
  const authAnnotations: CodeAnnotation[] = authVulnerabilities
    .filter((vuln: any) => {
      // Match vulnerabilities to current file by path
      const vulnPath = vuln.location || vuln.file_path || "";
      const fileName = currentFilePath.split("/").pop() || currentFile?.name || "";
      const matchesFile = vulnPath.includes(fileName) || vulnPath === currentFilePath || 
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
    } else if (annotation.type === "error" && existing.type !== "error") {
      // Replace with error type if it's more severe
      const index = acc.indexOf(existing);
      acc[index] = annotation;
    }
    return acc;
  }, []);

  // Reset found issues when file changes
  useEffect(() => {
    setFoundIssues([]);
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

  // Handler to fix a specific vulnerability
  const handleFixVulnerability = async (vulnerabilityIndex: number, vulnerability: any) => {
    if (!repository) {
      const newResults = new Map(fixResults);
      newResults.set(vulnerabilityIndex, { success: false, message: "Repository information not available" });
      setFixResults(newResults);
      return;
    }

    // Get GitHub token from localStorage
    const githubToken = localStorage.getItem("github_token");
    if (!githubToken) {
      const newResults = new Map(fixResults);
      newResults.set(vulnerabilityIndex, { success: false, message: "GitHub token not found. Please log in again." });
      setFixResults(newResults);
      return;
    }

    // Get current file data
    const currentFile = repoFiles?.[currentFileIndex];
    const suspiciousFile = suspiciousFiles?.[currentFileIndex];
    
    if (!currentFile || !suspiciousFile) {
      const newResults = new Map(fixResults);
      newResults.set(vulnerabilityIndex, { success: false, message: "File data not available" });
      setFixResults(newResults);
      return;
    }

    // Build single vulnerability array for this specific issue
    const singleVulnerability = {
      line: vulnerability.line,
      type: vulnerability.type || "Unknown vulnerability",
      severity: vulnerability.severity || "medium",
      description: vulnerability.description || "",
      location: vulnerability.location || currentFile.path,
    };

    // Build FileAnalysisData with only this vulnerability
    const fileAnalysisData: FileAnalysisData = {
      file_index: currentFileIndex,
      file_path: currentFile.path,
      file_name: currentFile.name,
      risk_level: suspiciousFile.risk_level || "medium",
      suspicious_functions: suspiciousFile.suspicious_functions || currentFile.functions || [],
      vulnerabilities: [singleVulnerability],
    };

    setFixingVulnerability(vulnerabilityIndex);
    
    // Clear previous result for this vulnerability
    const newResults = new Map(fixResults);
    newResults.delete(vulnerabilityIndex);
    setFixResults(newResults);

    try {
      setLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString().split(' ')[0]}] 🔧 Starting fix for: ${vulnerability.type}`,
      ]);

      const result = await submitFixToBackend(fileAnalysisData, repository, githubToken);
      
      if (result.success) {
        const resultData = {
          success: true,
          message: `Fixed successfully!`,
          pr_url: result.pr_url,
        };
        newResults.set(vulnerabilityIndex, resultData);
        setFixResults(new Map(newResults));
        
        setLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString().split(' ')[0]}] ✅ Fix completed: ${vulnerability.type}`,
          `[${new Date().toLocaleTimeString().split(' ')[0]}] 🔗 Pull Request: ${result.pr_url}`,
        ]);
      } else {
        const resultData = {
          success: false,
          message: `${result.error || "Unknown error"}`,
        };
        newResults.set(vulnerabilityIndex, resultData);
        setFixResults(new Map(newResults));
        
        setLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString().split(' ')[0]}] ❌ Fix failed: ${result.error}`,
        ]);
      }
    } catch (error: any) {
      const resultData = {
        success: false,
        message: `${error.message || "Failed to submit fix request"}`,
      };
      newResults.set(vulnerabilityIndex, resultData);
      setFixResults(new Map(newResults));
      
      setLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString().split(' ')[0]}] ❌ Error: ${error.message}`,
      ]);
    } finally {
      setFixingVulnerability(null);
    }
  };

  return (
    <main className="flex h-screen w-full bg-[#0d1117] text-white overflow-hidden">
      {/* Left Sidebar - File Explorer */}
      <div className="w-64 flex-shrink-0 border-r border-gray-800 bg-[#0d1117] p-4 flex flex-col">
        <h2 className="mb-4 text-xs font-bold uppercase tracking-wider text-gray-500">Suspicious Files</h2>
        <div className="space-y-1 overflow-y-auto max-h-[calc(100vh-100px)] scrollbar-hide">
          {displayFiles.map((file, i) => (
            <div
              key={file.name + i}
              onClick={() => onFileSelect?.(i)}
              className={`flex items-center gap-2 rounded px-2 py-1.5 text-sm cursor-pointer hover:bg-white/5 ${
                file.status === "scanning"
                  ? "bg-blue-500/10 text-blue-400"
                  : file.status === "completed"
                  ? "text-gray-400"
                  : "text-gray-600"
              }`}
            >
              <FileCode className="h-4 w-4 flex-shrink-0" />
              <span className="flex-1 truncate">{file.name}</span>
              {file.status === "scanning" && (
                <motion.div
                  className="h-1.5 w-1.5 rounded-full bg-blue-500"
                  animate={{ opacity: [1, 0.5, 1] }}
                  transition={{ duration: 1, repeat: Infinity }}
                />
              )}
              {file.status === "completed" && <CheckCircle className="h-3 w-3 text-green-500 flex-shrink-0" />}
            </div>
          ))}
        </div>
      </div>

      {/* Center - Code Scanner & Logs */}
      <div className="flex-1 flex flex-col min-w-0 bg-black/20">
        <div className="flex h-12 items-center border-b border-gray-800 px-4 bg-[#0d1117]">
          <span className="flex items-center gap-2 text-sm text-gray-400">
            <span className="text-gray-600">src</span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-blue-400">{currentFileName}</span>
          </span>
          <div className="ml-auto flex items-center gap-2">
            <div className="flex items-center gap-1.5 rounded-full bg-blue-500/10 px-2.5 py-1 text-xs text-blue-400">
              <Activity className="h-3 w-3" />
              <span>Scanning</span>
            </div>
            {wsConnected && (
              <div className="flex items-center gap-1.5 rounded-full bg-green-500/10 px-2.5 py-1 text-xs text-green-400">
                <div className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" />
                <span>Live</span>
              </div>
            )}
            <div className="flex items-center gap-1.5 rounded-full bg-gray-800 px-2.5 py-1 text-xs text-gray-400">
              <Cpu className="h-3 w-3" />
              <span>TS-Engine</span>
            </div>
          </div>
        </div>

        {/* Code Area */}
        <div className="flex-1 overflow-hidden p-8 flex items-center justify-center bg-[#0d1117]/50">
          <div className="w-full max-w-4xl h-full overflow-hidden">
            <CodeScanner 
              code={initialCode || ""} 
              language="typescript" 
              className="shadow-2xl ring-1 ring-white/5 bg-[#0d1117] backdrop-blur-sm h-full"
              annotations={currentAnnotations || []}
              onScanLine={handleScanLine}
              onScanStart={onScanStart}
              onScanComplete={onScanComplete}
              skipAnimation={completedFiles.has(currentFileIndex)}
            />
          </div>
        </div>

        {/* Agent Logs Terminal */}
        <div className="h-48 flex-shrink-0 border-t border-gray-800 bg-[#0a0d12] p-4">
          <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-gray-500">
            <Terminal className="h-3 w-3" />
            <span>Agent Logs</span>
          </div>
          <div className="h-[calc(100%-1.5rem)] overflow-y-auto font-mono text-xs text-gray-400 space-y-1 scrollbar-hide">
            {logs.length === 0 && (
              <span className="opacity-50 italic">Waiting for agent to start...</span>
            )}
            {logs.map((log, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="flex gap-2"
              >
                <span className="text-gray-600">{">"}</span>
                <span className={log.includes("ALERT") ? "text-red-400" : log.includes("Verified") ? "text-green-400" : ""}>
                  {log}
                </span>
              </motion.div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>
      </div>

      {/* Right Sidebar - Vulnerabilities */}
      <div className="w-80 flex-shrink-0 border-l border-gray-800 bg-[#0d1117] p-4 flex flex-col overflow-hidden">
        <h2 className="mb-4 text-xs font-bold uppercase tracking-wider text-gray-500">Scan Results</h2>

        <div className="space-y-3 overflow-y-auto flex-1 scrollbar-hide">
          <AnimatePresence mode="popLayout">
            {/* Auth Vulnerabilities from Agent */}
            {authVulnerabilities.map((vuln: any, i: number) => {
              const severity = vuln.severity?.toLowerCase() || "medium";
              const isHigh = severity === "high" || severity === "critical";
              const isLow = severity === "low";
              const fixResult = fixResults.get(i);
              const isFixing = fixingVulnerability === i;
              
              return (
                <motion.div
                  key={`auth-${i}-${vuln.location}-${vuln.line || 0}`}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className={`rounded-lg border p-3 ${
                    isHigh
                      ? "border-red-500/20 bg-red-500/10"
                      : isLow
                      ? "border-yellow-500/20 bg-yellow-500/10"
                      : "border-orange-500/20 bg-orange-500/10"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div className={`mt-0.5 rounded p-1 ${
                      isHigh
                        ? "bg-red-500/20 text-red-400"
                        : isLow
                        ? "bg-yellow-500/20 text-yellow-400"
                        : "bg-orange-500/20 text-orange-400"
                    }`}>
                      {getVulnerabilityIcon(vuln.type || "", vuln._vulnerabilityType)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className={`text-sm font-medium ${
                        isHigh ? "text-red-200" : isLow ? "text-yellow-200" : "text-orange-200"
                      }`}>
                        {vuln.type || "Authentication Vulnerability"}
                      </h3>
                      <p className="mt-1 text-xs text-gray-400 line-clamp-2">
                        {vuln.description || "No description available"}
                      </p>
                      <p className="mt-1 text-xs text-gray-500">
                        {vuln.location?.split("/").pop() || "Unknown file"}
                        {vuln.line && ` • Line ${vuln.line}`}
                        {vuln.severity && ` • ${vuln.severity.toUpperCase()}`}
                      </p>
                      
                      {/* Fix Button */}
                      {repository && (
                        <div className="mt-2">
                          <button
                            onClick={() => handleFixVulnerability(i, vuln)}
                            disabled={isFixing}
                            className="flex items-center gap-1.5 rounded bg-blue-600 hover:bg-blue-500 px-2 py-1 text-xs font-medium text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <Wrench className="h-3 w-3" />
                            {isFixing ? "Fixing..." : "Fix This"}
                          </button>
                        </div>
                      )}
                      
                      {/* Fix Result */}
                      {fixResult && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          className={`mt-2 rounded border p-2 text-xs ${
                            fixResult.success
                              ? "border-green-500/30 bg-green-500/10 text-green-200"
                              : "border-red-500/30 bg-red-500/10 text-red-200"
                          }`}
                        >
                          <p className="font-medium">{fixResult.message}</p>
                          {fixResult.pr_url && (
                            <a
                              href={fixResult.pr_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="mt-1 flex items-center gap-1 text-blue-400 hover:text-blue-300"
                            >
                              <ExternalLink className="h-3 w-3" />
                              View PR
                            </a>
                          )}
                        </motion.div>
                      )}
                    </div>
                  </div>
                </motion.div>
              );
            })}
            
            {/* Code scanning issues */}
            {foundIssues.map((issue, i) => (
              <motion.div
                key={issue.line}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className={`rounded-lg border p-3 ${
                  issue.type === "error"
                    ? "border-red-500/20 bg-red-500/10"
                    : issue.type === "warning"
                    ? "border-yellow-500/20 bg-yellow-500/10"
                    : "border-green-500/20 bg-green-500/10"
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`mt-0.5 rounded p-1 ${
                    issue.type === "error"
                      ? "bg-red-500/20 text-red-400"
                      : issue.type === "warning"
                      ? "bg-yellow-500/20 text-yellow-400"
                      : "bg-green-500/20 text-green-400"
                  }`}>
                    {issue.type === "error" ? <ShieldAlert className="h-4 w-4" /> :
                     issue.type === "warning" ? <AlertTriangle className="h-4 w-4" /> :
                     <CheckCircle className="h-4 w-4" />}
                  </div>
                  <div>
                    <h3 className={`text-sm font-medium ${
                      issue.type === "error" ? "text-red-200" :
                      issue.type === "warning" ? "text-yellow-200" :
                      "text-green-200"
                    }`}>
                      {issue.label}
                    </h3>
                    <p className="mt-1 text-xs text-gray-400">
                      Line {issue.line} • {issue.type === "error" ? "Critical Severity" : "Passed"}
                    </p>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
          
          {foundIssues.length === 0 && authVulnerabilities.length === 0 && (
            <div className="py-8 text-center text-sm text-gray-600">
              <div className="mb-2 flex justify-center">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                >
                  <FileText className="h-8 w-8 opacity-20" />
                </motion.div>
              </div>
              Scanning in progress...
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
