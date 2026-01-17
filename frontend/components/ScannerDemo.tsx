"use client";

import { useState, useRef, useEffect } from "react";
import { CodeScanner, type CodeAnnotation } from "@/components/CodeScanner";
import { FileCode, ShieldAlert, CheckCircle, AlertTriangle, FileText, ChevronRight, Terminal, Cpu, Activity } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const sampleCode = `interface User {
  id: string;
  name: string;
  role: "admin" | "user";
}

function validateUser(user: User): boolean {
  // Check if user has valid permissions
  if (user.role === "admin") {
    console.log("Access granted: Admin level");
    return true;
  }
  
  if (user.role === "user") {
    console.log("Access granted: User level");
    return true;
  }

  // Security vulnerability found here
  eval(user.name); // Dangerous execution
  return false;
}

// Initialize system scan
const currentUser: User = {
  id: "u_123456",
  name: "Alex Chen",
  role: "admin"
};

validateUser(currentUser);
`;

const annotations: CodeAnnotation[] = [
  { line: 9, type: "success", label: "Valid Role Check" },
  { line: 10, type: "success" },
  { line: 11, type: "success" },
  { line: 20, type: "error", label: "Remote Code Execution Risk" },
  { line: 21, type: "error" },
];

const scanLogs = [
  { line: 0, message: "Initializing analysis engine v2.4.0..." },
  { line: 2, message: "Parsing AST for 'user.ts'..." },
  { line: 8, message: "Analyzing control flow: validateUser()" },
  { line: 10, message: "Verifying RBAC implementation..." },
  { line: 19, message: "Scanning for unsafe patterns..." },
  { line: 20, message: "⚠ ALERT: Dangerous sink 'eval' detected" },
  { line: 21, message: "Tracing data flow from 'user.name'..." },
  { line: 32, message: "Analysis complete. Generating report." }
];

interface ScannerDemoProps {
  initialCode?: string | null;
  repoFiles?: { name: string; path: string; functions?: string[] }[];
  currentFileIndex?: number;
  onFileSelect?: (index: number) => void;
  onScanComplete?: () => void;
}

export default function ScannerDemo({ 
  initialCode, 
  repoFiles, 
  currentFileIndex = 0,
  onFileSelect,
  onScanComplete
}: ScannerDemoProps) {
  const [foundIssues, setFoundIssues] = useState<CodeAnnotation[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Effect to log functions when a new file starts scanning
  useEffect(() => {
    if (repoFiles && repoFiles[currentFileIndex]) {
      const file = repoFiles[currentFileIndex];
      const newLogs = [`Analyzing ${file.name}...`];
      
      if (file.functions && file.functions.length > 0) {
        newLogs.push(`Detected ${file.functions.length} functions: ${file.functions.join(", ")}`);
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
    const found = annotations.find(a => a.line === lineIndex + 1);
    if (found && found.label) {
      setFoundIssues(prev => {
        if (prev.find(p => p.line === found.line)) return prev;
        return [...prev, found];
      });
    }

    // Check for logs
    const log = scanLogs.find(l => l.line === lineIndex);
    if (log) {
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString().split(' ')[0]}] ${log.message}`]);
    }
  };

  const demoFiles = [
    { name: "auth.ts", status: "completed" },
    { name: "user.ts", status: "scanning" },
    { name: "database.ts", status: "pending" },
    { name: "api.ts", status: "pending" },
    { name: "config.ts", status: "pending" },
  ];

  // Use repoFiles if available, otherwise fallback to demoFiles
  const displayFiles = repoFiles 
    ? repoFiles.map((f, i) => ({
        name: f.name,
        status: i < currentFileIndex ? "completed" : i === currentFileIndex ? "scanning" : "pending"
      }))
    : demoFiles;

  const currentFileName = repoFiles ? repoFiles[currentFileIndex]?.name : "user.ts";

  return (
    <main className="flex h-screen w-full bg-[#0d1117] text-white overflow-hidden">
      {/* Left Sidebar - File Explorer */}
      <div className="w-64 flex-shrink-0 border-r border-gray-800 bg-[#0d1117] p-4 flex flex-col">
        <h2 className="mb-4 text-xs font-bold uppercase tracking-wider text-gray-500">Project Files</h2>
        <div className="space-y-1 overflow-y-auto max-h-[calc(100vh-100px)]">
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
            <div className="flex items-center gap-1.5 rounded-full bg-gray-800 px-2.5 py-1 text-xs text-gray-400">
              <Cpu className="h-3 w-3" />
              <span>TS-Engine</span>
            </div>
          </div>
        </div>

        {/* Code Area */}
        <div className="flex-1 overflow-hidden p-8 flex items-center justify-center bg-[#0d1117]/50">
          <div className="w-full max-w-4xl max-h-full overflow-y-auto">
            <CodeScanner 
              code={initialCode || ""} 
              language="typescript" 
              className="shadow-2xl ring-1 ring-white/5 bg-[#0d1117] backdrop-blur-sm"
              annotations={annotations}
              onScanLine={handleScanLine}
              onScanComplete={onScanComplete}
            />
          </div>
        </div>

        {/* Agent Logs Terminal */}
        <div className="h-48 flex-shrink-0 border-t border-gray-800 bg-[#0a0d12] p-4">
          <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-gray-500">
            <Terminal className="h-3 w-3" />
            <span>Agent Logs</span>
          </div>
          <div className="h-[calc(100%-1.5rem)] overflow-y-auto font-mono text-xs text-gray-400 space-y-1">
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
      <div className="w-80 flex-shrink-0 border-l border-gray-800 bg-[#0d1117] p-4 flex flex-col">
        <h2 className="mb-4 text-xs font-bold uppercase tracking-wider text-gray-500">Scan Results</h2>
        <div className="space-y-3">
          <AnimatePresence mode="popLayout">
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
          
          {foundIssues.length === 0 && (
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
