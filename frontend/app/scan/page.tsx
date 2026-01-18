"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import ScannerDemo from "@/components/ScannerDemo";
import { Suspense } from "react";
import { ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";
import Link from "next/link";

function ScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const encodedUrl = searchParams.get("url");
  const repoUrl = encodedUrl ? decodeURIComponent(encodedUrl) : null;
  const [repoFiles, setRepoFiles] = useState<{ 
    name: string; 
    path: string; 
    content?: string; 
    functions?: string[];
    riskLevel?: string;
    reason?: string;
  }[]>([]);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  const [currentCode, setCurrentCode] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [scanStatus, setScanStatus] = useState<string>("Initializing scan...");
  const [authVulnerabilities, setAuthVulnerabilities] = useState<any[]>([]);
  const [completedFiles, setCompletedFiles] = useState<Set<number>>(new Set());
  const [isScanningAnimation, setIsScanningAnimation] = useState(false);
  const [pendingFileChange, setPendingFileChange] = useState<{fileIndex: number, eventData: any} | null>(null);

  useEffect(() => {
    if (!repoUrl) {
      setScanStatus("No repository URL provided. Please provide a GitHub repository URL.");
      setIsLoading(false);
      return;
    }

    const startScan = async () => {
      // Clean the URL - remove trailing slashes, tree/blob paths, etc.
      const cleanUrl = repoUrl.replace(/\/tree\/.*$/, "").replace(/\/blob\/.*$/, "").replace(/\/$/, "");
      
      // More flexible regex to match GitHub URLs
      const githubMatch = cleanUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      
      if (githubMatch) {
        setIsLoading(true);
        setScanStatus("Scanning repository structure...");
        setRepoFiles([]);
        setCompletedFiles(new Set());
        
        try {
          setScanStatus("Analyzing files and identifying suspicious patterns...");
          
          console.log("Starting scan for URL:", cleanUrl);
          
          const res = await fetch("/api/analyze/stream", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: cleanUrl }),
          });

          if (!res.ok) {
            const errorText = await res.text();
            console.error("API Error:", res.status, errorText);
            throw new Error(`Analysis failed: ${res.status} ${errorText}`);
          }

          const reader = res.body?.getReader();
          const decoder = new TextDecoder();

          if (!reader) {
            throw new Error("Stream not available");
          }
          
          console.log("Stream started, reading events...");

          let buffer = "";

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n\n");
            buffer = lines.pop() || "";

            for (const line of lines) {
              if (!line.trim()) continue;

              const match = line.match(/^event: (\w+)\ndata: ([\s\S]+)$/);
              if (!match) continue;

              const eventType = match[1];
              const eventData = JSON.parse(match[2]);

              switch (eventType) {
                case "status":
                  if (eventData.message) {
                    setScanStatus(eventData.message);
                  }
                  break;

                case "file_analysis_start":
                  if (eventData.file_index !== undefined) {
                    const fileIndex = eventData.file_index;
                    
                    if (isScanningAnimation && fileIndex !== currentFileIndex) {
                      setPendingFileChange({ fileIndex, eventData });
                      break;
                    }
                    
                    setCurrentFileIndex(fileIndex);
                    
                    if (eventData.vulnerabilities && Array.isArray(eventData.vulnerabilities)) {
                      setAuthVulnerabilities(prev => {
                        const filtered = prev.filter(v => v.file_path !== eventData.file_path);
                        const newVulns = eventData.vulnerabilities.map((v: any) => ({
                          ...v,
                          file_index: fileIndex,
                          file_path: eventData.file_path
                        }));
                        return [...filtered, ...newVulns];
                      });
                    }
                    
                    setScanStatus(`Analyzing ${eventData.file_name || eventData.file_path || "file"}... Found ${eventData.vulnerabilities?.length || 0} vulnerability/vulnerabilities`);
                    setCurrentCode(null);
                  }
                  break;

                case "file_analysis_complete":
                  if (eventData.file_index !== undefined) {
                    const fileIndex = eventData.file_index;
                    setCompletedFiles(prev => new Set(prev).add(fileIndex));
                    setScanStatus(`Completed ${eventData.file_path?.split("/").pop() || "file"} - Found ${eventData.vulnerabilities_found || 0} vulnerability/vulnerabilities`);
                    
                    if (fileIndex + 1 < (repoFiles.length || 0)) {
                      setTimeout(() => {
                        // Next file will start when backend sends file_analysis_start
                      }, 2000);
                    }
                  }
                  break;

                case "vulnerability":
                  setAuthVulnerabilities(prev => {
                    const exists = prev.some(v => 
                      v.location === eventData.location && 
                      v.type === eventData.type &&
                      v.line === eventData.line
                    );
                    if (exists) return prev;
                    return [...prev, eventData];
                  });
                  break;

                case "suspicious_files":
                  if (Array.isArray(eventData) && eventData.length > 0) {
                    const mappedFiles = eventData.map((f: any) => ({
                      name: f.file_path?.split("/").pop() || "Unknown",
                      path: f.file_path || "",
                      functions: f.suspicious_functions || [],
                      riskLevel: f.risk_level || "unknown",
                      reason: f.reason || "",
                    }));
                    setRepoFiles(mappedFiles);
                    setIsLoading(false);
                    setScanStatus(`Found ${mappedFiles.length} suspicious file(s). Analyzing...`);
                  }
                  break;

                case "complete":
                  if (eventData.suspicious_files) {
                    const files = eventData.suspicious_files.map((f: any) => ({
                      name: f.file_path?.split("/").pop() || "Unknown",
                      path: f.file_path || "",
                      functions: f.suspicious_functions || [],
                      riskLevel: f.risk_level || "unknown",
                      reason: f.reason || "",
                    }));
                    setRepoFiles(files);
                  }
                  if (eventData.auth_vulnerabilities) {
                    setAuthVulnerabilities(eventData.auth_vulnerabilities);
                  }
                  setScanStatus(`Analysis complete. Found ${eventData.auth_vulnerabilities?.length || 0} vulnerability/vulnerabilities`);
                  setIsLoading(false);
                  break;

                case "error":
                  setScanStatus(`Error: ${eventData.message || "Analysis failed"}`);
                  setIsLoading(false);
                  break;
              }
            }
          }
          
          setIsLoading(false);
          return;
        } catch (error) {
          console.error("Scan error:", error);
          setScanStatus("Scan failed. Please try again.");
          setIsLoading(false);
        }
      } else if (repoUrl.includes("/blob/")) {
        const rawUrl = repoUrl
          .replace("github.com", "raw.githubusercontent.com")
          .replace("/blob/", "/");
        
        fetch(rawUrl)
          .then(res => res.text())
          .then(text => setCurrentCode(text));
      }
    };

    startScan();
  }, [repoUrl]);

  // Fetch content when current file changes (for repo mode)
  useEffect(() => {
    if (repoFiles.length > 0 && repoFiles[currentFileIndex] && repoUrl) {
      const file = repoFiles[currentFileIndex];
      
      if (file.content) {
        setCurrentCode(file.content);
        return;
      }

      // Clean the URL for matching
      const cleanUrl = repoUrl.replace(/\/tree\/.*$/, "").replace(/\/blob\/.*$/, "").replace(/\/$/, "");
      const match = cleanUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (match) {
        const [_, owner, repo] = match;
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${file.path}`;
        
        setCurrentCode(null);
        
        fetch(rawUrl)
          .then(res => {
            if (!res.ok) {
              return fetch(rawUrl.replace('/main/', '/master/'));
            }
            return res;
          })
          .then(res => res.text())
          .then(text => setCurrentCode(text))
          .catch(err => {
            console.error("Failed to fetch file content", err);
            setCurrentCode("// Error: Could not load file content");
          });
      }
    }
  }, [repoFiles, currentFileIndex, repoUrl]);

  const handleScanStart = () => {
    setIsScanningAnimation(true);
  };

  const handleScanComplete = () => {
    setIsScanningAnimation(false);
    
    if (pendingFileChange) {
      const { fileIndex, eventData } = pendingFileChange;
      setPendingFileChange(null);
      
      setCurrentFileIndex(fileIndex);
      
      if (eventData.vulnerabilities && Array.isArray(eventData.vulnerabilities)) {
        setAuthVulnerabilities(prev => {
          const filtered = prev.filter(v => v.file_path !== eventData.file_path);
          const newVulns = eventData.vulnerabilities.map((v: any) => ({
            ...v,
            file_index: fileIndex,
            file_path: eventData.file_path
          }));
          return [...filtered, ...newVulns];
        });
      }
      
      setScanStatus(`Analyzing ${eventData.file_name || eventData.file_path || "file"}... Found ${eventData.vulnerabilities?.length || 0} vulnerability/vulnerabilities`);
      setCurrentCode(null);
    }
  };

  // Extract project name from repo URL
  const getProjectName = () => {
    if (!repoUrl) return "";
    const cleanUrl = repoUrl.replace(/\/tree\/.*$/, "").replace(/\/blob\/.*$/, "").replace(/\/$/, "");
    const match = cleanUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (match) {
      return `${match[1]} / ${match[2]}`;
    }
    return "Unknown Project";
  };

  // Calculate scan progress
  const scannedCount = completedFiles.size;
  const totalFiles = repoFiles.length;
  const scanProgress = totalFiles > 0 ? `${scannedCount}/${totalFiles}` : "0/0";

  const currentFilePath = repoFiles[currentFileIndex]?.path || repoFiles[currentFileIndex]?.name || "";

  return (
    <div className="h-screen bg-[#0E141A] text-white flex flex-col overflow-hidden">
      {/* Header */}
      <header className="bg-[#0E141A] flex-shrink-0">
        <div className="py-4 flex items-center justify-between px-8">
          <div className="flex items-center gap-3">
            {/* TROJAN Logo */}
            <div className="flex items-center gap-2">
              <img src="/trojan.svg" alt="Trojan" className="h-14 w-auto" />
            </div>
          </div>
          <div className="flex flex-col items-end gap-1">
            {/* Project Name with GitHub icon */}
            {repoUrl && (
              <div className="flex items-center gap-2 text-[#D6D6D6]">
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
                <span className="text-sm">
                  {getProjectName().split(' / ').map((part, i) => 
                    i === 1 ? <span key={i} className="font-bold"> / {part}</span> : <span key={i}>{part}</span>
                  )}
                </span>
              </div>
            )}
            {/* Scan Status */}
            {repoFiles.length > 0 && (
              <div className="text-xs text-[#D6D6D6] text-opacity-60">
                {scanProgress} Suspicious Files Scanned
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Scanner Visualization or Loading State */}
      <div className="flex-1 overflow-hidden min-h-0 flex flex-col">
        {isLoading ? (
          <div className="flex items-center justify-center h-full bg-[#0E141A]">
            <div className="text-center">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                className="w-16 h-16 border-4 border-[#6699C9]/30 border-t-[#6699C9] rounded-full mx-auto mb-4"
              />
              <p className="text-[#D6D6D6] text-sm">{scanStatus}</p>
              <p className="text-[#D6D6D6] text-opacity-40 text-xs mt-2">This may take a moment...</p>
            </div>
          </div>
        ) : repoFiles.length > 0 ? (
          <ScannerDemo 
            initialCode={currentCode} 
            repoFiles={repoFiles}
            currentFileIndex={currentFileIndex}
            onFileSelect={setCurrentFileIndex}
            onScanStart={handleScanStart}
            onScanComplete={handleScanComplete}
            authVulnerabilities={authVulnerabilities}
            completedFiles={completedFiles}
            scanStatus={scanStatus}
            currentFilePath={currentFilePath}
          />
        ) : (
          <div className="flex items-center justify-center h-full bg-[#0E141A]">
            <div className="text-center">
              <ShieldCheck className="w-16 h-16 text-[#D6D6D6] text-opacity-40 mx-auto mb-4" />
              <p className="text-[#D6D6D6] text-sm">{scanStatus || "No repository URL provided"}</p>
              <Link
                href="/"
                className="mt-4 inline-flex items-center gap-2 text-blue-500 hover:text-blue-400 transition-colors"
              >
                <span>Start a new scan</span>
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={<div className="flex h-screen w-full items-center justify-center bg-[#0E141A] text-white">Loading...</div>}>
      <ScanContent />
    </Suspense>
  );
}
