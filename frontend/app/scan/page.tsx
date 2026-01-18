"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import Link from "next/link";
import ScannerDemo from "@/components/ScannerDemo";
import { Suspense } from "react";
import { ShieldCheck, Home, FolderOpen } from "lucide-react";
import { motion } from "framer-motion";

function ScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const repoUrl = searchParams.get("url");
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
  const [isScanningAnimation, setIsScanningAnimation] = useState(false); // Track if animation is in progress
  const [pendingFileChange, setPendingFileChange] = useState<{fileIndex: number, eventData: any} | null>(null); // Queue next file change
  const [repository, setRepository] = useState<string>("");
  const [suspiciousFiles, setSuspiciousFiles] = useState<any[]>([]);
  const [partialSuspiciousFiles, setPartialSuspiciousFiles] = useState<any[]>([]); // Accumulate partial results

  useEffect(() => {
    if (!repoUrl) return;

    const startScan = async () => {
      // Only use API for full repos, fallback to direct fetch for single files if needed
      const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (match) {
        // Save repository to localStorage for later use
        const [_, owner, repo] = match;
        const cleanRepo = repo.replace(/\.git$/, ''); // Remove .git suffix if present
        const repoName = `${owner}/${cleanRepo}`;
        localStorage.setItem('current_repository', repoName);
        setRepository(repoName); // Set repository state for ScannerDemo
        console.log(`Scanning repository: ${repoName}`);
        setIsLoading(true);
        setScanStatus("Scanning repository structure...");
        setRepoFiles([]); // Clear any previous files
        setCompletedFiles(new Set()); // Reset completed files
        
        try {
          setScanStatus("Analyzing files and identifying suspicious patterns...");
          
          // Use SSE streaming endpoint for real-time updates
          const res = await fetch("/api/analyze/stream", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: repoUrl }),
          });

          if (!res.ok) throw new Error("Analysis failed");

          const reader = res.body?.getReader();
          const decoder = new TextDecoder();

          if (!reader) {
            throw new Error("Stream not available");
          }

          let buffer = "";

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n\n");
            buffer = lines.pop() || ""; // Keep incomplete line in buffer

            for (const line of lines) {
              if (!line.trim()) continue;

              // Parse SSE format: "event: type\ndata: {...}\n\n"
              // Use [\s\S] instead of . with /s flag for compatibility
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
                  // Backend has analyzed a file and found vulnerabilities - switch frontend to visualize it
                  if (eventData.file_index !== undefined) {
                    const fileIndex = eventData.file_index;
                    
                    // If animation is still running for current file, queue this file change
                    if (isScanningAnimation && fileIndex !== currentFileIndex) {
                      setPendingFileChange({ fileIndex, eventData });
                      break;
                    }
                    
                    // Otherwise, switch to this file immediately
                    // Don't set isScanningAnimation yet - wait for CodeScanner to actually start
                    setCurrentFileIndex(fileIndex);
                    
                    // Set vulnerabilities immediately (backend already analyzed and found them)
                    if (eventData.vulnerabilities && Array.isArray(eventData.vulnerabilities)) {
                      setAuthVulnerabilities(prev => {
                        // Remove old vulnerabilities for this file, then add new ones
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
                    // Clear current code to trigger reload
                    setCurrentCode(null);
                  }
                  break;

                case "file_analysis_complete":
                  // Backend finished analyzing this file
                  if (eventData.file_index !== undefined) {
                    const fileIndex = eventData.file_index;
                    // Mark this file as completed
                    setCompletedFiles(prev => new Set(prev).add(fileIndex));
                    setScanStatus(`Completed ${eventData.file_path?.split("/").pop() || "file"} - Found ${eventData.vulnerabilities_found || 0} vulnerability/vulnerabilities`);
                    
                    // Auto-advance to next file after allowing visualization to complete
                    // Backend controls the flow - when it's done with one file, we move to next
                    if (fileIndex + 1 < (repoFiles.length || 0)) {
                      // Small delay to allow visualization to show the results
                      setTimeout(() => {
                        // Next file will start when backend sends file_analysis_start
                        // We don't auto-advance here - backend will send file_analysis_start for next file
                      }, 2000); // 2 second pause to show results
                    }
                  }
                  break;

                case "vulnerability":
                  // Add new vulnerability in real-time for the current file
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

                case "suspicious_files_partial":
                  // Accumulate partial results from batch processing
                  if (Array.isArray(eventData) && eventData.length > 0) {
                    setPartialSuspiciousFiles(prev => {
                      const combined = [...prev, ...eventData];
                      // Remove duplicates based on file_path
                      const unique = combined.filter((file, index, self) =>
                        index === self.findIndex(f => f.file_path === file.file_path)
                      );
                      
                      // Update UI with accumulated results
                      const mappedFiles = unique.map((f: any) => ({
                        name: f.file_path?.split("/").pop() || "Unknown",
                        path: f.file_path || "",
                        functions: f.suspicious_functions || [],
                        riskLevel: f.risk_level || "unknown",
                        reason: f.reason || "",
                      }));
                      setRepoFiles(mappedFiles);
                      setIsLoading(false);
                      setScanStatus(`Found ${unique.length} suspicious file(s) so far... Analyzing batches...`);
                      
                      return unique;
                    });
                  }
                  break;

                case "suspicious_files":
                  // Final combined results from all batches
                  if (Array.isArray(eventData) && eventData.length > 0) {
                    setSuspiciousFiles(eventData); // Store full suspicious files data
                    setPartialSuspiciousFiles([]); // Clear partial results
                    const mappedFiles = eventData.map((f: any) => ({
                      name: f.file_path?.split("/").pop() || "Unknown",
                      path: f.file_path || "",
                      functions: f.suspicious_functions || [],
                      riskLevel: f.risk_level || "unknown",
                      reason: f.reason || "",
                    }));
                    setRepoFiles(mappedFiles);
                    // Start visualization immediately when suspicious files are found
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
          
          // Stream ended, ensure loading is false
          setIsLoading(false);
          return;
        } catch (error) {
          console.error("Scan error:", error);
          setScanStatus("Scan failed. Please try again.");
          setIsLoading(false);
        }
      } else if (repoUrl.includes("/blob/")) {
        // Single file logic (unchanged for now)
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

      // Fetch file content from GitHub
      const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (match) {
        const [_, owner, repo] = match;
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${file.path}`;
        
        setCurrentCode(null); // Clear while loading
        
        fetch(rawUrl)
          .then(res => {
            if (!res.ok) {
              // Try master branch if main fails
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

  // Handle scan animation start
  const handleScanStart = () => {
    setIsScanningAnimation(true);
  };

  // Handle scan animation completion
  const handleScanComplete = () => {
    // Mark animation as complete
    setIsScanningAnimation(false);
    
    // If there's a pending file change, apply it now
    if (pendingFileChange) {
      const { fileIndex, eventData } = pendingFileChange;
      setPendingFileChange(null);
      
      setCurrentFileIndex(fileIndex);
      // Don't set isScanningAnimation here - let onScanStart handle it when animation actually starts
      
      // Set vulnerabilities for the pending file
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
      setCurrentCode(null); // Trigger reload
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-white flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-[#0d1117] flex-shrink-0">
        <div className="px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              href="/"
              className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
            >
              <Home className="h-5 w-5" />
              <span>Home</span>
            </Link>
            <span className="text-gray-600">|</span>
            <Link
              href="/projects"
              className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
            >
              <FolderOpen className="h-5 w-5" />
              <span>View All Projects</span>
            </Link>
          </div>
          <Link
            href="/"
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
          >
            <ShieldCheck className="h-6 w-6 text-blue-500" />
          </Link>
        </div>
      </header>

      {/* Scanner Visualization or Loading State */}
      <div className="flex-1 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full bg-[#0d1117]">
            <div className="text-center">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                className="w-16 h-16 border-4 border-blue-500/30 border-t-blue-500 rounded-full mx-auto mb-4"
              />
              <p className="text-gray-400 text-lg">{scanStatus}</p>
              <p className="text-gray-600 text-sm mt-2">This may take a moment...</p>
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
            repository={repository}
            suspiciousFiles={suspiciousFiles}
          />
        ) : (
          <div className="flex items-center justify-center h-full bg-[#0d1117]">
            <div className="text-center">
              <ShieldCheck className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 text-lg">{scanStatus}</p>
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
    <Suspense fallback={<div className="flex h-screen w-full items-center justify-center bg-[#0d1117] text-white">Loading...</div>}>
      <ScanContent />
    </Suspense>
  );
}
