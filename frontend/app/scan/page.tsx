"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useEffect, useState, useRef } from "react";
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
  const [pendingFileChanges, setPendingFileChanges] = useState<Array<{fileIndex: number, eventData: any}>>([]);
  const lastFetchedFileIndexRef = useRef<number>(-1);
  const isScanningAnimationRef = useRef(false); // Ref to track scanning state synchronously

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
          
          let res;
          try {
            res = await fetch("/api/analyze/stream", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ url: cleanUrl }),
            });
          } catch (fetchError) {
            // Handle network errors (CORS, connection refused, DNS errors, etc.)
            console.error("Network error fetching stream:", fetchError);
            const errorMessage = fetchError instanceof Error 
              ? fetchError.message 
              : "Network error";
            setScanStatus(`Failed to connect to analysis service: ${errorMessage}. Please check your connection and try again.`);
            setIsLoading(false);
            return;
          }

          if (!res || !res.ok) {
            const errorText = res ? await res.text().catch(() => "Unknown error") : "No response from server";
            console.error("API Error:", res?.status || "No status", errorText);
            setScanStatus(`Analysis failed: ${res?.status || "Connection error"} - ${errorText}`);
            setIsLoading(false);
            return;
          }

          const reader = res.body?.getReader();
          const decoder = new TextDecoder();

          if (!reader) {
            setScanStatus("Error: Stream not available. Please try again.");
            setIsLoading(false);
            return;
          }
          
          console.log("Stream started, reading events...");

          let buffer = "";

          try {
            while (true) {
              let readResult;
              try {
                readResult = await reader.read();
              } catch (readError) {
                console.error("Error reading from stream:", readError);
                setScanStatus(`Error reading stream: ${readError instanceof Error ? readError.message : "Unknown error"}`);
                setIsLoading(false);
                return;
              }

              const { done, value } = readResult;
              if (done) break;

              buffer += decoder.decode(value, { stream: true });
              const lines = buffer.split("\n\n");
              buffer = lines.pop() || "";

              for (const line of lines) {
                if (!line.trim()) continue;

                const match = line.match(/^event: (\w+)\ndata: ([\s\S]+)$/);
                if (!match) continue;

                const eventType = match[1];
                let eventData;
                try {
                  eventData = JSON.parse(match[2]);
                } catch (parseError) {
                  console.error("Error parsing event data:", parseError, "Line:", line);
                  continue;
                }

              switch (eventType) {
                case "status":
                  if (eventData.message) {
                    setScanStatus(eventData.message);
                  }
                  break;

                case "file_analysis_start":
                  if (eventData.file_index !== undefined) {
                    const fileIndex = eventData.file_index;
                    
                    // #region agent log
                    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:107',message:'file_analysis_start received',data:{fileIndex,currentFileIndex,isScanningAnimation:isScanningAnimationRef.current,willSwitch:fileIndex!==currentFileIndex},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
                    // #endregion
                    
                    // If we're currently scanning and this is a different file, queue it
                    if (isScanningAnimationRef.current && fileIndex !== currentFileIndex) {
                      setPendingFileChanges(prev => {
                        // Only add if not already in queue
                        if (!prev.some(p => p.fileIndex === fileIndex)) {
                          // #region agent log
                          fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:117',message:'Queueing file change',data:{fileIndex,currentFileIndex,queueLength:prev.length,newQueueLength:prev.length+1},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
                          // #endregion
                          return [...prev, { fileIndex, eventData }];
                        }
                        return prev;
                      });
                      break;
                    }
                    
                    // Only switch files if it's actually a different file AND we're not currently scanning
                    if (fileIndex !== currentFileIndex && !isScanningAnimationRef.current) {
                      // #region agent log
                      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:120',message:'Switching file',data:{fromFileIndex:currentFileIndex,toFileIndex:fileIndex,isScanningAnimation:isScanningAnimationRef.current},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
                      // #endregion
                      setCurrentFileIndex(fileIndex);
                      // Only clear code when switching to a different file
                      setCurrentCode(null);
                      // Reset scanning state - will be set to true when code loads
                      isScanningAnimationRef.current = false;
                      setIsScanningAnimation(false);
                    }
                    
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
                  }
                  break;

                case "file_analysis_complete":
                  if (eventData.file_index !== undefined) {
                    const fileIndex = eventData.file_index;
                    // Don't mark as complete here - wait for animation to complete
                    // Just update the status message
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
                    // Mark all files as complete EXCEPT the last file
                    // The last file will be marked complete when its animation finishes naturally
                    setCompletedFiles(prev => {
                      const newSet = new Set(prev);
                      const lastFileIndex = files.length - 1;
                      
                      // Mark all files as complete except the last one
                      files.forEach((_: any, index: number) => {
                        if (index !== lastFileIndex) {
                          newSet.add(index);
                        }
                      });
                      
                      return newSet;
                    });
                    
                    // Ensure the last file is switched to if it hasn't been scanned yet
                    const lastFileIndex = files.length - 1;
                    if (!completedFiles.has(lastFileIndex) && currentFileIndex !== lastFileIndex) {
                      // Switch to the last file so it can be fetched and scanned
                      setTimeout(() => {
                        setCurrentFileIndex(lastFileIndex);
                        setCurrentCode(null); // Clear code to trigger fetch
                      }, 100);
                    }
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
          } catch (streamError) {
            console.error("Error processing stream:", streamError);
            setScanStatus(`Stream processing error: ${streamError instanceof Error ? streamError.message : "Unknown error"}`);
            setIsLoading(false);
            return;
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
          .then(res => {
            if (!res.ok) {
              throw new Error(`Failed to fetch file: ${res.status}`);
            }
            return res.text();
          })
          .then(text => setCurrentCode(text))
          .catch(err => {
            console.error("Failed to fetch blob content:", err);
            setCurrentCode("// Error: Could not load file content");
            setScanStatus("Failed to load file content. Please check the URL.");
          });
      }
    };

    startScan();
  }, [repoUrl]);

  // Fetch content when current file changes (for repo mode)
  useEffect(() => {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:230',message:'File fetch effect triggered',data:{repoFilesLength:repoFiles.length,currentFileIndex,lastFetched:lastFetchedFileIndexRef.current,hasFile:!!repoFiles[currentFileIndex]},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
    // #endregion
    
    // Only fetch if this is a different file than we last fetched AND repoFiles is available
    if (lastFetchedFileIndexRef.current === currentFileIndex && repoFiles.length > 0) {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:235',message:'Skipping fetch, same file as last fetch',data:{fileIndex:currentFileIndex},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
      // #endregion
      return;
    }
    
    if (repoFiles.length > 0 && repoFiles[currentFileIndex] && repoUrl) {
      const file = repoFiles[currentFileIndex];
      lastFetchedFileIndexRef.current = currentFileIndex;
      
      if (file.content) {
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:243',message:'Setting code from file.content',data:{fileIndex:currentFileIndex,codeLength:file.content.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
        // #endregion
        setCurrentCode(file.content);
        isScanningAnimationRef.current = true;
        setIsScanningAnimation(true); // Mark that we're starting to scan this file
        return;
      }

      // Clean the URL for matching
      const cleanUrl = repoUrl.replace(/\/tree\/.*$/, "").replace(/\/blob\/.*$/, "").replace(/\/$/, "");
      const match = cleanUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (match) {
        const [_, owner, repo] = match;
        
        // #region agent log
        fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:253',message:'Clearing code before fetch',data:{fileIndex:currentFileIndex,filePath:file.path},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
        // #endregion
        setCurrentCode(null);
        
        // Try proxy API route first (with GitHub token), fallback to direct URL
        const proxyUrl = `/api/github/file?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}&path=${encodeURIComponent(file.path)}`;
        const directUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${file.path}`;
        
        // Validate file path before fetching
        if (!file.path || file.path.trim() === "") {
          console.error("Invalid file path:", file.path);
          setCurrentCode("// Error: Invalid file path");
          return;
        }
        
        // Try proxy first
        fetch(proxyUrl)
          .then(res => {
            if (!res.ok) {
              throw new Error(`Proxy failed: ${res.status}`);
            }
            return res.json();
          })
          .then(data => {
            if (data.error) {
              throw new Error(data.error);
            }
            // #region agent log
            fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:305',message:'Code fetched via proxy and set',data:{fileIndex:currentFileIndex,codeLength:data.content?.length||0},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
            // #endregion
            setCurrentCode(data.content || "// Error: Could not load file content");
            isScanningAnimationRef.current = true;
            setIsScanningAnimation(true);
          })
          .catch((proxyErr: any) => {
            // Handle network errors specifically
            if (proxyErr instanceof TypeError && proxyErr.message === "Failed to fetch") {
              console.error("Network error fetching from proxy:", proxyErr);
            }
            // #region agent log
            fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:315',message:'Proxy failed, trying direct URL',data:{error:proxyErr.message,fileIndex:currentFileIndex},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
            // #endregion
            // Fallback to direct GitHub URL
            fetch(directUrl)
              .then(res => {
                if (!res.ok) {
                  return fetch(directUrl.replace('/main/', '/master/'));
                }
                return res;
              })
              .then(res => {
                if (!res.ok) {
                  throw new Error(`Failed to fetch: ${res.status}`);
                }
                return res.text();
              })
              .then(text => {
                // #region agent log
                fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:325',message:'Code fetched via direct URL and set',data:{fileIndex:currentFileIndex,codeLength:text?.length||0},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
                // #endregion
                setCurrentCode(text || "// Error: Could not load file content");
                isScanningAnimationRef.current = true;
                setIsScanningAnimation(true);
              })
              .catch((err: any) => {
                // #region agent log
                fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:332',message:'Failed to fetch file content from both proxy and direct URL',data:{error:err.message,fileIndex:currentFileIndex,filePath:file.path},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
                // #endregion
                console.error("Failed to fetch file content", err);
                // Handle network errors specifically
                if (err instanceof TypeError && err.message === "Failed to fetch") {
                  setCurrentCode(`// Error: Network error - could not load file content\n// File: ${file.path}\n// Please check your connection and try again`);
                } else {
                  setCurrentCode(`// Error: Could not load file content\n// File: ${file.path}\n// ${err.message || "Unknown error"}`);
                }
              });
          })
          .catch((networkErr: any) => {
            // Catch network errors from the proxy fetch
            console.error("Network error fetching from proxy:", networkErr);
            // Handle network errors - if it's a network error, try direct URL
            if (networkErr instanceof TypeError && networkErr.message === "Failed to fetch") {
              // Try direct URL as fallback
              fetch(directUrl)
                .then(res => {
                  if (!res.ok) {
                    return fetch(directUrl.replace('/main/', '/master/'));
                  }
                  return res;
                })
                .then(res => {
                  if (!res.ok) {
                    throw new Error(`Failed to fetch: ${res.status}`);
                  }
                  return res.text();
                })
                .then(text => {
                  setCurrentCode(text || "// Error: Could not load file content");
                  isScanningAnimationRef.current = true;
                  setIsScanningAnimation(true);
                })
                .catch((err: any) => {
                  console.error("Failed to fetch file content from all sources:", err);
                  if (err instanceof TypeError && err.message === "Failed to fetch") {
                    setCurrentCode(`// Error: Network error - could not load file content\n// File: ${file.path}\n// Please check your connection and try again`);
                  } else {
                    setCurrentCode(`// Error: Could not load file content\n// File: ${file.path}\n// ${err.message || "Unknown error"}`);
                  }
                });
            } else {
              // Non-network error from proxy, show error message
              setCurrentCode(`// Error: Could not load file content\n// File: ${file.path}\n// ${networkErr.message || "Unknown error"}`);
            }
          });
      }
    }
  }, [currentFileIndex, repoUrl, repoFiles]); // Need repoFiles to know when files are available

  const handleScanStart = () => {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:289',message:'handleScanStart called',data:{currentFileIndex},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
    // #endregion
    isScanningAnimationRef.current = true;
    setIsScanningAnimation(true);
  };

  const handleScanComplete = () => {
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:293',message:'handleScanComplete called',data:{currentFileIndex,pendingChangesCount:pendingFileChanges.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
    // #endregion
    
    // Mark current file as complete when animation finishes
    setCompletedFiles(prev => new Set(prev).add(currentFileIndex));
    
    isScanningAnimationRef.current = false;
    setIsScanningAnimation(false);
    
    // Process the next file in the queue (FIFO - first in, first out)
    if (pendingFileChanges.length > 0) {
      const [nextChange, ...remaining] = pendingFileChanges;
      const { fileIndex, eventData } = nextChange;
      setPendingFileChanges(remaining);
      
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/d7ed34c7-a4a6-4f15-8a74-de07d29ed0ca',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'scan/page.tsx:318',message:'Processing queued file change',data:{fromFileIndex:currentFileIndex,toFileIndex:fileIndex,remainingInQueue:remaining.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
      // #endregion
      
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
            <Link href="/" className="flex items-center gap-2 cursor-pointer hover:opacity-80 transition-opacity">
              <img src="/trojan.svg" alt="Trojan" className="h-14 w-auto" />
            </Link>
          </div>
          <div className="flex flex-col items-end gap-1">
            {/* Project Name with GitHub icon */}
            {repoUrl && (() => {
              const cleanUrl = repoUrl.replace(/\/tree\/.*$/, "").replace(/\/blob\/.*$/, "").replace(/\/$/, "");
              const githubUrl = cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`;
              return (
                <a 
                  href={githubUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-[#D6D6D6] hover:text-white transition-colors cursor-pointer"
                >
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                  </svg>
                  <span className="text-sm">
                    {getProjectName().split(' / ').map((part, i) => 
                      i === 1 ? <span key={i} className="font-bold"> / {part}</span> : <span key={i}>{part}</span>
                    )}
                  </span>
                </a>
              );
            })()}
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
