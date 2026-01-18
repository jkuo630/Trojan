"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState, useRef } from "react";
import ScannerDemo from "@/components/ScannerDemo";
import { Suspense } from "react";
import { CodeAnnotation } from "@/components/CodeScanner";

function ScanContent() {
  const searchParams = useSearchParams();
  const repoUrl = searchParams.get("url");
  const [repoFiles, setRepoFiles] = useState<{ name: string; path: string; content?: string; functions?: string[]; vulnerabilities?: CodeAnnotation[] }[]>([]);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  const [currentCode, setCurrentCode] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const [wsConnected, setWsConnected] = useState(false);

  // WebSocket connection for real-time vulnerability updates
  useEffect(() => {
    if (!repoUrl || repoFiles.length === 0) return;

    // Only connect if WebSocket URL is configured
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL;
    if (!wsUrl) {
      console.log("WebSocket URL not configured. Set NEXT_PUBLIC_WS_URL to enable real-time vulnerability updates.");
      return;
    }
    
    let ws: WebSocket;
    let reconnectTimeout: NodeJS.Timeout;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log("WebSocket connected to backend");
          setWsConnected(true);
          
          // Send initial message to start scanning (adjust message format based on your backend)
          ws.send(JSON.stringify({
            type: "start_scan",
            repoUrl: repoUrl,
            files: repoFiles.map(f => ({ path: f.path, name: f.name }))
          }));
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            
            // Handle different message types from backend
            if (data.type === "vulnerability") {
              // Expected format: { type: "vulnerability", filePath: string, vulnerability: CodeAnnotation }
              const { filePath, vulnerability } = data;
              
              setRepoFiles(prev => prev.map(file => {
                if (file.path === filePath) {
                  const existing = file.vulnerabilities || [];
                  // Avoid duplicates
                  if (existing.find(v => v.line === vulnerability.line && v.label === vulnerability.label)) {
                    return file;
                  }
                  return {
                    ...file,
                    vulnerabilities: [...existing, vulnerability]
                  };
                }
                return file;
              }));
            } else if (data.type === "scan_complete") {
              console.log("Backend scan completed");
              ws.close();
            } else if (data.type === "error") {
              console.error("WebSocket error from backend:", data.message);
            }
          } catch (error) {
            console.error("Failed to parse WebSocket message:", error);
          }
        };

        ws.onerror = (event) => {
          // WebSocket error event doesn't have detailed error info
          console.warn("WebSocket connection error. Backend may not be running or URL is incorrect.");
          setWsConnected(false);
        };

        ws.onclose = (event) => {
          console.log("WebSocket disconnected", event.code === 1000 ? "(normal)" : `(code: ${event.code})`);
          setWsConnected(false);
          
          // Only attempt reconnect if it wasn't a normal closure and we still have files
          if (event.code !== 1000 && repoFiles.length > 0) {
            console.log("Attempting to reconnect in 3 seconds...");
            reconnectTimeout = setTimeout(() => {
              connect();
            }, 3000);
          }
        };

        wsRef.current = ws;
      } catch (error) {
        console.error("Failed to create WebSocket connection:", error);
        setWsConnected(false);
      }
    };

    connect();

    return () => {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close(1000, "Component unmounting");
      }
    };
  }, [repoUrl, repoFiles.length]); // Reconnect if repo changes

  useEffect(() => {
    if (!repoUrl) return;

    const startScan = async () => {
      // Only use API for full repos, fallback to direct fetch for single files if needed
      if (repoUrl.match(/github\.com\/([^/]+)\/([^/]+)$/)) {
        setIsLoading(true);
        try {
          // 1. Get Repo Structure (no vulnerabilities yet - they come via WebSocket)
          const res = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: repoUrl }),
          });

          if (!res.ok) throw new Error("Analysis failed");

          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            
            // 2. Fetch file contents (vulnerabilities will come via WebSocket)
            const filesWithContent = await Promise.all(data.map(async (f: any) => {
                const filePath = f.breadcrumb.join("/");
                
                // Fetch content
                const [_, owner, repo] = repoUrl?.match(/github\.com\/([^/]+)\/([^/]+)/) || [];
                const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${filePath}`;
                const contentRes = await fetch(rawUrl);
                
                if (!contentRes.ok) {
                  // Try master branch
                  const masterUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${filePath}`;
                  const masterRes = await fetch(masterUrl);
                  if (!masterRes.ok) {
                    return {
                      name: f.name,
                      path: filePath,
                      functions: f.functions,
                      vulnerabilities: [], // Will be populated via WebSocket
                      content: ""
                    };
                  }
                  const content = await masterRes.text();
                  return {
                    name: f.name,
                    path: filePath,
                    functions: f.functions,
                    vulnerabilities: [], // Will be populated via WebSocket
                    content: content
                  };
                }
                
                const content = await contentRes.text();

                return {
                    name: f.name,
                    path: filePath,
                    functions: f.functions,
                    vulnerabilities: [], // Will be populated via WebSocket
                    content: content 
                };
            }));

            setRepoFiles(filesWithContent);
          }
        } catch (error) {
          console.error("Scan error:", error);
        } finally {
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
    if (repoFiles.length > 0 && repoFiles[currentFileIndex]) {
      const file = repoFiles[currentFileIndex];
      
      if (file.content) {
        setCurrentCode(file.content);
        return;
      }
      // ... fallback fetch logic ...
    }
  }, [repoFiles, currentFileIndex, repoUrl]);

  // Auto-advance scanning through the repo
  const handleScanComplete = () => {
    if (repoFiles.length > 0 && currentFileIndex < repoFiles.length - 1) {
      // Move to next file after a brief pause
      setTimeout(() => {
        setCurrentFileIndex(prev => prev + 1);
      }, 1000);
    }
  };

  return (
    <ScannerDemo 
      initialCode={currentCode} 
      repoFiles={repoFiles.length > 0 ? repoFiles : undefined}
      currentFileIndex={currentFileIndex}
      onFileSelect={setCurrentFileIndex}
      onScanComplete={handleScanComplete}
      wsConnected={wsConnected}
    />
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={<div className="flex h-screen w-full items-center justify-center bg-[#0d1117] text-white">Loading...</div>}>
      <ScanContent />
    </Suspense>
  );
}
