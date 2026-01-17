"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import ScannerDemo from "@/components/ScannerDemo";
import { Suspense } from "react";

function ScanContent() {
  const searchParams = useSearchParams();
  const repoUrl = searchParams.get("url");
  const [repoFiles, setRepoFiles] = useState<{ name: string; path: string; content?: string; functions?: string[] }[]>([]);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  const [currentCode, setCurrentCode] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!repoUrl) return;

    const startScan = async () => {
      // Only use API for full repos, fallback to direct fetch for single files if needed
      if (repoUrl.match(/github\.com\/[^/]+\/[^/]+$/)) {
        setIsLoading(true);
        try {
          const res = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: repoUrl }),
          });

          if (!res.ok) throw new Error("Analysis failed");

          const data = await res.json();
          // data is now just an array of files
          if (Array.isArray(data) && data.length > 0) {
            // We need to fetch content for the first file since API doesn't return it anymore
            const files = data.map((f: any) => ({
              name: f.name,
              path: f.breadcrumb.join("/"),
              functions: f.functions,
              // content is missing, will be fetched by useEffect
            }));
            setRepoFiles(files);
          }
        } catch (error) {
          console.error("Scan error:", error);
        } finally {
          setIsLoading(false);
        }
      } else if (repoUrl.includes("/blob/")) {
        // Single file logic
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

      // Fallback
      const [_, owner, repo] = repoUrl?.match(/github\.com\/([^/]+)\/([^/]+)/) || [];
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${file.path}`;
      
      setCurrentCode(null);
      
      fetch(rawUrl)
        .then(res => res.text())
        .then(text => setCurrentCode(text))
        .catch(err => console.error("Failed to fetch file content", err));
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
