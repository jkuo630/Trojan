"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import ScannerDemo from "@/components/ScannerDemo";
import { Suspense } from "react";

function ScanContent() {
  const searchParams = useSearchParams();
  const repoUrl = searchParams.get("url");
  const [repoFiles, setRepoFiles] = useState<{ name: string; path: string }[]>([]);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  const [currentCode, setCurrentCode] = useState<string | null>(null);

  useEffect(() => {
    if (!repoUrl) return;

    // Handle full repo URLs
    // Ex: https://github.com/facebook/react -> Fetch tree
    if (repoUrl.match(/github\.com\/[^/]+\/[^/]+$/)) {
      const [_, owner, repo] = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/) || [];
      if (owner && repo) {
        // Fetch repo tree (using public API, limited to 60 req/hr if unauth)
        fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/main?recursive=1`)
          .then(res => res.json())
          .then(data => {
            if (data.tree) {
              const files = data.tree
                .filter((f: any) => f.type === "blob" && /\.(ts|tsx|js|jsx|py|go|rs)$/.test(f.path))
                .slice(0, 20) // Limit to first 20 files for demo
                .map((f: any) => ({ name: f.path.split('/').pop(), path: f.path }));
              setRepoFiles(files);
            }
          })
          .catch(err => console.error("Failed to fetch repo tree", err));
      }
    } 
    // Handle specific file URLs
    else if (repoUrl.includes("/blob/")) {
      const rawUrl = repoUrl
        .replace("github.com", "raw.githubusercontent.com")
        .replace("/blob/", "/");
      
      fetch(rawUrl)
        .then(res => res.text())
        .then(text => setCurrentCode(text));
    }
  }, [repoUrl]);

  // Fetch content when current file changes (for repo mode)
  useEffect(() => {
    if (repoFiles.length > 0 && repoFiles[currentFileIndex]) {
      const [_, owner, repo] = repoUrl?.match(/github\.com\/([^/]+)\/([^/]+)/) || [];
      const file = repoFiles[currentFileIndex];
      // Construct raw URL
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${file.path}`;
      
      // Reset code to null to show loading state or transition
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
