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

  useEffect(() => {
    if (!repoUrl) return;

    const startScan = async () => {
      // Only use API for full repos, fallback to direct fetch for single files if needed
      if (repoUrl.match(/github\.com\/[^/]+\/[^/]+$/)) {
        setIsLoading(true);
        setScanStatus("Scanning repository structure...");
        setRepoFiles([]); // Clear any previous files
        
        try {
          setScanStatus("Analyzing files and identifying suspicious patterns...");
          const res = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: repoUrl }),
          });

          if (!res.ok) throw new Error("Analysis failed");

          setScanStatus("Processing results...");
          const data = await res.json();
          
          // If project was saved, redirect to project detail page
          if (data.project_id) {
            router.push(`/projects/${data.project_id}`);
            return;
          }
          
          // Use suspicious_files from LangGraph agent instead of all files
          if (data.suspicious_files && Array.isArray(data.suspicious_files)) {
            if (data.suspicious_files.length > 0) {
              // Map suspicious files to the format expected by the frontend
              const files = data.suspicious_files.map((f: any) => ({
                name: f.file_path?.split("/").pop() || "Unknown",
                path: f.file_path || "",
                functions: f.suspicious_functions || [],
                riskLevel: f.risk_level || "unknown",
                reason: f.reason || "",
                // content will be fetched by useEffect
              }));
              setRepoFiles(files);
              setScanStatus(`Found ${files.length} suspicious file(s)`);
            } else {
              setScanStatus("No suspicious files found. Analysis complete.");
            }
          } else if (Array.isArray(data) && data.length > 0) {
            // Fallback to old format if suspicious_files doesn't exist
            const files = data.map((f: any) => ({
              name: f.name,
              path: f.breadcrumb.join("/"),
              functions: f.functions,
            }));
            setRepoFiles(files);
            setScanStatus(`Analyzing ${files.length} file(s)`);
          } else {
            setScanStatus("No files to analyze");
          }
        } catch (error) {
          console.error("Scan error:", error);
          setScanStatus("Scan failed. Please try again.");
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
            onScanComplete={handleScanComplete}
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
