"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import { Github } from "lucide-react";

export default function LandingPage() {
  const router = useRouter();
  const [showInput, setShowInput] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");

  const submitUrl = (url: string) => {
    if (!url) return;

    // Basic validation to ensure it's a GitHub URL
    if (!url.includes("github.com")) {
      return;
    }

    // Check if it's a valid GitHub repository URL pattern
    const githubMatch = url.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!githubMatch) {
      return;
    }

    // Encode the URL to pass it safely as a query parameter
    const encodedUrl = encodeURIComponent(url);
    router.push(`/scan?url=${encodedUrl}`);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    submitUrl(repoUrl);
  };

  // Auto-submit when a valid GitHub URL is entered
  useEffect(() => {
    if (showInput && repoUrl) {
      const githubMatch = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (githubMatch) {
        // Small delay to ensure user has finished typing
        const timeoutId = setTimeout(() => {
          submitUrl(repoUrl);
        }, 500);
        return () => clearTimeout(timeoutId);
      }
    }
  }, [repoUrl, showInput]);

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#0d1117] text-white">
      <div className="flex flex-col items-center justify-center text-center px-4">
        {/* Logo */}
        <div className="mb-4">
          <Image
            src="/horse.svg"
            alt="Trojan Logo"
            width={130}
            height={130}
            className="w-30 h-30"
          />
        </div>

        {/* Title */}
        <h1 className="mb-6 text-6xl font-bold uppercase tracking-tight sm:text-7xl text-white">
          TROJAN
        </h1>

        {/* Subtitle */}
        <p className="mb-30 text-lg text-gray-300 font-normal max-w-md">
          Find security vulnerabilities in your code
          <br />
          and patch them instantly.
        </p>

        {/* Connect to Github Button or Input */}
        {!showInput ? (
          <button className="mb-4 flex items-center gap-3 bg-[#161b22] hover:bg-[#1c2128] border border-[#30363d] rounded-lg px-6 py-3 text-white font-medium transition-colors">
            <Github className="h-5 w-5" />
            <span>Connect to Github</span>
          </button>
        ) : (
          <form onSubmit={handleSubmit} className="mb-4 w-full max-w-md">
            <div className="flex items-center gap-2 bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-3">
              <Github className="h-5 w-5 text-gray-400 flex-shrink-0" />
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/username/repo..."
                className="w-full bg-transparent border-none text-white placeholder-gray-500 focus:outline-none focus:ring-0"
                autoFocus
              />
            </div>
          </form>
        )}

        {/* Secondary Link */}
        <button
          onClick={() => setShowInput(!showInput)}
          className="text-sm text-gray-300 underline hover:text-white transition-colors cursor-pointer"
        >
          {showInput ? "or connect to your GitHub" : "or link your GitHub repository"}
        </button>
      </div>
    </main>
  );
}
