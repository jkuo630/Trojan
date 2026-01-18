"use client";

import Link from "next/link";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { ShieldCheck, ChevronRight, Play, Github, LogIn } from "lucide-react";
import { supabase } from "@/lib/supabase";

export default function LandingPage() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [checkingAuth, setCheckingAuth] = useState(true);

  useEffect(() => {
    // Check if user is logged in
    supabase.auth.getUser().then(({ data }: { data: any }) => {
      setUser(data.user);
      setCheckingAuth(false);
    });

    // Listen for auth changes
    const { data: authListener } = supabase.auth.onAuthStateChange((event: any, session: any) => {
      setUser(session?.user ?? null);
    });

    return () => {
      authListener.subscription.unsubscribe();
    };
  }, []);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl) return;

    // Basic validation to ensure it's a GitHub URL
    if (!repoUrl.includes("github.com")) {
      alert("Please enter a valid GitHub repository URL");
      return;
    }

    setLoading(true);
    // Encode the URL to pass it safely as a query parameter
    const encodedUrl = encodeURIComponent(repoUrl);
    router.push(`/scan?url=${encodedUrl}`);
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-[#0d1117] text-white overflow-hidden relative">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-blue-900/20 via-[#0d1117] to-[#0d1117]" />
      
      {/* Grid Pattern */}
      <div className="absolute inset-0 opacity-20" 
           style={{ backgroundImage: 'linear-gradient(#30363d 1px, transparent 1px), linear-gradient(90deg, #30363d 1px, transparent 1px)', backgroundSize: '40px 40px' }} 
      />

      <div className="relative z-10 max-w-5xl px-4 text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="flex justify-center mb-8"
        >
          <div className="relative">
            <div className="absolute inset-0 animate-pulse bg-blue-500/50 blur-xl rounded-full" />
            <ShieldCheck className="relative h-24 w-24 text-blue-500" />
          </div>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="mb-6 text-6xl font-bold tracking-tight sm:text-8xl bg-gradient-to-br from-white via-blue-100 to-blue-500 bg-clip-text text-transparent"
        >
          TROJAN
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mb-12 text-xl text-gray-400 sm:text-2xl max-w-2xl mx-auto"
        >
          Automated vulnerability scanning for your modern stack. 
          Identify security risks in real-time with AI-powered static analysis.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="w-full max-w-md mx-auto"
        >
          <form onSubmit={handleScan} className="flex flex-col gap-4">
            <div className="relative group">
              <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-cyan-600 rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
              <div className="relative flex items-center bg-[#0d1117] rounded-lg border border-gray-700 p-1 focus-within:border-blue-500 transition-colors">
                <Github className="ml-3 h-5 w-5 text-gray-500" />
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/username/repo..."
                  className="w-full bg-transparent border-none px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-0"
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {loading ? "Loading..." : "Scan"}
                  {!loading && <ChevronRight className="h-4 w-4" />}
                </button>
              </div>
            </div>
          </form>
          
          <p className="mt-4 text-sm text-gray-500">
            Paste a public GitHub repository URL to analyze the codebase.
          </p>
        </motion.div>

        {/* Auth Section */}
        {!checkingAuth && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.8 }}
            className="mt-8"
          >
            {user ? (
              <Link
                href="/projects"
                className="inline-flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
              >
                <span>View Your Projects</span>
                <ChevronRight className="h-4 w-4" />
              </Link>
            ) : (
              <Link
                href="/auth/login"
                className="inline-flex items-center gap-2 text-blue-500 hover:text-blue-400 transition-colors"
              >
                <LogIn className="h-4 w-4" />
                <span>Sign in to save your scans</span>
              </Link>
            )}
          </motion.div>
        )}
      </div>

      {/* Decorative footer elements */}
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1, duration: 1 }}
        className="absolute bottom-8 left-0 right-0 flex justify-center gap-8 text-xs text-gray-600 uppercase tracking-widest"
      >
        <span>Secure</span>
        <span>•</span>
        <span>Fast</span>
        <span>•</span>
        <span>Intelligent</span>
      </motion.div>
    </main>
  );
}
