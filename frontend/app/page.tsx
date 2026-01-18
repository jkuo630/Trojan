"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Image from "next/image";
import { Github, CheckCircle2, ArrowRight } from "lucide-react";
import { supabase } from "@/lib/supabase";

function LandingPageContent(): JSX.Element {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [showInput, setShowInput] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [justSynced, setJustSynced] = useState(false);

  const submitUrl = (url: string) => {
    if (!url) return;

    // Check if user is authenticated
    if (!user) {
      router.push("/auth/login");
      return;
    }

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

  const handleGitHubLogin = async () => {
    setLoading(true);

    try {
      const { data, error } = await supabase.auth.signInWithOAuth({
        provider: "github",
        options: {
          redirectTo: `${window.location.origin}/auth/callback`,
          scopes: "repo read:user", // Request repo access for GitHub API
        },
      });

      if (error) throw error;
      // The redirect will happen automatically, so we don't need to do anything else
    } catch (err: any) {
      console.error("Failed to login with GitHub:", err);
      setLoading(false);
      // Optionally show an error message to the user
      alert("Failed to connect with GitHub. Please try again.");
    }
  };

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    setUser(null);
    router.push("/");
  };

  // Get user display name
  const getUserDisplayName = () => {
    if (!user) return "";
    return user.user_metadata?.full_name || 
           user.user_metadata?.name || 
           user.email?.split("@")[0] || 
           "User";
  };

  // Check if user just synced GitHub
  useEffect(() => {
    const synced = searchParams.get("synced");
    if (synced === "true") {
      setJustSynced(true);
      // Remove the query parameter from URL
      router.replace("/", { scroll: false });
      // Check auth status
      supabase.auth.getUser().then(({ data }) => {
        if (data.user) {
          setUser(data.user);
          // Auto-show input when synced
          setShowInput(true);
        }
      });
    } else {
      // Check auth status normally
      supabase.auth.getUser().then(({ data }) => {
        if (data.user) {
          setUser(data.user);
        }
      });
    }
  }, [searchParams, router]);


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
        <h1 className="mb-4 text-6xl font-bold uppercase tracking-tight sm:text-7xl text-white">
          TROJAN
        </h1>

        {/* Subtitle */}
        <p className={`text-lg text-gray-300 font-normal max-w-md ${justSynced && user ? "mb-15" : "mb-30"}`}>
        Agentic security testing for vibe-coded apps.
        </p>

        {/* Success message after GitHub sync */}
        {justSynced && user && (
          <div className="mb-6 flex items-center gap-2 bg-green-500/10 border border-green-500/30 rounded-lg px-4 py-3 text-green-400">
            <CheckCircle2 className="h-5 w-5 flex-shrink-0" />
            <span className="text-sm">GitHub connected! Add a repository link below to get started.</span>
          </div>
        )}

        {/* Connect to Github Button or Input */}
        {!user ? (
          <button 
            onClick={handleGitHubLogin}
            disabled={loading}
            className="mb-4 flex items-center gap-3 bg-[#161b22] hover:bg-[#1c2128] border border-[#30363d] rounded-lg px-6 py-3 text-white font-medium transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Github className="h-5 w-5" />
            <span>{loading ? "Connecting..." : "Sign in with GitHub"}</span>
          </button>
        ) : (
          <>
            <form onSubmit={handleSubmit} className="mb-2 w-full max-w-md">
              <div className="flex items-center gap-2 bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-3">
                <Github className="h-5 w-5 text-gray-400 flex-shrink-0" />
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/username/repo..."
                  className="flex-1 bg-transparent border-none text-white placeholder-gray-500 focus:outline-none focus:ring-0"
                  autoFocus={justSynced}
                />
                <button
                  type="submit"
                  disabled={!repoUrl || !repoUrl.includes("github.com")}
                  className="flex-shrink-0 p-1.5 bg-[#6699C9] hover:bg-[#5a8ab8] disabled:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors cursor-pointer"
                  title="Submit"
                >
                  <ArrowRight className="h-4 w-4 text-white" />
                </button>
              </div>
            </form>
            <p className="text-xs text-gray-400 mb-4">
              Signed in as {getUserDisplayName()},{" "}
              <button
                onClick={handleSignOut}
                className="underline hover:text-gray-300 transition-colors cursor-pointer"
              >
                Sign out?
              </button>
            </p>
          </>
        )}
      </div>
    </main>
  );
}

export default function LandingPage() {
  return (
    <Suspense fallback={
      <main className="flex min-h-screen items-center justify-center bg-[#0d1117] text-white">
        <div className="text-gray-400">Loading...</div>
      </main>
    }>
      <LandingPageContent />
    </Suspense>
  );
}
