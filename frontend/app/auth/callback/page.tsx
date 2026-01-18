"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { ShieldCheck } from "lucide-react";

export default function AuthCallbackPage() {
  const router = useRouter();

  useEffect(() => {
    const handleCallback = async () => {
      try {
        // Get the session from the URL hash
        const { data, error } = await supabase.auth.getSession();

        if (error) {
          console.error("Error getting session:", error);
          router.push("/auth/login?error=callback_failed");
          return;
        }

        if (data.session) {
          // Store the GitHub access token for later use
          const githubToken = data.session.provider_token;
          
          console.log("=".repeat(60));
          console.log("🎉 GitHub OAuth Success!");
          console.log("=".repeat(60));
          console.log("📝 Full Session Data:", data.session);
          console.log("🔑 GitHub Token:", githubToken);
          console.log("👤 User Email:", data.session.user?.email);
          console.log("🆔 User ID:", data.session.user?.id);
          console.log("📅 Token Expires:", data.session.expires_at);
          console.log("=".repeat(60));
          
          if (githubToken) {
            // Store in localStorage for your Python bot to access later
            localStorage.setItem("github_token", githubToken);
            console.log("✅ Token saved to localStorage");
            
            // Test the token by fetching user's repos
            console.log("🧪 Testing token with GitHub API...");
            try {
              const response = await fetch("https://api.github.com/user", {
                headers: {
                  Authorization: `Bearer ${githubToken}`,
                  Accept: "application/vnd.github.v3+json",
                },
              });
              
              if (response.ok) {
                const userData = await response.json();
                console.log("✅ GitHub API Test Success!");
                console.log("👤 GitHub Username:", userData.login);
                console.log("📦 Public Repos:", userData.public_repos);
                console.log("🔒 Can access private repos:", response.headers.get("x-oauth-scopes")?.includes("repo"));
              } else {
                console.error("❌ GitHub API Test Failed:", response.status);
              }
            } catch (apiError) {
              console.error("❌ Error testing GitHub API:", apiError);
            }
          } else {
            console.warn("⚠️ No GitHub token found in session");
          }

          // Redirect to home page with synced flag
          console.log("🔄 Redirecting to home page...");
          router.push("/?synced=true");
        } else {
          console.warn("⚠️ No session found, redirecting to login");
          router.push("/auth/login");
        }
      } catch (err) {
        console.error("❌ Callback error:", err);
        router.push("/auth/login?error=unknown");
      }
    };

    handleCallback();
  }, [router]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-[#0d1117] text-white">
      <div className="flex flex-col items-center gap-4">
        <div className="relative">
          <div className="absolute inset-0 animate-pulse bg-blue-500/50 blur-xl rounded-full" />
          <ShieldCheck className="relative h-16 w-16 text-blue-500" />
        </div>
        <h2 className="text-xl font-semibold">Signing you in...</h2>
        <p className="text-gray-400">Please wait while we complete authentication</p>
      </div>
    </main>
  );
}
