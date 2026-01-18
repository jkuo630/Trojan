"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabase";
<<<<<<< HEAD
import { ShieldCheck } from "lucide-react";
=======
import { ShieldCheck, Github } from "lucide-react";
>>>>>>> ec4775d74a727c9454d744f04358018aef183d7a

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
      });

      if (error) throw error;

      router.push("/projects");
    } catch (err: any) {
      setError(err.message || "Failed to sign up");
    } finally {
      setLoading(false);
    }
  };

<<<<<<< HEAD
=======
  const handleGitHubSignup = async () => {
    setLoading(true);
    setError("");

    try {
      const { data, error } = await supabase.auth.signInWithOAuth({
        provider: "github",
        options: {
          redirectTo: `${window.location.origin}/auth/callback`,
          scopes: "repo read:user", // Request repo access for GitHub API
        },
      });

      if (error) throw error;
    } catch (err: any) {
      setError(err.message || "Failed to sign up with GitHub");
      setLoading(false);
    }
  };

>>>>>>> ec4775d74a727c9454d744f04358018aef183d7a
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-[#0d1117] text-white">
      <div className="w-full max-w-md px-4">
        <div className="flex justify-center mb-8">
          <div className="relative">
            <div className="absolute inset-0 animate-pulse bg-blue-500/50 blur-xl rounded-full" />
            <ShieldCheck className="relative h-16 w-16 text-blue-500" />
          </div>
        </div>

        <h1 className="text-4xl font-bold text-center mb-2">TROJAN</h1>
        <p className="text-gray-400 text-center mb-8">Create your account</p>

        <form onSubmit={handleSignup} className="space-y-4">
          <div>
            <label htmlFor="email" className="block text-sm font-medium mb-2">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full bg-[#0d1117] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              placeholder="you@example.com"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium mb-2">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={6}
              className="w-full bg-[#0d1117] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              placeholder="••••••••"
            />
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/50 rounded-lg px-4 py-3 text-red-400 text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Creating account..." : "Sign Up"}
          </button>
        </form>

<<<<<<< HEAD
=======
        <div className="relative my-6">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-700"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-[#0d1117] text-gray-500">Or continue with</span>
          </div>
        </div>

        <button
          onClick={handleGitHubSignup}
          disabled={loading}
          className="w-full bg-[#24292e] hover:bg-[#2f363d] text-white px-6 py-3 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          <Github className="h-5 w-5" />
          {loading ? "Connecting..." : "Sign up with GitHub"}
        </button>

>>>>>>> ec4775d74a727c9454d744f04358018aef183d7a
        <p className="text-center text-gray-500 mt-6">
          Already have an account?{" "}
          <Link href="/auth/login" className="text-blue-500 hover:text-blue-400">
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
