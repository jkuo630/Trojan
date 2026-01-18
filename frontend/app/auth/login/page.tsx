"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabase";
import { ShieldCheck, Github } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [loginAttempts, setLoginAttempts] = useState(0);
  const maxAttempts = 5;
  const lockoutTime = 30000; // 30 seconds

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    if (loginAttempts >= maxAttempts) {
      setError("Too many login attempts. Please try again later.");
      setLoading(false);
      return;
    }

    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        setLoginAttempts((prev) => prev + 1);
        throw error;
      }

      setLoginAttempts(0); // Reset login attempts on successful login
      router.push("/projects");
    } catch (err: any) {
      setError(err.message || "Failed to login");
    } finally {
      setLoading(false);
      if (loginAttempts >= maxAttempts) {
        setTimeout(() => setLoginAttempts(0), lockoutTime); // Reset attempts after lockout time
      }
    }
  };

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
        <p className="text-gray-400 text-center mb-8">Sign in to your account</p>

        <form onSubmit={handleLogin} className="space-y-4">
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
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <p className="text-center text-gray-500 mt-6">
          Don't have an account?{" "}
          <Link href="/auth/signup" className="text-blue-500 hover:text-blue-400">
            Sign up
          </Link>
        </p>
      </div>
    </main>
  );
}
