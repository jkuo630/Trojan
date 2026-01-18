"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabase";
import { ShieldCheck, Plus, LogOut, FolderOpen, AlertTriangle } from "lucide-react";

interface Project {
  id: string;
  github_url: string;
  repository_name: string;
  suspicious_files?: any[];
  created_at: string;
  status: string;
}

export default function ProjectsPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    // Check auth status
    supabase.auth.getUser().then(({ data, error }) => {
      if (error || !data.user) {
        router.push("/auth/login");
        return;
      }
      setUser(data.user);
      loadProjects();
    });

    // Listen for auth changes
    const { data: authListener } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === "SIGNED_OUT" || !session) {
        router.push("/auth/login");
      }
    });

    return () => {
      authListener?.subscription.unsubscribe();
    };
  }, [router]);

  const loadProjects = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      const { data, error } = await supabase
        .from("projects")
        .select("*")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });

      if (error) throw error;
      setProjects(data || []);
    } catch (error) {
      console.error("Error loading projects:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    router.push("/auth/login");
  };

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#0d1117] text-white">
        <div className="text-gray-400">Loading...</div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#0d1117] text-white">
      {/* Header */}
      <header className="border-b border-gray-800 bg-[#0d1117]">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <ShieldCheck className="h-8 w-8 text-blue-500" />
            <h1 className="text-2xl font-bold">TROJAN</h1>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-gray-400 text-sm">{user?.email}</span>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
            >
              <LogOut className="h-4 w-4" />
              Logout
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-8">
          <h2 className="text-3xl font-bold">Your Projects</h2>
          <Link
            href="/"
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg font-medium transition-colors"
          >
            <Plus className="h-5 w-5" />
            New Scan
          </Link>
        </div>

        {projects.length === 0 ? (
          <div className="text-center py-16">
            <FolderOpen className="h-16 w-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400 mb-6">No projects yet. Start a new scan to get started.</p>
            <Link
              href="/"
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg font-medium transition-colors"
            >
              <Plus className="h-5 w-5" />
              Start New Scan
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {projects.map((project) => (
              <Link
                key={project.id}
                href={`/projects/${project.id}`}
                className="block bg-[#161b22] border border-gray-800 rounded-lg p-6 hover:border-blue-500 transition-colors"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold mb-1 truncate">{project.repository_name}</h3>
                    <p className="text-sm text-gray-400 truncate">{project.github_url}</p>
                  </div>
                  {project.suspicious_files && project.suspicious_files.length > 0 && (
                    <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0" />
                  )}
                </div>

                <div className="space-y-2 text-sm text-gray-400">
                  {project.suspicious_files && (
                    <div>
                      <span className="text-gray-500">Suspicious files: </span>
                      <span className="text-white">{project.suspicious_files.length}</span>
                    </div>
                  )}
                  <div>
                    <span className="text-gray-500">Status: </span>
                    <span className="capitalize text-white">{project.status}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Created: </span>
                    <span className="text-white">
                      {new Date(project.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
