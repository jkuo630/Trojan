"use client";

import { useEffect, useState } from "react";
import { useRouter, useParams } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabase";
import ScannerDemo from "@/components/ScannerDemo";
import { ShieldCheck, ArrowLeft, LogOut } from "lucide-react";

interface Project {
  id: string;
  github_url: string;
  repository_name: string;
  file_structure?: any[];
  suspicious_files?: any[];
  created_at: string;
}

export default function ProjectDetailPage() {
  const router = useRouter();
  const params = useParams();
  const projectId = params?.id as string;

  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);
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
  const [repository, setRepository] = useState<string>("");
  const [suspiciousFiles, setSuspiciousFiles] = useState<any[]>([]);
  const [authVulnerabilities, setAuthVulnerabilities] = useState<any[]>([]);

  useEffect(() => {
    console.log("useEffect triggered - checking auth...");
    // Check auth
    supabase.auth.getUser().then(({ data, error }) => {
      if (error || !data.user) {
        console.log("Auth failed - redirecting to login");
        router.push("/auth/login");
        return;
      }
      console.log("Auth successful - calling loadProject()");
      loadProject();
    });
  }, [projectId, router]);

  const loadProject = async () => {
    console.log("loadProject() called");
    try {
      const { data: { user } } = await supabase.auth.getUser();
      console.log("Got user:", user?.id);
      if (!user) {
        console.log("No user found - returning early");
        return;
      }

      const { data, error } = await supabase
        .from("projects")
        .select("*")
        .eq("id", projectId)
        .eq("user_id", user.id)
        .single();

      console.log("Supabase query result:", { hasData: !!data, hasError: !!error });
      
      if (error) {
        console.log("Supabase error:", error);
        throw error;
      }
      if (!data) {
        console.log("No project data - redirecting");
        router.push("/projects");
        return;
      }

      console.log("Project data loaded successfully");
      setProject(data);

      // Get repository from localStorage
      const storedRepo = localStorage.getItem('current_repository');
      if (storedRepo) {
        setRepository(storedRepo);
      }
      console.log(`Repository: ${storedRepo}`);

      // Store suspicious files data for fix workflow
      if (data.suspicious_files && Array.isArray(data.suspicious_files)) {
        setSuspiciousFiles(data.suspicious_files);
        
        // Map suspicious files for visualization
        const files = data.suspicious_files.map((f: any) => ({
          name: f.file_path?.split("/").pop() || "Unknown",
          path: f.file_path || "",
          functions: f.suspicious_functions || [],
          riskLevel: f.risk_level || "unknown",
          reason: f.reason || "",
        }));
        setRepoFiles(files);
      }

      // Load auth vulnerabilities if available
      if (data.auth_vulnerabilities && Array.isArray(data.auth_vulnerabilities)) {
        setAuthVulnerabilities(data.auth_vulnerabilities);
      }
    } catch (error) {
      console.error("Error loading project:", error);
      router.push("/projects");
    } finally {
      setLoading(false);
    }
  };

  // Fetch file content when current file changes
  useEffect(() => {
    if (repoFiles.length > 0 && repoFiles[currentFileIndex] && project) {
      const file = repoFiles[currentFileIndex];
      
      if (file.content) {
        setCurrentCode(file.content);
        return;
      }

      // Extract owner/repo from github_url
      const match = project.github_url.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (match) {
        const [_, owner, repo] = match;
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/main/${file.path}`;
        
        setCurrentCode(null);
        fetch(rawUrl)
          .then(res => res.text())
          .then(text => setCurrentCode(text))
          .catch(err => console.error("Failed to fetch file content", err));
      }
    }
  }, [repoFiles, currentFileIndex, project]);

  const handleScanComplete = () => {
    if (repoFiles.length > 0 && currentFileIndex < repoFiles.length - 1) {
      setTimeout(() => {
        setCurrentFileIndex(prev => prev + 1);
      }, 1000);
    }
  };

  if (loading) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#0d1117] text-white">
        <div className="text-gray-400">Loading...</div>
      </main>
    );
  }

  if (!project) {
    return null;
  }

  return (
    <main className="min-h-screen bg-[#0d1117] text-white flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-[#0d1117] flex-shrink-0">
        <div className="px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              href="/projects"
              className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="h-5 w-5" />
              <span>Back to Projects</span>
            </Link>
            <span className="text-gray-600">|</span>
            <span className="text-gray-400">{project.repository_name}</span>
          </div>
          <Link
            href="/projects"
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
          >
            <ShieldCheck className="h-6 w-6 text-blue-500" />
          </Link>
        </div>
      </header>

      {/* Scanner Visualization */}
      <div className="flex-1 overflow-hidden">
        <ScannerDemo
          initialCode={currentCode}
          repoFiles={repoFiles.length > 0 ? repoFiles : undefined}
          currentFileIndex={currentFileIndex}
          onFileSelect={setCurrentFileIndex}
          onScanComplete={handleScanComplete}
          repository={repository}
          suspiciousFiles={suspiciousFiles}
          authVulnerabilities={authVulnerabilities}
        />
      </div>
    </main>
  );
}
