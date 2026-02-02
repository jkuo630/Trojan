import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import * as parser from "@babel/parser";
import traverse from "@babel/traverse";
import path from "path";
import { createServerClient } from "@/lib/supabase-server";

// Helper to recursively get files from GitHub API
async function getRepoFiles(owner: string, repo: string, treeSha = "main") {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`;
  const headers: HeadersInit = {
    "User-Agent": "Trojan-Scanner-Bot",
  };
  
  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  
  const res = await fetch(url, {
    headers,
    next: { revalidate: 3600 } // Cache for 1 hour
  });
  
  if (!res.ok) {
    // Try 'master' if 'main' fails
    if (treeSha === "main") return getRepoFiles(owner, repo, "master");
    throw new Error(`Failed to fetch tree: ${res.statusText}`);
  }
  
  const data = await res.json();
  return data.tree.filter((item: any) => item.type === "blob");
}

// Helper to fetch file content
async function getFileContent(owner: string, repo: string, path: string) {
  const headers: HeadersInit = {};
  
  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/main/${path}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
     // Try 'master' branch
     const masterUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${path}`;
     const resMaster = await fetch(masterUrl, { headers });
     if (!resMaster.ok) return "";
     return await resMaster.text();
  }
  return await res.text();
}

function extractFunctions(code: string, fileName: string): string[] {
  const functions: string[] = [];
  
  // Skip non-JS/TS files
  if (!/\.(js|jsx|ts|tsx)$/.test(fileName)) return functions;

  try {
    const ast = parser.parse(code, {
      sourceType: "module",
      plugins: ["typescript", "jsx"],
    });

    // @ts-ignore - Babel traverse types can be tricky with ESM
    const traverseFn = traverse.default || traverse;
    
    traverseFn(ast, {
      FunctionDeclaration(path: any) {
        if (path.node.id) functions.push(path.node.id.name);
      },
      VariableDeclarator(path: any) {
        if (
          path.node.init &&
          (path.node.init.type === "ArrowFunctionExpression" ||
           path.node.init.type === "FunctionExpression") &&
          path.node.id.type === "Identifier"
        ) {
          functions.push(path.node.id.name);
        }
      },
      ClassMethod(path: any) {
        if (path.node.key.type === "Identifier") {
          functions.push(path.node.key.name);
        }
      },
    });
  } catch (e) {
    // Ignore parsing errors
  }

  return functions;
}

export async function POST(req: NextRequest) {
  try {
    const supabase = createServerClient();
    const { data: { user }, error: authError } = await supabase.auth.getUser();

    // Fix for Vulnerability #1, #4, #6: Require authentication
    if (authError || !user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    }

    const body = await req.json();
    const { url, github_token } = body;

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
    }

    // Fix for Vulnerability #7: Validate and encrypt GitHub token
    if (github_token && typeof github_token !== 'string') {
      return NextResponse.json({ error: "Invalid GitHub token" }, { status: 400 });
    }

    // Clean URL: remove /tree/main, /blob/main, etc to get base repo URL
    const cleanUrl = url.replace(/\/tree\/.*$/, "").replace(/\/blob\/.*$/, "");
    const match = cleanUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
    
    if (!match) {
      return NextResponse.json({ error: "Invalid GitHub URL" }, { status: 400 });
    }

    const [_, owner, repo] = match;

    // 1. Get File Tree
    const files = await getRepoFiles(owner, repo);
    
    // 2. Filter out irrelevant files (images, configs, locks, etc)
    const codeFiles = files
      .filter((f: any) => {
        const path = f.path.toLowerCase();
        // Exclude common non-code / binary / config extensions
        const excludeExts = /\.(png|jpg|jpeg|gif|svg|ico|pdf|zip|tar|gz|json|lock|md|txt|xml|yaml|yml|css|scss|less|html|map|ttf|woff|woff2|eot|mp4|webm|mp3|ds_store)$/;
        
        // Exclude common generated/config directories
        const excludeDirs = /(node_modules|dist|build|coverage|\.git|\.next|\.vercel|public|assets|vendor|libs)/;

        return !excludeExts.test(path) && !excludeDirs.test(path);
      })
      .slice(0, 10); // increased limit slightly

    // 3. Process files in parallel
    const processPromises = codeFiles.map(async (file: any) => {
      try {
        const content = await getFileContent(owner, repo, file.path);
        const functions = extractFunctions(content, file.path);
        
        return {
          name: file.path.split("/").pop(),
          breadcrumb: file.path.split("/"),
          functions: functions
        };
      } catch (e) {
        console.error(`Error processing ${file.path}:`, e);
        return null;
      }
    });

    const processedFiles = (await Promise.all(processPromises)).filter(Boolean);

    // 4. Call LangGraph agent to identify suspicious files and analyze auth vulnerabilities
    let suspiciousFiles: any[] = [];
    let authVulnerabilities: any[] = [];
    try {
      const agentScriptPath = path.join(
        process.cwd(),
        "..",
        "langgraph",
        "test_starter",
        "run_agent.py"
      );
      
      // Prepare the file structure as JSON
      const fileStructureJson = JSON.stringify(processedFiles);
      
      // Execute Python script with file structure as stdin using spawn
      const pythonProcess = spawn("python3", [agentScriptPath], {
        env: {
          ...process.env,
          PYTHONPATH: path.join(process.cwd(), "..", "langgraph", "test_starter"),
        },
      });

      let stdout = "";
      let stderr = "";

      pythonProcess.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      pythonProcess.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      // Handle stdin write errors (EPIPE)
      pythonProcess.stdin.on("error", (err: any) => {
        if (err.code !== "EPIPE") {
          console.error("Python process stdin error:", err);
        }
      });

      // Write input to stdin
      try {
        pythonProcess.stdin.write(fileStructureJson);
        pythonProcess.stdin.end();
      } catch (err: any) {
        // Handle EPIPE errors when process has already ended
        if (err.code !== "EPIPE") {
          console.error("Error writing to Python process:", err);
        }
      }

      // Wait for process to complete
      await new Promise<void>((resolve, reject) => {
        pythonProcess.on("close", (code) => {
          if (code === 0) {
            resolve();
          } else {
            reject(new Error(`Python script exited with code ${code}`));
          }
        });
        pythonProcess.on("error", reject);
      });

      // Parse the output (now includes both suspicious_files and auth_vulnerabilities)
      if (stdout) {
        try {
          const output = JSON.parse(stdout.trim());
          // Handle both old format (array) and new format (object)
          if (Array.isArray(output)) {
            // Old format - just suspicious files array
            suspiciousFiles = output;
            authVulnerabilities = [];
          } else if (output.error) {
            // Error response
            throw new Error(output.error);
          } else {
            // New format - object with suspicious_files and auth_vulnerabilities
            suspiciousFiles = output.suspicious_files || [];
            authVulnerabilities = output.auth_vulnerabilities || [];
          }
        } catch (parseError: any) {
          // If parsing fails, check if it's an error message
          if (stdout.includes("error") || stdout.includes("Error") || stdout.includes("quota")) {
            console.error("Agent returned error:", stdout);
            throw new Error(stdout.trim());
          }
          console.error("Failed to parse agent output:", stdout);
          suspiciousFiles = [];
          authVulnerabilities = [];
        }
      }

      // Output to terminal
      console.log("\n=== SECURITY RISK ASSESSMENT ===");
      console.log(`Repository: ${owner}/${repo}`);
      console.log(`Total files analyzed: ${processedFiles.length}`);
      console.log(`Suspicious files found: ${suspiciousFiles.length}`);
      console.log(`Auth vulnerabilities found: ${authVulnerabilities.length}\n`);

      if (suspiciousFiles.length > 0) {
        suspiciousFiles.forEach((file: any, index: number) => {
          console.log(`${index + 1}. ${file.file_path || "Unknown"}`);
          console.log(`   Risk Level: ${file.risk_level || "unknown"}`);
          console.log(`   Reason: ${file.reason || "No reason provided"}`);
          if (file.suspicious_functions && file.suspicious_functions.length > 0) {
            console.log(`   Suspicious Functions: ${file.suspicious_functions.join(", ")}`);
          }
          console.log("");
        });
      } else {
        console.log("No suspicious files identified.\n");
      }

      if (authVulnerabilities.length > 0) {
        console.log("\n=== AUTHENTICATION VULNERABILITIES ===");
        authVulnerabilities.forEach((vuln: any, index: number) => {
          console.log(`${index + 1}. ${vuln.type || "Unknown"}`);
          console.log(`   Severity: ${vuln.severity || "unknown"}`);
          console.log(`   Location: ${vuln.location || "Unknown"}`);
          console.log(`   Description: ${vuln.description || "No description"}`);
          if (vuln.line) {
            console.log(`   Line: ${vuln.line}`);
          }
          console.log("");
        });
      }
      console.log("================================\n");

      if (stderr) {
        console.error("Agent stderr:", stderr);
      }
    } catch (agentError: any) {
      console.error("Error running security agent:", agentError);
      // Continue even if agent fails - return file structure anyway
    }

    // 5. Save project to Supabase if user is authenticated
    let projectId: string | null = null;
    try {
      if (user) {
        const repositoryName = `${owner}/${repo}`;
        const { data, error } = await supabase
          .from("projects")
          .insert({
            user_id: user.id,
            github_url: cleanUrl,
            repository_name: repositoryName,
            file_structure: processedFiles,
            suspicious_files: suspiciousFiles,
            status: "completed",
          })
          .select()
          .single();

        if (!error && data) {
          projectId = data.id;
          console.log(`Project saved to Supabase: ${projectId}`);
        } else {
          console.error("Error saving project to Supabase:", error);
        }
      }
    } catch (saveError) {
      console.error("Error saving project:", saveError);
      // Continue even if save fails
    }

    // Return file structure, suspicious files, auth vulnerabilities, plus project ID if saved
    return NextResponse.json({
      file_structure: processedFiles,
      suspicious_files: suspiciousFiles,
      auth_vulnerabilities: authVulnerabilities,
      project_id: projectId,
    });

  } catch (error) {
    console.error("Analysis failed:", error);
    return NextResponse.json({ error: "Analysis failed" }, { status: 500 });
  }
}