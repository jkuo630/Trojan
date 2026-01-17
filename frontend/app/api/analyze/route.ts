import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import * as parser from "@babel/parser";
import traverse from "@babel/traverse";
import path from "path";

// Helper to recursively get files from GitHub API
async function getRepoFiles(owner: string, repo: string, treeSha = "main") {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`;
  const res = await fetch(url, {
    headers: {
      // Add a user agent to avoid some rate limits
      "User-Agent": "Trojan-Scanner-Bot",
      // If you have a token, add it here:
      // Authorization: `Bearer ${process.env.GITHUB_TOKEN}`
    },
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
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/main/${path}`;
  const res = await fetch(url);
  if (!res.ok) {
     // Try 'master' branch
     const masterUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${path}`;
     const resMaster = await fetch(masterUrl);
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
    const body = await req.json();
    const { url } = body;

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
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
        const excludeExts = /\.(png|jpg|jpeg|gif|svg|ico|pdf|zip|tar|gz|json|lock|md|txt|xml|yaml|yml|css|scss|less|html|map|ttf|woff|woff2|eot|mp4|webm|mp3)$/;
        
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

    // 4. Call LangGraph agent to identify suspicious files
    let suspiciousFiles: any[] = [];
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

      // Write input to stdin
      pythonProcess.stdin.write(fileStructureJson);
      pythonProcess.stdin.end();

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

      // Parse the output
      if (stdout) {
        try {
          suspiciousFiles = JSON.parse(stdout.trim());
        } catch (parseError) {
          console.error("Failed to parse agent output:", stdout);
          suspiciousFiles = [];
        }
      }

      // Output to terminal
      console.log("\n=== SECURITY RISK ASSESSMENT ===");
      console.log(`Repository: ${owner}/${repo}`);
      console.log(`Total files analyzed: ${processedFiles.length}`);
      console.log(`Suspicious files found: ${suspiciousFiles.length}\n`);

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
      console.log("================================\n");

      if (stderr) {
        console.error("Agent stderr:", stderr);
      }
    } catch (agentError: any) {
      console.error("Error running security agent:", agentError);
      // Continue even if agent fails - return file structure anyway
    }

    // Return both file structure and suspicious files
    return NextResponse.json({
      file_structure: processedFiles,
      suspicious_files: suspiciousFiles,
    });

  } catch (error) {
    console.error("Analysis failed:", error);
    return NextResponse.json({ error: "Analysis failed" }, { status: 500 });
  }
}
