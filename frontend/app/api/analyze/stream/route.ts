import { NextRequest } from "next/server";
import { spawn } from "child_process";
import * as parser from "@babel/parser";
import traverse from "@babel/traverse";
import path from "path";

// Middleware for authentication
async function authenticateRequest(req: NextRequest) {
  // Implement your authentication logic here
  // Example: Check for a valid session token or API key
  const authHeader = req.headers.get('Authorization');
  if (!authHeader || !isValidToken(authHeader)) {
    throw new Error('Unauthorized');
  }
}

// Helper to recursively get files from GitHub API
async function getRepoFiles(owner: string, repo: string, treeSha = "main") {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`;
  const res = await fetch(url, {
    headers: {
      "User-Agent": "Trojan-Scanner-Bot",
    },
    next: { revalidate: 3600 }
  });
  
  if (!res.ok) {
    if (treeSha === "main") return getRepoFiles(owner, repo, "master");
    throw new Error(`Failed to fetch tree: ${res.statusText}`);
  }
  
  const data = await res.json();
  
  // Check if the tree was truncated (GitHub API limits to 100,000 entries)
  if (data.truncated) {
    console.warn(`GitHub tree was truncated. Only showing first ${data.tree.length} files.`);
  }
  
  return data.tree.filter((item: any) => item.type === "blob");
}

// Helper to fetch file content
async function getFileContent(owner: string, repo: string, path: string) {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/main/${path}`;
  const res = await fetch(url);
  if (!res.ok) {
    const masterUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${path}`;
    const resMaster = await fetch(masterUrl);
    if (!resMaster.ok) return "";
    return await resMaster.text();
  }
  return await res.text();
}

function extractFunctions(code: string, fileName: string): string[] {
  const functions: string[] = [];
  
  if (!/\.(js|jsx|ts|tsx)$/.test(fileName)) return functions;

  try {
    const ast = parser.parse(code, {
      sourceType: "module",
      plugins: ["typescript", "jsx"],
    });

    const traverseFn = (traverse as any).default || traverse;
    
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
    await authenticateRequest(req); // Ensure request is authenticated
  } catch (error) {
    return new Response(JSON.stringify({ error: "Unauthorized access" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const body = await req.json();
  const { url, github_token } = body;

  if (!url) {
    return new Response(JSON.stringify({ error: "URL is required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate and encrypt GitHub token
  if (!github_token || !isValidGithubToken(github_token)) {
    return new Response(JSON.stringify({ error: "Invalid GitHub token" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const cleanUrl = url.replace(/\/tree\/.*$/, "").replace(/\/blob\/.*$/, "");
  const match = cleanUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
  
  if (!match) {
    return new Response(JSON.stringify({ error: "Invalid GitHub URL" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const [_, owner, repo] = match;

  // Create a readable stream for SSE
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const sendEvent = (type: string, data: any) => {
        const event = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
        controller.enqueue(encoder.encode(event));
      };

      try {
        // 1. Get File Tree
        sendEvent("status", { message: "Scanning repository structure..." });
        const files = await getRepoFiles(owner, repo);
        
        // 2. Filter code files
        const codeFiles = files
          .filter((f: any) => {
            const path = f.path.toLowerCase();
            const excludeExts = /\.(png|jpg|jpeg|gif|svg|ico|pdf|zip|tar|gz|json|lock|md|txt|xml|yaml|yml|css|scss|less|html|map|ttf|woff|woff2|eot|mp4|webm|mp3)$/;
            const excludeDirs = /(node_modules|dist|build|coverage|\.git|\.next|\.vercel|public|assets|vendor|libs)/;
            return !excludeExts.test(path) && !excludeDirs.test(path);
          });

        sendEvent("status", { message: `Analyzing ${codeFiles.length} files...` });

        // 3. Process files (include content for line number analysis)
        const processPromises = codeFiles.map(async (file: any) => {
          try {
            const content = await getFileContent(owner, repo, file.path);
            const functions = extractFunctions(content, file.path);
            return {
              name: file.path.split("/").pop(),
              path: file.path,
              breadcrumb: file.path.split("/"),
              functions: functions,
              content: content  // Include content so agent can find line numbers
            };
          } catch (e) {
            return null;
          }
        });

        const processedFiles = (await Promise.all(processPromises)).filter(Boolean);

        // 4. Call LangGraph agent with streaming
        sendEvent("status", { message: "Running security analysis..." });
        const agentScriptPath = path.join(
          process.cwd(),
          "..",
          "langgraph",
          "test_starter",
          "run_agent.py"
        );
        
        const fileStructureJson = JSON.stringify(processedFiles);
        const pythonProcess = spawn("python3", [agentScriptPath], {
          env: {
            ...process.env,
            PYTHONPATH: path.join(process.cwd(), "..", "langgraph", "test_starter"),
          },
        });

        let stdout = "";
        let stderr = "";

        // Read stdout line by line to catch streaming events
        pythonProcess.stdout.on("data", (data) => {
          const text = data.toString();
          stdout += text;
          
          // Process each line to check for streaming events
          const lines = text.split("\n");
          for (const line of lines) {
            if (line.startsWith("__STREAM__:")) {
              try {
                const eventData = JSON.parse(line.substring(11)); // Remove "__STREAM__:" prefix
                if (eventData.type === "auth_vulnerability" || 
                    eventData.type === "injection_vulnerability" ||
                    eventData.type === "sensitive_data_vulnerability" ||
                    eventData.type === "cryptographic_vulnerability") {
                  sendEvent("vulnerability", { ...eventData.data, _vulnerabilityType: eventData.type });
                } else if (eventData.type === "suspicious_files") {
                  sendEvent("suspicious_files", eventData.data);
                } else if (eventData.type === "suspicious_files_partial") {
                  sendEvent("suspicious_files_partial", eventData.data);
                } else if (eventData.type === "file_analysis_start") {
                  sendEvent("file_analysis_start", eventData.data);
                } else if (eventData.type === "file_analysis_complete") {
                  sendEvent("file_analysis_complete", eventData.data);
                } else if (eventData.type === "error") {
                  sendEvent("error", eventData.data);
                }
              } catch (e) {
                // Ignore parse errors for stream events
              }
            }
          }
        });

        pythonProcess.stderr.on("data", (data) => {
          stderr += data.toString();
        });

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

        // Parse final output
        if (stdout) {
          try {
            const output = JSON.parse(stdout.trim());
            if (!Array.isArray(output) && !output.error) {
              // New format with suspicious_files and auth_vulnerabilities
              if (output.suspicious_files) {
                sendEvent("suspicious_files", output.suspicious_files);
              }
              if (output.auth_vulnerabilities) {
                // Already sent via stream, but send final summary
                sendEvent("complete", {
                  suspicious_files: output.suspicious_files || [],
                  auth_vulnerabilities: output.auth_vulnerabilities || []
                });
              }
            }
          } catch (parseError) {
            // Ignore parse errors
          }
        }

        sendEvent("status", { message: "Analysis complete" });
        
      } catch (error: any) {
        sendEvent("error", { message: error.message || "Analysis failed" });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    },
  });
}

// Helper function to validate tokens
function isValidToken(token: string): boolean {
  // Implement your token validation logic
  return true;
}

// Helper function to validate GitHub tokens
function isValidGithubToken(token: string): boolean {
  // Implement your GitHub token validation logic
  return true;
}
