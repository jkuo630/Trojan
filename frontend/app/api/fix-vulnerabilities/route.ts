import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import path from "path";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { file_fix_request, github_token, base_branch } = body;

    // Validate required fields
    if (!file_fix_request) {
      return NextResponse.json(
        { success: false, error: "file_fix_request is required" },
        { status: 400 }
      );
    }

    if (!github_token) {
      return NextResponse.json(
        { success: false, error: "github_token is required" },
        { status: 400 }
      );
    }

    // Path to the Python script
    const pythonScriptPath = path.join(
      process.cwd(),
      "..",
      "langgraph",
      "test_starter",
      "fix_vulnerabilities.py"
    );

    console.log("🔧 Starting vulnerability fix workflow...");
    console.log(`   Repository: ${file_fix_request.repository}`);
    console.log(`   File: ${file_fix_request.file_path}`);
    console.log(`   Vulnerabilities: ${file_fix_request.vulnerabilities?.length || 0}`);

    // Execute Python script with request data as stdin
    const pythonProcess = spawn("python", [pythonScriptPath], {
      env: {
        ...process.env,
        PYTHONPATH: path.join(process.cwd(), "..", "langgraph", "test_starter"),
      },
    });

    let stdout = "";
    let stderr = "";

    pythonProcess.stdout.on("data", (data) => {
      const output = data.toString();
      stdout += output;
      console.log(output); // Log to server console
    });

    pythonProcess.stderr.on("data", (data) => {
      const output = data.toString();
      stderr += output;
      console.error(output); // Log errors to server console
    });

    // Prepare request payload
    const requestPayload = {
      file_fix_request,
      github_token,
      base_branch: base_branch || "main",
    };

    // Handle stdin write errors (EPIPE)
    pythonProcess.stdin.on("error", (err: any) => {
      if (err.code !== "EPIPE") {
        console.error("Python process stdin error:", err);
      }
    });

    // Write input to stdin
    try {
      pythonProcess.stdin.write(JSON.stringify(requestPayload));
      pythonProcess.stdin.end();
    } catch (err: any) {
      // Handle EPIPE errors when process has already ended
      if (err.code !== "EPIPE") {
        console.error("Error writing to Python process:", err);
      }
    }

    // Wait for process to complete
    const exitCode = await new Promise<number>((resolve, reject) => {
      pythonProcess.on("close", (code) => {
        resolve(code || 0);
      });
      pythonProcess.on("error", (err: any) => {
        if (err.code !== "EPIPE") {
          reject(err);
        } else {
          resolve(0); // EPIPE is expected if process ended unexpectedly
        }
      });
    });

    // Parse the output - extract multi-line JSON from stdout
    if (stdout) {
      try {
        // Find where JSON starts (line starting with '{')
        const lines = stdout.split('\n');
        const jsonStartIndex = lines.findIndex(line => line.trim() === '{');
        
        if (jsonStartIndex === -1) {
          throw new Error("Could not find JSON object in output");
        }
        
        // Take all lines from JSON start to end and join them
        const jsonString = lines.slice(jsonStartIndex).join('\n');
        const result = JSON.parse(jsonString);
        
        // Log success/failure
        if (result.success) {
          console.log("✅ Fix workflow completed successfully!");
          console.log(`   PR URL: ${result.pr_url}`);
          console.log(`   Vulnerabilities fixed: ${result.vulnerabilities_fixed}`);
        } else {
          console.error("❌ Fix workflow failed:", result.error);
        }

        return NextResponse.json(result);
      } catch (parseError: any) {
        console.error("❌ Failed to parse Python output");
        console.error("Parse error:", parseError.message);
        console.error("Full stdout:", stdout);
        return NextResponse.json(
          {
            success: false,
            error: `Failed to parse response: ${parseError.message}`,
            step: "parse",
            raw_output: stdout,
          },
          { status: 500 }
        );
      }
    }

    // If no stdout but stderr exists
    if (stderr) {
      console.error("Python script error:", stderr);
      return NextResponse.json(
        {
          success: false,
          error: stderr,
          step: "execution",
        },
        { status: 500 }
      );
    }

    // No output at all
    return NextResponse.json(
      {
        success: false,
        error: "No output from fix workflow",
        step: "execution",
      },
      { status: 500 }
    );
  } catch (error: any) {
    console.error("Fix workflow API error:", error);
    return NextResponse.json(
      {
        success: false,
        error: error.message || "Unknown error occurred",
        step: "api",
      },
      { status: 500 }
    );
  }
}
