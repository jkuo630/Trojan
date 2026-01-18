import { NextRequest, NextResponse } from "next/server";

// Proxy route for frontend to fetch GitHub files with token (keeps token server-side)
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const owner = searchParams.get("owner");
  const repo = searchParams.get("repo");
  const path = searchParams.get("path");
  const branch = searchParams.get("branch") || "main";

  if (!owner || !repo || !path) {
    return NextResponse.json(
      { error: "Missing required parameters: owner, repo, path" },
      { status: 400 }
    );
  }

  const headers: HeadersInit = {};
  
  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  
  try {
    const res = await fetch(url, { headers });
    
    if (!res.ok) {
      // Try 'master' branch if 'main' fails
      if (branch === "main") {
        const masterUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${path}`;
        const resMaster = await fetch(masterUrl, { headers });
        if (resMaster.ok) {
          const text = await resMaster.text();
          return NextResponse.json({ content: text });
        }
      }
      return NextResponse.json(
        { error: `Failed to fetch file: ${res.statusText}` },
        { status: res.status }
      );
    }
    
    const text = await res.text();
    return NextResponse.json({ content: text });
  } catch (error) {
    return NextResponse.json(
      { error: `Error fetching file: ${error instanceof Error ? error.message : "Unknown error"}` },
      { status: 500 }
    );
  }
}
