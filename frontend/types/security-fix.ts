/**
 * Type definitions for security vulnerability fixes.
 * These match the Python data structures in github_api.py
 */

// ============================================================================
// Data types from agent (graph.py output)
// ============================================================================

export type RiskLevel = "high" | "medium" | "low";
export type Severity = "high" | "medium" | "low";

export interface Vulnerability {
  line: number | null;       // Line number of vulnerability
  type: string;              // e.g., "Weak Password Policy"
  severity: Severity;        // Severity level
  description: string;       // Detailed explanation
  location: string;          // File path
}

export interface FileAnalysisData {
  file_index: number;          // Index in suspicious files array
  file_path: string;           // e.g., "src/auth/login.js"
  file_name: string;           // Just the filename
  risk_level: RiskLevel;       // Overall file risk
  suspicious_functions: string[];  // Function names
  vulnerabilities: Vulnerability[];  // ALL vulnerabilities in file
}

// ============================================================================
// Request/Response types for API calls
// ============================================================================

/**
 * Request payload to submit a multi-vulnerability fix.
 * Send this to your backend API route.
 */
export interface SubmitFixRequest {
  // Agent data + repository info
  file_fix_request: {
    repository: string;        // e.g., "owner/repo"
    file_path: string;
    file_name: string;
    risk_level: RiskLevel;
    vulnerabilities: Vulnerability[];
  };
  // Authentication
  github_token: string;        // From OAuth
  base_branch?: string;        // Optional, defaults to "main"
}

/**
 * Response from the fix submission API.
 */
export interface FixResponse {
  success: boolean;
  // Success fields
  vulnerabilities_fixed?: number;
  branch_name?: string;
  commit_sha?: string;
  pr_number?: number;
  pr_url?: string;
  pr_title?: string;
  // Error fields
  step?: string;
  error?: string;
}

// ============================================================================
// Helper function types
// ============================================================================

/**
 * Convert agent FileAnalysisData to the format needed for API call.
 */
export function createFixRequest(
  agentData: FileAnalysisData,
  repository: string,
  githubToken: string
): SubmitFixRequest {
  return {
    file_fix_request: {
      repository,
      file_path: agentData.file_path,
      file_name: agentData.file_name,
      risk_level: agentData.risk_level,
      vulnerabilities: agentData.vulnerabilities,
    },
    github_token: githubToken,
  };
}

/**
 * Submit a fix request to your backend API.
 * 
 * @example
 * ```ts
 * const result = await submitFixToBackend(
 *   fileAnalysisData,
 *   "owner/repo",
 *   githubToken
 * );
 * 
 * if (result.success) {
 *   console.log("PR created:", result.pr_url);
 * }
 * ```
 */
export async function submitFixToBackend(
  agentData: FileAnalysisData,
  repository: string,
  githubToken: string
): Promise<FixResponse> {
  const payload = createFixRequest(agentData, repository, githubToken);
  
  const response = await fetch('/api/fix-vulnerabilities', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }
  
  return response.json();
}
