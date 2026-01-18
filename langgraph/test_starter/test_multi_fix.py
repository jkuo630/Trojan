"""
Test script for multi-vulnerability fix workflow.
Demonstrates how to use process_file_fix_request with FileFixRequest data.
"""

import os
from github_api import FileFixRequest, Vulnerability, process_file_fix_request
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============================================================================
# EXAMPLE: Converting FileAnalysisData from agent to FileFixRequest
# ============================================================================

def create_file_fix_request_from_agent_data(
    agent_data: dict,
    repository: str
) -> FileFixRequest:
    """
    Convert FileAnalysisData from graph.py agent to FileFixRequest.
    
    Args:
        agent_data: The data from agent's file_analysis_start event
        repository: Repository string like "owner/repo"
    
    Returns:
        FileFixRequest object ready for process_file_fix_request()
    """
    # Convert vulnerability dictionaries to Vulnerability objects
    vulnerabilities = [
        Vulnerability(
            line=v.get("line"),
            type=v["type"],
            severity=v["severity"],
            description=v["description"],
            location=v["location"]
        )
        for v in agent_data["vulnerabilities"]
    ]
    
    return FileFixRequest(
        repository=repository,
        file_path=agent_data["file_path"],
        file_name=agent_data["file_name"],
        risk_level=agent_data["risk_level"],
        vulnerabilities=vulnerabilities
    )


# ============================================================================
# EXAMPLE DATA: Simulating what the agent would send
# ============================================================================

# This matches the FileAnalysisData structure from graph.py
EXAMPLE_AGENT_OUTPUT = {
    "file_index": 0,
    "file_path": "frontend/app/auth/login/page.tsx",
    "file_name": "page.tsx",
    "risk_level": "high",
    "suspicious_functions": ["handleLogin"],
    "vulnerabilities": [
        {
            "line": 22,
            "type": "Missing Rate Limiting",
            "severity": "medium",
            "description": "The login form does not implement rate limiting, making it vulnerable to brute force attacks. An attacker could attempt unlimited login attempts.",
            "location": "frontend/app/auth/login/page.tsx"
        },
        {
            "line": 28,
            "type": "No Account Lockout",
            "severity": "medium",
            "description": "Failed login attempts do not trigger account lockout mechanisms. This allows attackers to perform credential stuffing attacks indefinitely.",
            "location": "frontend/app/auth/login/page.tsx"
        },
        {
            "line": 35,
            "type": "Insufficient Error Handling",
            "severity": "low",
            "description": "Generic error messages don't distinguish between invalid email and invalid password, but more detailed logging should be added for security monitoring.",
            "location": "frontend/app/auth/login/page.tsx"
        }
    ]
}


# ============================================================================
# TEST FUNCTION: How frontend would call this
# ============================================================================

def submit_multi_vulnerability_fix(
    agent_data: dict,
    repository: str,
    github_token: str = None,
    openai_api_key: str = None,
    base_branch: str = "main"
) -> dict:
    """
    Submit a multi-vulnerability fix request to the GitHub API.
    This is what your frontend API route would call.
    
    Args:
        agent_data: FileAnalysisData from the agent
        repository: Repository string like "owner/repo"
        github_token: GitHub OAuth token (from frontend)
        openai_api_key: OpenAI API key (from env or frontend)
        base_branch: Base branch (default: "main")
    
    Returns:
        dict with PR details or error
    """
    # Get tokens from environment if not provided
    if not github_token:
        github_token = os.getenv("GITHUB_TOKEN")
    if not openai_api_key:
        openai_api_key = os.getenv("OPENAI_API_KEY")
    
    if not github_token:
        return {"success": False, "error": "GitHub token required"}
    if not openai_api_key:
        return {"success": False, "error": "OpenAI API key required"}
    
    # Convert agent data to FileFixRequest
    file_fix_request = create_file_fix_request_from_agent_data(
        agent_data=agent_data,
        repository=repository
    )
    
    print(f"\n{'='*60}")
    print(f"Processing Multi-Vulnerability Fix Request")
    print(f"{'='*60}")
    print(f"Repository: {repository}")
    print(f"File: {file_fix_request.file_path}")
    print(f"Risk Level: {file_fix_request.risk_level}")
    print(f"Vulnerabilities: {len(file_fix_request.vulnerabilities)}")
    for idx, vuln in enumerate(file_fix_request.vulnerabilities, 1):
        print(f"  {idx}. {vuln.type} ({vuln.severity})")
    print(f"{'='*60}\n")
    
    # Process the fix
    result = process_file_fix_request(
        file_fix_request=file_fix_request,
        github_token=github_token,
        openai_api_key=openai_api_key,
        base_branch=base_branch
    )
    
    return result


# ============================================================================
# MAIN: Run test
# ============================================================================

def main():
    """Test the multi-vulnerability fix workflow."""
    
    # Simulate data coming from frontend
    # In real app, this would come from the agent's file_analysis_start event
    agent_data = EXAMPLE_AGENT_OUTPUT
    repository = "jkuo630/Trojan"  # This would be provided by frontend
    
    # Submit the fix request
    result = submit_multi_vulnerability_fix(
        agent_data=agent_data,
        repository=repository,
        base_branch="main"
    )
    
    # Display results
    print("\n" + "="*60)
    print("RESULT")
    print("="*60)
    
    if result["success"]:
        print("✅ SUCCESS!")
        print(f"\n📊 Summary:")
        print(f"   - Vulnerabilities Fixed: {result['vulnerabilities_fixed']}")
        print(f"   - Branch: {result['branch_name']}")
        print(f"   - PR Number: #{result['pr_number']}")
        print(f"   - PR Title: {result['pr_title']}")
        print(f"\n🔗 Pull Request URL:")
        print(f"   {result['pr_url']}")
    else:
        print("❌ FAILED")
        print(f"\n⚠️  Error Details:")
        print(f"   - Step: {result.get('step', 'unknown')}")
        print(f"   - Error: {result.get('error', 'unknown error')}")
    
    print("="*60 + "\n")
    
    return result


if __name__ == "__main__":
    main()
