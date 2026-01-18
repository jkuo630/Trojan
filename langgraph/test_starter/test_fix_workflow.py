#!/usr/bin/env python3
"""
Security Fix Request Handler

This module provides a function to process security fix requests.
Call submit_fix_request() with a FixRequest to automatically create a PR.
"""

from github_api import FixRequest, process_security_fix
import os
import sys


def submit_fix_request(fix_request: FixRequest, github_token: str = None, 
                       openai_api_key: str = None, base_branch: str = "main") -> dict:
    """
    Submit a security fix request and create a PR automatically.
    
    Args:
        fix_request: FixRequest object with vulnerability details
        github_token: GitHub OAuth token (defaults to env variable)
        openai_api_key: OpenAI API key (defaults to env variable)
        base_branch: Base branch to create PR against (default: "main")
    
    Returns:
        dict with:
            - success: bool
            - pr_url: str (if successful)
            - pr_number: int (if successful)
            - pr_title: str (if successful)
            - branch_name: str (if successful)
            - error: str (if failed)
            - step: str (which step failed, if applicable)
    
    Example:
        >>> fix_request = FixRequest(
        ...     repository="owner/repo",
        ...     file_path="src/file.py",
        ...     lines="10-20",
        ...     description="SQL injection vulnerability",
        ...     severity="HIGH",
        ...     why_it_matters="Allows unauthorized database access"
        ... )
        >>> result = submit_fix_request(fix_request)
        >>> print(result['pr_url'])
    """
    # Get tokens from parameters or environment
    github_token = github_token or os.getenv("GITHUB_TOKEN")
    openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
    
    # Validate tokens
    if not github_token:
        return {
            "success": False,
            "error": "GitHub token not provided. Set GITHUB_TOKEN environment variable or pass as parameter.",
            "step": "validation"
        }
    
    if not openai_api_key:
        return {
            "success": False,
            "error": "OpenAI API key not provided. Set OPENAI_API_KEY environment variable or pass as parameter.",
            "step": "validation"
        }
    
    # Process the fix request
    result = process_security_fix(
        fix_request=fix_request,
        github_token=github_token,
        openai_api_key=openai_api_key,
        base_branch=base_branch
    )
    
    return result


# ============================================================================
# EXAMPLE INPUT DATA
# ============================================================================

# Example 1: Rate Limiting Vulnerability
EXAMPLE_RATE_LIMITING = FixRequest(
    repository="jkuo630/Trojan",
    file_path="frontend/app/auth/login/page.tsx",
    lines="22-34",
    description="Missing rate limiting on login form - vulnerable to brute force attacks",
    severity="MEDIUM",
)

# ============================================================================
# CLI INTERFACE (for testing)
# ============================================================================

def main():
    """Command-line interface for testing."""
    print("Security Fix Request Handler")
    print("="*70)
    
    # Use the example fix request
    fix_request = EXAMPLE_RATE_LIMITING
    
    print(f"\n📋 Submitting fix request:")
    print(f"   Repository: {fix_request.repository}")
    print(f"   File: {fix_request.file_path}")
    print(f"   Issue: {fix_request.description}")
    print(f"   Severity: {fix_request.severity}")
    
    # Submit the request
    result = submit_fix_request(fix_request)
    
    # Display results
    print("\n" + "="*70)
    print("RESULT")
    print("="*70)
    
    if result["success"]:
        print("SUCCESS! Security fix PR created.")
        print(f"\nBranch: {result['branch_name']}")
        print(f"📝 Commit: {result['commit_sha'][:10]}...")
        print(f"PR #{result['pr_number']}")
        print(f"📋 Title: {result['pr_title']}")
        print(f"\nView PR: {result['pr_url']}")
        print("\n💡 Next steps:")
        print("   1. Review the PR on GitHub")
        print("   2. Check the code changes")
        print("   3. Merge if everything looks good!")
    else:
        print(f"FAILED at step: {result.get('step', 'unknown')}")
        print(f"   Error: {result['error']}")
        print("\n💡 Troubleshooting:")
        print("   - Ensure GITHUB_TOKEN and OPENAI_API_KEY are set")
        print("   - Verify you have write access to the repository")
        print("   - Check that the file path exists")
    
    print("="*70)


if __name__ == "__main__":
    main()
