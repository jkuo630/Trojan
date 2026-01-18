"""
GitHub API - Security Fix Workflow

Complete workflow for fetching vulnerable files, generating fixes with LLM,
committing changes, and creating pull requests.
"""

import requests
import json
import base64
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
import os

try:
    from openai import OpenAI
except ImportError:
    print("⚠️  OpenAI not installed. Run: pip install openai")
    OpenAI = None


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class FixRequest:
    """Structure for a security fix request."""
    repository: str      # Format: "owner/repo-name"
    file_path: str       # Path to file in repo (e.g., "src/auth/login.py")
    lines: str           # Line range (e.g., "45-52")
    description: str     # Description of the vulnerability
    severity: str        # HIGH, MEDIUM, LOW


@dataclass
class LLMFixResult:
    """Result from LLM fix generation."""
    fixed_content: str       # The complete fixed file content
    pr_title: str           # Pull request title
    pr_description: str     # Pull request description
    changes_summary: str    # Summary of what changed


# ============================================================================
# STEP 1: FETCH VULNERABLE FILE FROM GITHUB
# ============================================================================

def fetch_file_from_github(github_token: str, repo_owner: str, repo_name: str, 
                          file_path: str, branch: str = "main") -> dict:
    """
    Fetch a file from GitHub repository.
    
    Args:
        github_token: GitHub OAuth token or PAT
        repo_owner: Repository owner (e.g., "jkuo630")
        repo_name: Repository name (e.g., "Trojan")
        file_path: Path to file in repo (e.g., "README.md")
        branch: Branch to fetch from (default: "main")
    
    Returns:
        dict with:
            - success: bool
            - content: str (decoded file content)
            - sha: str (file SHA, needed for updates)
            - error: str (if failed)
    """
    print(f"📥 Fetching file: {file_path}...")
    
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file_path}"
    params = {"ref": branch}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        file_data = response.json()
        
        # Decode base64 content
        file_content = base64.b64decode(file_data["content"]).decode('utf-8')
        file_sha = file_data["sha"]
        
        print(f"✅ File fetched.")
        
        return {
            "success": True,
            "content": file_content,
            "sha": file_sha,
            "size": file_data["size"]
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
        print(f"❌ Failed: {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Error: {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }


# ============================================================================
# STEP 2: GENERATE FIX USING LLM (OpenAI)
# ============================================================================

def generate_fix_with_llm(fix_request: FixRequest, file_content: str, 
                         openai_api_key: str) -> dict:
    """
    Use OpenAI to generate a fixed version of the file and PR details.
    
    Args:
        fix_request: FixRequest object with vulnerability details
        file_content: Current file content
        openai_api_key: OpenAI API key
    
    Returns:
        dict with:
            - success: bool
            - fixed_content: str (complete fixed file)
            - pr_title: str
            - pr_description: str
            - changes_summary: str
            - error: str (if failed)
    """
    print(f"🤖 Generating fix with LLM...")
    
    if OpenAI is None:
        return {
            "success": False,
            "error": "OpenAI library not installed"
        }
    
    try:
        client = OpenAI(api_key=openai_api_key)
        
        # Get the problematic lines for context
        lines = file_content.split('\n')
        start_line, end_line = map(int, fix_request.lines.split('-'))
        problem_lines = '\n'.join(lines[start_line-1:end_line])
        
        # Construct the prompt
        prompt = f"""You are a security expert. Fix the following security vulnerability in this file.

## Vulnerability Details
- **File**: {fix_request.file_path}
- **Lines**: {fix_request.lines}
- **Severity**: {fix_request.severity}
- **Issue**: {fix_request.description}
- **Why it matters**: {fix_request.why_it_matters}

## Problematic Code (lines {fix_request.lines}):
```
{problem_lines}
```

## Complete Current File:
```
{file_content}
```

## Your Task:
1. Generate the COMPLETE fixed file with the vulnerability patched
2. Maintain all original formatting and structure
3. Only fix the security issue, don't refactor other code
4. Add a brief comment near the fix explaining what was changed

## Output Format:
Return a JSON object with these fields:
{{
    "fixed_content": "the complete fixed file content",
    "pr_title": "concise PR title (max 80 chars)",
    "pr_description": "detailed PR description in markdown",
    "changes_summary": "bullet points of what changed"
}}

The fixed_content should be the ENTIRE file, ready to replace the original.
"""
        
        response = client.chat.completions.create(
            model="gpt-4o",  # Using gpt-4o which supports JSON mode
            messages=[
                {
                    "role": "system",
                    "content": "You are a security expert who fixes code vulnerabilities. Always return valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            response_format={"type": "json_object"}
        )
        
        result_text = response.choices[0].message.content
        result_json = json.loads(result_text)
        
        print(f"✅ Fix generated.")
        
        return {
            "success": True,
            "fixed_content": result_json["fixed_content"],
            "pr_title": result_json["pr_title"],
            "pr_description": result_json["pr_description"],
            "changes_summary": result_json["changes_summary"]
        }
        
    except json.JSONDecodeError as e:
        error_msg = f"Failed to parse LLM response: {str(e)}"
        print(f"❌ {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }
    except Exception as e:
        error_msg = f"LLM error: {str(e)}"
        print(f"❌ {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }


# ============================================================================
# STEP 3: CREATE BRANCH (Only called after successful LLM fix)
# ============================================================================

def create_branch(github_token, repo_owner, repo_name, new_branch_name, base_branch="main"):
    """
    Create a new branch in a GitHub repository.
    Called ONLY after LLM successfully generates a fix.
    
    Args:
        github_token (str): GitHub personal access token or OAuth token
        repo_owner (str): Repository owner (e.g., "jkuo630")
        repo_name (str): Repository name (e.g., "Trojan")
        new_branch_name (str): Name for the new branch
        base_branch (str): Base branch to create from (default: "main")
    
    Returns:
        dict: Response with success status and branch info
    """
    print(f"🌿 Creating branch: {new_branch_name}...")
    
    # GitHub API base URL
    base_url = "https://api.github.com"
    
    # Set up headers with authentication
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    # Get the SHA of the base branch
    ref_url = f"{base_url}/repos/{repo_owner}/{repo_name}/git/ref/heads/{base_branch}"
    
    try:
        ref_response = requests.get(ref_url, headers=headers)
        ref_response.raise_for_status()
        
        base_sha = ref_response.json()["object"]["sha"]
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {
                "success": False,
                "error": f"Base branch '{base_branch}' not found"
            }
        else:
            return {
                "success": False,
                "error": f"Failed to get base branch: {e.response.status_code}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error getting base branch: {str(e)}"
        }
    
    # Create the new branch
    create_ref_url = f"{base_url}/repos/{repo_owner}/{repo_name}/git/refs"
    
    payload = {
        "ref": f"refs/heads/{new_branch_name}",
        "sha": base_sha
    }
    
    try:
        create_response = requests.post(create_ref_url, headers=headers, json=payload)
        create_response.raise_for_status()
        
        result = create_response.json()
        
        print(f"✅ Branch created.")
        
        return {
            "success": True,
            "branch_name": new_branch_name,
            "sha": base_sha,
            "url": result.get("url"),
            "github_url": f"https://github.com/{repo_owner}/{repo_name}/tree/{new_branch_name}"
        }
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 422:
            return {
                "success": False,
                "error": f"Branch '{new_branch_name}' already exists"
            }
        else:
            return {
                "success": False,
                "error": f"Failed to create branch: {e.response.status_code}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error creating branch: {str(e)}"
        }


# ============================================================================
# STEP 4: COMMIT FIXED FILE TO BRANCH
# ============================================================================

def commit_fixed_file(github_token: str, repo_owner: str, repo_name: str,
                     file_path: str, fixed_content: str, file_sha: str,
                     branch_name: str, commit_message: str) -> dict:
    """
    Commit the fixed file content to the branch.
    
    Args:
        github_token: GitHub OAuth token or PAT
        repo_owner: Repository owner
        repo_name: Repository name
        file_path: Path to file in repo (e.g., "src/login.py")
        fixed_content: The new file content (from LLM)
        file_sha: Current file SHA (from fetch step)
        branch_name: Branch to commit to
        commit_message: Commit message
    
    Returns:
        dict with:
            - success: bool
            - commit_sha: str
            - error: str (if failed)
    """
    print(f"💾 Committing fix...")
    
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Encode content to base64
    encoded_content = base64.b64encode(fixed_content.encode()).decode()
    
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file_path}"
    
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "sha": file_sha,
        "branch": branch_name
    }
    
    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        
        result = response.json()
        commit_sha = result["commit"]["sha"]
        
        print(f"✅ Committed.")
        
        return {
            "success": True,
            "commit_sha": commit_sha,
            "commit_url": result["commit"]["html_url"]
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
        print(f"❌ Failed: {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Error: {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }


# ============================================================================
# STEP 5: CREATE PULL REQUEST
# ============================================================================

def create_pull_request(github_token: str, repo_owner: str, repo_name: str,
                       branch_name: str, base_branch: str, pr_title: str,
                       pr_description: str) -> dict:
    """
    Create a pull request with the fix.
    
    Args:
        github_token: GitHub OAuth token or PAT
        repo_owner: Repository owner
        repo_name: Repository name
        branch_name: Source branch (with the fix)
        base_branch: Target branch (usually "main")
        pr_title: PR title (from LLM)
        pr_description: PR description (from LLM)
    
    Returns:
        dict with:
            - success: bool
            - pr_number: int
            - pr_url: str
            - error: str (if failed)
    """
    print(f"🔃 Creating pull request...")
    
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"
    
    payload = {
        "title": pr_title,
        "head": branch_name,
        "base": base_branch,
        "body": pr_description
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
        result = response.json()
        pr_number = result["number"]
        pr_url = result["html_url"]
        
        print(f"✅ PR created: #{pr_number}")
        
        return {
            "success": True,
            "pr_number": pr_number,
            "pr_url": pr_url
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
        print(f"❌ Failed: {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Error: {error_msg}")
        return {
            "success": False,
            "error": error_msg
        }


# ============================================================================
# COMPLETE WORKFLOW: ORCHESTRATOR FUNCTION
# ============================================================================

def process_security_fix(fix_request: FixRequest, github_token: str, 
                        openai_api_key: str, base_branch: str = "main") -> dict:
    """
    Complete workflow: Fetch file → Generate fix → Create branch → Commit → PR
    
    Args:
        fix_request: FixRequest with vulnerability details
        github_token: GitHub OAuth token
        openai_api_key: OpenAI API key
        base_branch: Base branch (default: "main")
    
    Returns:
        dict with complete results or error
    """
    print(f"\n🚀 Security Fix Workflow")
    print(f"   Repository: {fix_request.repository}")
    print(f"   File: {fix_request.file_path}")
    print(f"   Severity: {fix_request.severity}\n")
    
    # Parse repository
    repo_owner, repo_name = fix_request.repository.split('/')
    
    # STEP 1: Fetch vulnerable file
    fetch_result = fetch_file_from_github(
        github_token=github_token,
        repo_owner=repo_owner,
        repo_name=repo_name,
        file_path=fix_request.file_path,
        branch=base_branch
    )
    
    if not fetch_result["success"]:
        return {"success": False, "step": "fetch", "error": fetch_result["error"]}
    
    file_content = fetch_result["content"]
    file_sha = fetch_result["sha"]
    
    # STEP 2: Generate fix with LLM
    llm_result = generate_fix_with_llm(
        fix_request=fix_request,
        file_content=file_content,
        openai_api_key=openai_api_key
    )
    
    if not llm_result["success"]:
        return {"success": False, "step": "llm", "error": llm_result["error"]}
    
    fixed_content = llm_result["fixed_content"]
    pr_title = llm_result["pr_title"]
    pr_description = llm_result["pr_description"]
    
    # STEP 3: Create branch (only if LLM succeeded)
    branch_name = f"fix/{fix_request.severity.lower()}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    branch_result = create_branch(
        github_token=github_token,
        repo_owner=repo_owner,
        repo_name=repo_name,
        new_branch_name=branch_name,
        base_branch=base_branch
    )
    
    if not branch_result["success"]:
        return {"success": False, "step": "branch", "error": branch_result["error"]}
    
    # STEP 4: Commit fixed file
    commit_result = commit_fixed_file(
        github_token=github_token,
        repo_owner=repo_owner,
        repo_name=repo_name,
        file_path=fix_request.file_path,
        fixed_content=fixed_content,
        file_sha=file_sha,
        branch_name=branch_name,
        commit_message=f"Fix: {fix_request.description}"
    )
    
    if not commit_result["success"]:
        return {"success": False, "step": "commit", "error": commit_result["error"]}
    
    # STEP 5: Create pull request
    pr_result = create_pull_request(
        github_token=github_token,
        repo_owner=repo_owner,
        repo_name=repo_name,
        branch_name=branch_name,
        base_branch=base_branch,
        pr_title=pr_title,
        pr_description=pr_description
    )
    
    if not pr_result["success"]:
        return {"success": False, "step": "pr", "error": pr_result["error"]}
    
    # SUCCESS!
    print(f"\n✅ Workflow completed!")
    print(f"   PR: {pr_result['pr_url']}\n")
    
    return {
        "success": True,
        "branch_name": branch_name,
        "commit_sha": commit_result["commit_sha"],
        "pr_number": pr_result["pr_number"],
        "pr_url": pr_result["pr_url"],
        "pr_title": pr_title
    }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def verify_token(github_token):
    """Verify the GitHub token works and has the necessary permissions."""
    
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        response = requests.get("https://api.github.com/user", headers=headers)
        response.raise_for_status()
        
        user_data = response.json()
        scopes = response.headers.get("X-OAuth-Scopes", "").split(", ")
        
        print("🔐 Token Verification")
        print("=" * 60)
        print(f"✅ Token is valid!")
        print(f"👤 Authenticated as: {user_data.get('login')}")
        print(f"📧 Email: {user_data.get('email', 'N/A')}")
        print(f"🔑 Scopes: {', '.join(scopes)}")
        print(f"🔒 Has 'repo' scope: {'repo' in scopes}")
        print("=" * 60)
        
        if 'repo' not in scopes:
            print("⚠️  WARNING: Token doesn't have 'repo' scope!")
            print("   You need 'repo' scope to create branches.")
            return False
        
        return True
        
    except requests.exceptions.HTTPError as e:
        print(f"❌ Token verification failed: {e.response.status_code}")
        print(f"   {e.response.text}")
        return False