"""Script to fix vulnerabilities using the GitHub API workflow.

This script accepts a fix request via stdin and outputs the result.
Expected input format:
{
  "file_fix_request": {
    "repository": "owner/repo",
    "file_path": "path/to/file.js",
    "file_name": "file.js",
    "risk_level": "high",
    "vulnerabilities": [...]
  },
  "github_token": "token",
  "base_branch": "main" (optional)
}
"""

import json
import sys
import os
from dotenv import load_dotenv
from github_api import FileFixRequest, Vulnerability, process_file_fix_request

# Load environment variables from .env file
load_dotenv()


def main():
    """Read fix request from stdin and execute the fix workflow."""
    try:
        # Read JSON from stdin
        input_data = sys.stdin.read()
        request_data = json.loads(input_data)
        
        # Extract parameters
        file_fix_data = request_data.get("file_fix_request", {})
        github_token = request_data.get("github_token")
        openai_api_key = os.getenv("OPENAI_API_KEY")
        base_branch = request_data.get("base_branch", "main")
        
        # Validate required fields
        if not github_token:
            raise ValueError("github_token is required")
        
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set in backend")
        
        # Convert vulnerabilities to Vulnerability objects
        vulnerabilities = [
            Vulnerability(
                line=v.get("line"),
                type=v.get("type", "Unknown"),
                severity=v.get("severity", "medium"),
                description=v.get("description", ""),
                location=v.get("location", "")
            )
            for v in file_fix_data.get("vulnerabilities", [])
        ]
        
        # Create FileFixRequest object
        file_fix_request = FileFixRequest(
            repository=file_fix_data.get("repository"),
            file_path=file_fix_data.get("file_path"),
            file_name=file_fix_data.get("file_name"),
            risk_level=file_fix_data.get("risk_level", "medium"),
            vulnerabilities=vulnerabilities
        )
        
        # Execute the fix workflow
        result = process_file_fix_request(
            file_fix_request=file_fix_request,
            github_token=github_token,
            openai_api_key=openai_api_key,
            base_branch=base_branch
        )
        
        # Output result as JSON
        print(json.dumps(result, indent=2))
        
    except json.JSONDecodeError as e:
        error_msg = {"success": False, "error": f"Invalid JSON: {str(e)}", "step": "parse"}
        print(json.dumps(error_msg), file=sys.stderr)
        print(json.dumps(error_msg))
        sys.exit(1)
    except ValueError as e:
        error_msg = {"success": False, "error": str(e), "step": "validation"}
        print(json.dumps(error_msg), file=sys.stderr)
        print(json.dumps(error_msg))
        sys.exit(1)
    except Exception as e:
        error_msg = {
            "success": False,
            "error": str(e),
            "step": "execution",
            "exception_type": type(e).__name__
        }
        print(json.dumps(error_msg), file=sys.stderr)
        print(json.dumps(error_msg))
        sys.exit(1)


if __name__ == "__main__":
    main()
