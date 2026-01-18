"""Script to run the suspicious file identifier agent from command line.

This script accepts JSON file structure via stdin and outputs suspicious files.
"""

import json
import sys
from agent import graph

# Try to import OpenAI errors for better error handling
try:
    from openai import RateLimitError, APIError
except ImportError:
    RateLimitError = None
    APIError = None


def main():
    """Read file structure from stdin and run the agent."""
    try:
        # Read JSON from stdin
        input_data = sys.stdin.read()
        file_structure = json.loads(input_data)
        
        # Prepare state for the graph
        inputs = {
            "file_structure": file_structure,
            "suspicious_files": []
        }
        
        # Run the graph
        result = graph.invoke(inputs)
        
        # Output results as JSON (both suspicious_files and auth_vulnerabilities)
        output = {
            "suspicious_files": result.get("suspicious_files", []),
            "auth_vulnerabilities": result.get("auth_vulnerabilities", [])
        }
        print(json.dumps(output, indent=2))
        
    except json.JSONDecodeError as e:
        error_msg = json.dumps({"error": f"Invalid JSON: {str(e)}"})
        print(error_msg, file=sys.stderr)
        # Also print to stdout so the API can catch it
        print(error_msg)
        sys.exit(1)
    except Exception as e:
        # Check for OpenAI quota/rate limit errors specifically
        error_str = str(e)
        error_type_name = type(e).__name__
        
        # Handle OpenAI RateLimitError or insufficient_quota
        if RateLimitError and isinstance(e, RateLimitError):
            error_msg = json.dumps({
                "error": "OpenAI API quota exceeded. Please check your OpenAI API billing/quota at https://platform.openai.com/account/billing",
                "error_type": "quota_exceeded"
            })
        elif "insufficient_quota" in error_str.lower() or "quota" in error_str.lower() or "rate_limit" in error_str.lower() or "429" in error_str:
            error_msg = json.dumps({
                "error": "API quota exceeded or rate limit hit. Please check your OpenAI API quota/billing or try again later.",
                "error_type": "quota_exceeded"
            })
        else:
            # Include error type in message for debugging
            error_msg = json.dumps({
                "error": error_str,
                "error_type": "api_error",
                "exception_type": error_type_name
            })
        
        print(error_msg, file=sys.stderr)
        # Also print to stdout so the API can catch it
        print(error_msg)
        sys.exit(1)


if __name__ == "__main__":
    main()