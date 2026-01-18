"""Sensitive data exposure vulnerability analyzer agent."""
import json
import os
from typing import Any, Dict, List

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from ..utils.parser import parse_auth_response


def analyze_single_file_sensitive_data(file_index: int, suspicious_file: Dict[str, Any], file_structure: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze a single file for sensitive data exposure vulnerabilities."""
    file_path = suspicious_file.get("file_path", "")
    risk_level = suspicious_file.get("risk_level", "unknown")
    suspicious_functions = suspicious_file.get("suspicious_functions", [])
    
    # Find file content
    file_content = None
    for file in file_structure:
        file_path_from_struct = file.get("path") or "/".join(file.get("breadcrumb", [])) or file.get("name", "")
        if file_path_from_struct == file_path or file_path in file_path_from_struct or file_path_from_struct in file_path:
            file_content = file.get("content", "")
            break
    
    functions_str = ", ".join(suspicious_functions) if suspicious_functions else "N/A"
    
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    model = ChatOpenAI(model=model_name, temperature=0)
    
    system_prompt = """You are a sensitive data exposure security specialist. Analyze code files for sensitive data exposure vulnerabilities.

Focus on finding:
1. Hardcoded secrets (API keys, passwords, tokens, credentials in plaintext)
2. Exposed credentials (database passwords, AWS keys, GitHub tokens, OAuth secrets)
3. Hardcoded encryption keys or private keys
4. PII (Personally Identifiable Information) exposure without encryption
5. Logging of sensitive data (passwords, credit cards, SSNs in logs)
6. Unencrypted sensitive data storage (passwords in plaintext, unencrypted databases)
7. Weak or missing encryption for sensitive data at rest or in transit
8. Exposed environment variables or configuration files with secrets
9. Sensitive data in error messages or stack traces
10. Backup files containing sensitive information
11. Credentials in code comments or documentation

IMPORTANT: You MUST provide the exact line number for each vulnerability found. Analyze the code content carefully and identify the specific line where the sensitive data is exposed.

Return JSON array of vulnerabilities found. Each entry MUST include: line (integer line number, not null), type (string - e.g., "Hardcoded API Key", "Plaintext Password"), severity (high/medium/low), description (string), location (file path)."""

    if file_content:
        user_prompt = f"""Analyze this file for sensitive data exposure vulnerabilities:

File Path: {file_path}
Risk Level: {risk_level}
Functions: {functions_str}

File Content:
{file_content}

Analyze this file for sensitive data exposure issues. Return a JSON array of vulnerabilities found.
You MUST provide the exact line number for each vulnerability by analyzing the code content above.

Example format:
[
  {{
    "line": 42,
    "type": "Hardcoded API Key",
    "severity": "high",
    "description": "API key hardcoded in source code at line 42: 'sk_live_1234567890abcdef'",
    "location": "{file_path}"
  }},
  {{
    "line": 89,
    "type": "Plaintext Password",
    "severity": "high",
    "description": "Database password stored in plaintext variable at line 89",
    "location": "{file_path}"
  }},
  {{
    "line": 156,
    "type": "Sensitive Data in Logs",
    "severity": "medium",
    "description": "Credit card number logged in console.log at line 156",
    "location": "{file_path}"
  }}
]

If no vulnerabilities found, return empty array []. Be specific about what sensitive data is exposed and ALWAYS include the line number."""
    else:
        user_prompt = f"""Analyze this file for sensitive data exposure vulnerabilities:

File Path: {file_path}
Risk Level: {risk_level}
Functions: {functions_str}

Note: File content not available. Analyze based on file path and functions.

Analyze this file for sensitive data exposure issues. Return a JSON array of vulnerabilities found.

Example format:
[
  {{
    "line": null,
    "type": "Potential Secret Exposure",
    "severity": "medium",
    "description": "File path suggests potential configuration file containing secrets",
    "location": "{file_path}"
  }}
]

If no vulnerabilities found, return empty array []. Be specific about what sensitive data issues you identify."""

    messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
    response = model.invoke(messages)
    content = response.content if hasattr(response, "content") else str(response)
    vulnerabilities = parse_auth_response(content, file_path)  # Reuse parser - same format
    
    # Stream vulnerabilities as found
    for vuln in vulnerabilities:
        stream_event = json.dumps({
            "type": "sensitive_data_vulnerability",
            "data": {
                **vuln,
                "file_index": file_index,
                "file_path": file_path
            }
        })
        print(f"__STREAM__:{stream_event}", flush=True)
    
    # Add file_index to each vulnerability
    for vuln in vulnerabilities:
        vuln["file_index"] = file_index
    
    return vulnerabilities
