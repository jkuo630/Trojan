"""Authentication vulnerability analyzer agent."""
import json
import os
from typing import Any, Dict, List

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from ..utils.parser import parse_auth_response


def analyze_single_file_auth(file_index: int, suspicious_file: Dict[str, Any], file_structure: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze a single file for auth vulnerabilities."""
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
    
    system_prompt = """You are an authentication security specialist. Analyze code files for authentication vulnerabilities.

Focus on finding:
1. Weak password policies (no complexity requirements, short passwords)
2. Missing authentication checks (public endpoints without auth)
3. Session management flaws (weak tokens, no expiration, insecure storage)
4. Credential handling issues (plaintext passwords, weak hashing)
5. Authentication bypass (token manipulation, privilege escalation)
6. Broken access control (IDOR, missing authorization checks)
7. OAuth/JWT misconfigurations

IMPORTANT: You MUST provide the exact line number for each vulnerability found. Analyze the code content carefully and identify the specific line where the vulnerability exists.

Return JSON array of vulnerabilities found. Each entry MUST include: line (integer line number, not null), type (string), severity (high/medium/low), description (string), location (file path)."""

    if file_content:
        user_prompt = f"""Analyze this file for authentication vulnerabilities:

File Path: {file_path}
Risk Level: {risk_level}
Functions: {functions_str}

File Content:
{file_content}

Analyze this file for authentication security issues. Return a JSON array of vulnerabilities found.
You MUST provide the exact line number for each vulnerability by analyzing the code content above.

Example format:
[
  {{
    "line": 42,
    "type": "Weak Password Policy",
    "severity": "medium",
    "description": "No password complexity requirements detected in authentication logic at line 42",
    "location": "{file_path}"
  }}
]

If no vulnerabilities found, return empty array []. Be specific about what authentication issues you identify and ALWAYS include the line number."""
    else:
        user_prompt = f"""Analyze this file for authentication vulnerabilities:

File Path: {file_path}
Risk Level: {risk_level}
Functions: {functions_str}

Note: File content not available. Analyze based on file path and functions.

Analyze this file for authentication security issues. Return a JSON array of vulnerabilities found.

Example format:
[
  {{
    "line": null,
    "type": "Weak Password Policy",
    "severity": "medium",
    "description": "No password complexity requirements detected in authentication logic",
    "location": "{file_path}"
  }}
]

If no vulnerabilities found, return empty array []. Be specific about what authentication issues you identify."""

    messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
    response = model.invoke(messages)
    content = response.content if hasattr(response, "content") else str(response)
    vulnerabilities = parse_auth_response(content, file_path)
    
    # Stream vulnerabilities as found
    for vuln in vulnerabilities:
        stream_event = json.dumps({
            "type": "auth_vulnerability",
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
