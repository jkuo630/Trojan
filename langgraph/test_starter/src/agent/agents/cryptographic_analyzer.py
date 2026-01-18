"""Cryptographic failure vulnerability analyzer agent."""
import json
import os
from typing import Any, Dict, List

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from ..utils.parser import parse_auth_response


def analyze_single_file_cryptographic(file_index: int, suspicious_file: Dict[str, Any], file_structure: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze a single file for cryptographic failure vulnerabilities."""
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
    
    system_prompt = """You are a cryptographic failure security specialist. Analyze code files for cryptographic vulnerabilities.

Focus on finding:
1. Weak cryptographic algorithms (MD5, SHA1, DES, RC4, weak random number generators)
2. Deprecated or broken cryptographic libraries (outdated crypto libraries, EOL ciphers)
3. Improper certificate validation (disabled SSL/TLS verification, self-signed certs without validation)
4. Weak key management (short keys, keys derived from weak sources, hardcoded keys)
5. Insufficient entropy for random number generation (weak PRNG, predictable seeds)
6. Insecure cryptographic protocols (TLS 1.0/1.1, SSL, weak cipher suites)
7. Incorrect implementation of cryptographic primitives (ECB mode, improper IV usage, padding oracle)
8. Insecure hash functions (MD5, SHA1 for passwords, missing salt)
9. Missing or weak encryption (unencrypted sensitive data, weak encryption keys)
10. Cryptographic downgrade attacks (protocol downgrade vulnerabilities)
11. Improper key exchange (weak key exchange algorithms, missing forward secrecy)
12. Timing attacks (vulnerable constant-time comparison implementations)

IMPORTANT: You MUST provide the exact line number for each vulnerability found. Analyze the code content carefully and identify the specific line where the cryptographic vulnerability exists.

Return JSON array of vulnerabilities found. Each entry MUST include: line (integer line number, not null), type (string - e.g., "Weak Hash Algorithm", "Insecure SSL/TLS"), severity (high/medium/low), description (string), location (file path)."""

    if file_content:
        user_prompt = f"""Analyze this file for cryptographic failure vulnerabilities:

File Path: {file_path}
Risk Level: {risk_level}
Functions: {functions_str}

File Content:
{file_content}

Analyze this file for cryptographic security issues. Return a JSON array of vulnerabilities found.
You MUST provide the exact line number for each vulnerability by analyzing the code content above.

Example format:
[
  {{
    "line": 42,
    "type": "Weak Hash Algorithm",
    "severity": "high",
    "description": "MD5 hash function used at line 42, which is cryptographically broken and should not be used for security purposes",
    "location": "{file_path}"
  }}
]

If no vulnerabilities found, return empty array []. Be specific about what cryptographic issues you identify and ALWAYS include the line number."""
    else:
        user_prompt = f"""Analyze this file for cryptographic failure vulnerabilities:

File Path: {file_path}
Risk Level: {risk_level}
Functions: {functions_str}

Note: File content not available. Analyze based on file path and functions.

Analyze this file for cryptographic security issues. Return a JSON array of vulnerabilities found.

Example format:
[
  {{
    "line": null,
    "type": "Weak Hash Algorithm",
    "severity": "high",
    "description": "MD5 hash function detected, which is cryptographically broken",
    "location": "{file_path}"
  }}
]

If no vulnerabilities found, return empty array []. Be specific about what cryptographic issues you identify."""

    messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
    response = model.invoke(messages)
    content = response.content if hasattr(response, "content") else str(response)
    vulnerabilities = parse_auth_response(content, file_path)
    
    # Stream vulnerabilities as found
    for vuln in vulnerabilities:
        stream_event = json.dumps({
            "type": "cryptographic_vulnerability",
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
