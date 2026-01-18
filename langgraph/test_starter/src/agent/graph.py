<<<<<<< HEAD
"""Suspicious File Identifier Agent.

Identifies files and functions that may contain security vulnerabilities
based on file structure and function names.
=======
"""Main graph definition for the security scanning agent.

This module defines the LangGraph state and graph structure, importing
individual agents from separate modules for better organization.
>>>>>>> ec4775d74a727c9454d744f04358018aef183d7a
"""

from __future__ import annotations

<<<<<<< HEAD
import json
import os
from typing import Any, Dict, List

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from typing_extensions import TypedDict
=======
from dotenv import load_dotenv
from langgraph.graph import StateGraph, START, END
from typing_extensions import TypedDict
from typing import Any, Dict, List

from .agents.identify_suspicious import identify_suspicious_files
from .agents.parallel_analyzer import analyze_all_vulnerabilities_parallel
>>>>>>> ec4775d74a727c9454d744f04358018aef183d7a

# Load environment variables from .env file
load_dotenv()


class State(TypedDict):
    """State for the agent."""

    file_structure: List[Dict[str, Any]]
    suspicious_files: List[Dict[str, Any]]
    auth_vulnerabilities: List[Dict[str, Any]]  # Authentication vulnerabilities found
<<<<<<< HEAD


def identify_suspicious_files(state: State) -> Dict[str, Any]:
    """Analyze file structure and identify suspicious files with security risks."""
    # Initialize the LLM with OpenAI
    # Get API key from environment variable (or it will use OPENAI_API_KEY from environment)
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable is required")
    
    # Get model name from env (default: gpt-4o-mini for cost efficiency)
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    model = ChatOpenAI(
        model=model_name,
        temperature=0,
        # No max_tokens limit - uses model's maximum
        # OPENAI_API_KEY is read automatically from environment
    )

    # Prepare the prompt (no truncation - send full file structure)
    file_structure_str = format_file_structure(state["file_structure"])

    # Shorter system prompt to save tokens
    system_prompt = """Security expert analyzing code for vulnerabilities.

Identify suspicious files based on paths/functions. Focus on:
1. Auth (login, auth, session, token)
2. DB queries (sql, execute)
3. User input (form, request)
4. File ops (upload, download)
5. API endpoints (route, handler)
6. Crypto (hash, encrypt)
7. Command exec (exec, shell)

Return JSON array with: file_path, reason, risk_level (high/medium/low), suspicious_functions."""

    # Shorter user prompt to save tokens
    user_prompt = f"""Analyze file structure and identify suspicious files:

{file_structure_str}

Return JSON array. Each entry: file_path, reason, risk_level (high/medium/low), suspicious_functions.

Example: [{{"file_path": "src/auth/login.js", "reason": "Auth logic may lack input sanitization", "risk_level": "high", "suspicious_functions": ["validate"]}}]"""

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ]

    # Get LLM response
    response = model.invoke(messages)

    # Extract content from response
    content = response.content if hasattr(response, "content") else str(response)

    # Parse the response
    suspicious_files = parse_llm_response(content)

    # Stream suspicious files when found (so frontend can start visualization)
    if suspicious_files:
        stream_event = json.dumps({
            "type": "suspicious_files",
            "data": suspicious_files
        })
        print(f"__STREAM__:{stream_event}", flush=True)

    return {"suspicious_files": suspicious_files, "auth_vulnerabilities": []}


def format_file_structure(file_structure: List[Dict[str, Any]]) -> str:
    """Format file structure for LLM input."""
    formatted = []
    
    for file_info in file_structure:
        file_path = "/".join(file_info.get("breadcrumb", [])) or file_info.get("name", "unknown")
        functions = file_info.get("functions", [])
        
        line = f"- {file_path}"
        if functions:
            functions_str = ', '.join(functions)
            line += f"\n  Functions: {functions_str}"
        
        formatted.append(line)
    
    return "\n".join(formatted)


def parse_llm_response(content: str) -> List[Dict[str, Any]]:
    """Parse LLM response to extract suspicious files list."""
    import json
    import re

    # Try to extract JSON from the response
    # Look for JSON array in the content
    json_match = re.search(r'\[.*\]', content, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # Fallback: try to parse the entire content as JSON
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict) and "suspicious_files" in parsed:
            return parsed["suspicious_files"]
    except json.JSONDecodeError:
        pass

    # If parsing fails, return empty list
    return []


def analyze_auth_vulnerabilities(state: State) -> Dict[str, Any]:
    """Authentication specialist agent that analyzes suspicious files for auth vulnerabilities."""
    if not state.get("suspicious_files"):
        return {"auth_vulnerabilities": []}
    
    suspicious_files = state["suspicious_files"]
    file_structure = state.get("file_structure", [])
    
    # Get model
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    model = ChatOpenAI(
        model=model_name,
        temperature=0,
    )
    
    auth_vulnerabilities = []
    
    # Analyze each suspicious file for authentication issues - ONE AT A TIME
    for file_index, suspicious_file in enumerate(suspicious_files):
        file_path = suspicious_file.get("file_path", "")
        risk_level = suspicious_file.get("risk_level", "unknown")
        suspicious_functions = suspicious_file.get("suspicious_functions", [])
        
        # Find corresponding file in file_structure for more context and content
        file_info = None
        file_content = None
        for file in file_structure:
            file_path_from_struct = file.get("path") or "/".join(file.get("breadcrumb", [])) or file.get("name", "")
            if file_path_from_struct == file_path or file_path in file_path_from_struct or file_path_from_struct in file_path:
                file_info = file
                file_content = file.get("content", "")
                break
        
        functions_str = ", ".join(suspicious_functions) if suspicious_functions else "N/A"
        
        # System prompt for authentication specialist
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

        # Build user prompt with file content if available
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

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        
        try:
            response = model.invoke(messages)
            content = response.content if hasattr(response, "content") else str(response)
            
            # Parse vulnerabilities
            vulnerabilities = parse_auth_response(content, file_path)
            auth_vulnerabilities.extend(vulnerabilities)
            
            # NEW FLOW: Send file_analysis_start with ALL vulnerabilities found
            # This tells frontend to visualize this file with these annotations
            file_start_event = json.dumps({
                "type": "file_analysis_start",
                "data": {
                    "file_index": file_index,
                    "file_path": file_path,
                    "file_name": file_path.split("/").pop() if "/" in file_path else file_path,
                    "risk_level": risk_level,
                    "suspicious_functions": suspicious_functions,
                    "vulnerabilities": vulnerabilities  # Send all vulnerabilities at once
                }
            })
            print(f"__STREAM__:{file_start_event}", flush=True)
            
            # Stream event: File analysis complete (frontend can move to next file)
            file_complete_event = json.dumps({
                "type": "file_analysis_complete",
                "data": {
                    "file_index": file_index,
                    "file_path": file_path,
                    "vulnerabilities_found": len(vulnerabilities)
                }
            })
            print(f"__STREAM__:{file_complete_event}", flush=True)
            
        except Exception as e:
            error_msg = json.dumps({
                "type": "error",
                "data": {"message": f"Error analyzing {file_path}: {str(e)}"}
            })
            print(f"__STREAM__:{error_msg}", flush=True)
            # Continue with other files even if one fails
            continue
    
    return {"auth_vulnerabilities": auth_vulnerabilities}


def parse_auth_response(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Parse authentication vulnerability response from LLM."""
    import json
    import re
    
    # Try to extract JSON array from response
    json_match = re.search(r'\[.*\]', content, re.DOTALL)
    if json_match:
        try:
            parsed = json.loads(json_match.group(0))
            if isinstance(parsed, list):
                # Ensure each vulnerability has required fields
                for vuln in parsed:
                    if "location" not in vuln:
                        vuln["location"] = file_path
                    if "line" not in vuln:
                        vuln["line"] = None
                return parsed
        except json.JSONDecodeError:
            pass
    
    # Fallback: try parsing entire content
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass
    
    return []
=======
    injection_vulnerabilities: List[Dict[str, Any]]  # Injection vulnerabilities found
    sensitive_data_vulnerabilities: List[Dict[str, Any]]  # Sensitive data exposure vulnerabilities found
    cryptographic_vulnerabilities: List[Dict[str, Any]]  # Cryptographic failure vulnerabilities found
>>>>>>> ec4775d74a727c9454d744f04358018aef183d7a


# Define the graph
graph = StateGraph(State)
graph.add_node("identify_suspicious_files", identify_suspicious_files)
<<<<<<< HEAD
graph.add_node("analyze_auth_vulnerabilities", analyze_auth_vulnerabilities)

# Flow: START -> identify_suspicious_files -> analyze_auth_vulnerabilities -> END
graph.add_edge(START, "identify_suspicious_files")
graph.add_edge("identify_suspicious_files", "analyze_auth_vulnerabilities")
graph.add_edge("analyze_auth_vulnerabilities", END)
=======
graph.add_node("analyze_all_vulnerabilities_parallel", analyze_all_vulnerabilities_parallel)

# Flow: START -> identify_suspicious_files -> analyze_all_vulnerabilities_parallel (runs auth, injection, sensitive_data & cryptographic in parallel) -> END
graph.add_edge(START, "identify_suspicious_files")
graph.add_edge("identify_suspicious_files", "analyze_all_vulnerabilities_parallel")
graph.add_edge("analyze_all_vulnerabilities_parallel", END)
>>>>>>> ec4775d74a727c9454d744f04358018aef183d7a

graph = graph.compile()
