"""Suspicious File Identifier Agent.

Identifies files and functions that may contain security vulnerabilities
based on file structure and function names.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END
from typing_extensions import TypedDict

# Load environment variables from .env file
load_dotenv()


class State(TypedDict):
    """State for the agent."""

    file_structure: List[Dict[str, Any]]
    suspicious_files: List[Dict[str, Any]]


def identify_suspicious_files(state: State) -> Dict[str, Any]:
    """Analyze file structure and identify suspicious files with security risks."""
    # Initialize the LLM with Gemini
    # Get API key from environment variable
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError("GOOGLE_API_KEY environment variable is required")
    
    model = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0,
        google_api_key=api_key,
    )

    # Prepare the prompt
    file_structure_str = format_file_structure(state["file_structure"])

    system_prompt = """You are a security expert analyzing codebases for potential security vulnerabilities.

Your task is to identify suspicious files and functions that may contain security issues based on:
- File paths and names
- Function names
- File structure context

Focus on files that might contain:
1. Authentication/authorization logic (login, auth, session, token)
2. Database queries (query, db, sql, execute)
3. User input handling (input, form, request, user_data)
4. File operations (upload, download, file, save)
5. API endpoints (route, handler, controller, api)
6. Validation logic (validate, sanitize, escape)
7. Crypto/encryption operations (hash, encrypt, decrypt, sign)
8. Command execution (exec, system, shell, command)

For each suspicious file, provide:
- file_path: The full path or breadcrumb
- reason: Why this file is suspicious
- risk_level: "high", "medium", or "low"
- suspicious_functions: List of function names that are particularly concerning

Return your analysis as a JSON-serializable list of dictionaries.
Be specific about why each file is suspicious."""

    user_prompt = f"""Analyze the following file structure and identify suspicious files that may contain security vulnerabilities:

{file_structure_str}

Return a JSON array of suspicious files. Each entry should have:
- file_path: string (join breadcrumb with "/" if available, or use name)
- reason: string (explanation of why it's suspicious)
- risk_level: string ("high", "medium", or "low")
- suspicious_functions: array of strings (function names that are concerning)

Example format:
[
  {{
    "file_path": "src/auth/login.js",
    "reason": "Contains authentication logic with functions like 'validate' and 'authenticate' that may not properly sanitize input",
    "risk_level": "high",
    "suspicious_functions": ["validate", "authenticate"]
  }}
]"""

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

    return {"suspicious_files": suspicious_files}


def format_file_structure(file_structure: List[Dict[str, Any]]) -> str:
    """Format file structure for LLM input."""
    formatted = []
    for file_info in file_structure:
        file_path = "/".join(file_info.get("breadcrumb", [])) or file_info.get("name", "unknown")
        functions = file_info.get("functions", [])
        formatted.append(f"- {file_path}")
        if functions:
            formatted.append(f"  Functions: {', '.join(functions)}")
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


# Define the graph
graph = StateGraph(State)
graph.add_node("identify_suspicious_files", identify_suspicious_files)
graph.add_edge(START, "identify_suspicious_files")
graph.add_edge("identify_suspicious_files", END)
graph = graph.compile()
