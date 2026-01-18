"""Suspicious File Identifier Agent.

Identifies files and functions that may contain security vulnerabilities
based on file structure and function names.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
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

    return {"suspicious_files": suspicious_files}


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


# Define the graph
graph = StateGraph(State)
graph.add_node("identify_suspicious_files", identify_suspicious_files)
graph.add_edge(START, "identify_suspicious_files")
graph.add_edge("identify_suspicious_files", END)
graph = graph.compile()
