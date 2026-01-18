"""Main graph definition for the security scanning agent.

This module defines the LangGraph state and graph structure, importing
individual agents from separate modules for better organization.
"""

from __future__ import annotations

from dotenv import load_dotenv
from langgraph.graph import StateGraph, START, END
from typing_extensions import TypedDict
from typing import Any, Dict, List

from .agents.identify_suspicious import identify_suspicious_files
from .agents.parallel_analyzer import analyze_all_vulnerabilities_parallel

# Load environment variables from .env file
load_dotenv()


class State(TypedDict):
    """State for the agent."""

    file_structure: List[Dict[str, Any]]
    suspicious_files: List[Dict[str, Any]]
    auth_vulnerabilities: List[Dict[str, Any]]  # Authentication vulnerabilities found
    injection_vulnerabilities: List[Dict[str, Any]]  # Injection vulnerabilities found
    sensitive_data_vulnerabilities: List[Dict[str, Any]]  # Sensitive data exposure vulnerabilities found


# Define the graph
graph = StateGraph(State)
graph.add_node("identify_suspicious_files", identify_suspicious_files)
graph.add_node("analyze_all_vulnerabilities_parallel", analyze_all_vulnerabilities_parallel)

# Flow: START -> identify_suspicious_files -> analyze_all_vulnerabilities_parallel (runs auth, injection & sensitive_data in parallel) -> END
graph.add_edge(START, "identify_suspicious_files")
graph.add_edge("identify_suspicious_files", "analyze_all_vulnerabilities_parallel")
graph.add_edge("analyze_all_vulnerabilities_parallel", END)

graph = graph.compile()
