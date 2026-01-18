"""Parser utilities for vulnerability detection."""
import json
import re
from typing import Any, Dict, List


def parse_llm_response(content: str) -> List[Dict[str, Any]]:
    """Parse LLM response to extract suspicious files list."""
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


def parse_auth_response(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Parse authentication vulnerability response from LLM."""
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
