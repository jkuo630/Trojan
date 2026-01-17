"""Script to run the suspicious file identifier agent from command line.

This script accepts JSON file structure via stdin and outputs suspicious files.
"""

import json
import sys
from agent import graph


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
        
        # Output results as JSON
        suspicious_files = result.get("suspicious_files", [])
        print(json.dumps(suspicious_files, indent=2))
        
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {str(e)}"}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()