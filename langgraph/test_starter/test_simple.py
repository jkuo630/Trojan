"""Simple test script to run the suspicious file identifier agent."""

from agent import graph

# Sample file structure (same format as /api/analyze returns)
file_structure = [
    {
        "name": "login.js",
        "breadcrumb": ["src", "auth", "login.js"],
        "functions": ["login", "validate", "authenticate"]
    },
    {
        "name": "database.js",
        "breadcrumb": ["src", "db", "database.js"],
        "functions": ["query", "execute", "getUser"]
    },
    {
        "name": "upload.js",
        "breadcrumb": ["src", "upload", "upload.js"],
        "functions": ["uploadFile", "saveFile", "processFile"]
    },
]

if __name__ == "__main__":
    print("Testing suspicious file identifier agent...")
    print(f"Input: {len(file_structure)} files\n")

    # Invoke the graph
    inputs = {
        "file_structure": file_structure,
        "suspicious_files": []
    }

    result = graph.invoke(inputs)

    # Print results
    print(f"Found {len(result.get('suspicious_files', []))} suspicious files:\n")

    for file_info in result.get("suspicious_files", []):
        print(f"📁 {file_info.get('file_path')}")
        print(f"   Risk Level: {file_info.get('risk_level')}")
        print(f"   Reason: {file_info.get('reason')}")
        print(f"   Suspicious Functions: {file_info.get('suspicious_functions')}")
        print()
