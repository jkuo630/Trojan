import pytest

from agent import graph


@pytest.mark.langsmith
def test_identify_suspicious_files() -> None:
    """Test that the agent identifies suspicious files."""
    file_structure = [
        {
            "name": "login.js",
            "breadcrumb": ["src", "auth", "login.js"],
            "functions": ["login", "validate", "authenticate"]
        },
        {
            "name": "database.js",
            "breadcrumb": ["src", "db", "database.js"],
            "functions": ["query", "execute"]
        },
    ]
    
    inputs = {
        "file_structure": file_structure,
        "suspicious_files": []
    }
    
    result = graph.invoke(inputs)
    
    assert result is not None
    assert "suspicious_files" in result
    assert isinstance(result["suspicious_files"], list)
