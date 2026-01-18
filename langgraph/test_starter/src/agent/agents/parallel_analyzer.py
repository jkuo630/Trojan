"""Parallel vulnerability analyzer coordinator."""
import json
import threading
from typing import Any, Dict, List

from .auth_analyzer import analyze_single_file_auth
from .injection_analyzer import analyze_single_file_injection
from .sensitive_data_analyzer import analyze_single_file_sensitive_data
from .cryptographic_analyzer import analyze_single_file_cryptographic


def analyze_all_vulnerabilities_parallel(state: Dict[str, Any]) -> Dict[str, Any]:
    """Coordinate parallel execution of auth, injection, sensitive data, and cryptographic vulnerability analysis."""
    if not state.get("suspicious_files"):
        return {"auth_vulnerabilities": [], "injection_vulnerabilities": [], "sensitive_data_vulnerabilities": [], "cryptographic_vulnerabilities": []}
    
    suspicious_files = state["suspicious_files"]
    file_structure = state.get("file_structure", [])
    
    auth_vulnerabilities = []
    injection_vulnerabilities = []
    sensitive_data_vulnerabilities = []
    cryptographic_vulnerabilities = []
    results_lock = threading.Lock()
    
    # Analyze each suspicious file - run auth, injection, and sensitive data analysis in parallel
    for file_index, suspicious_file in enumerate(suspicious_files):
        file_path = suspicious_file.get("file_path", "")
        
        # Thread function for auth analysis
        def analyze_auth_thread(file_idx, sus_file):
            try:
                result = analyze_single_file_auth(file_idx, sus_file, file_structure)
                with results_lock:
                    auth_vulnerabilities.extend(result)
            except Exception as e:
                error_msg = json.dumps({
                    "type": "error",
                    "data": {"message": f"Error in auth analysis for {file_path}: {str(e)}"}
                })
                print(f"__STREAM__:{error_msg}", flush=True)
        
        # Thread function for injection analysis  
        def analyze_injection_thread(file_idx, sus_file):
            try:
                result = analyze_single_file_injection(file_idx, sus_file, file_structure)
                with results_lock:
                    injection_vulnerabilities.extend(result)
            except Exception as e:
                error_msg = json.dumps({
                    "type": "error",
                    "data": {"message": f"Error in injection analysis for {file_path}: {str(e)}"}
                })
                print(f"__STREAM__:{error_msg}", flush=True)
        
        # Thread function for sensitive data analysis
        def analyze_sensitive_data_thread(file_idx, sus_file):
            try:
                result = analyze_single_file_sensitive_data(file_idx, sus_file, file_structure)
                with results_lock:
                    sensitive_data_vulnerabilities.extend(result)
            except Exception as e:
                error_msg = json.dumps({
                    "type": "error",
                    "data": {"message": f"Error in sensitive data analysis for {file_path}: {str(e)}"}
                })
                print(f"__STREAM__:{error_msg}", flush=True)
        
        # Thread function for cryptographic analysis
        def analyze_cryptographic_thread(file_idx, sus_file):
            try:
                result = analyze_single_file_cryptographic(file_idx, sus_file, file_structure)
                with results_lock:
                    cryptographic_vulnerabilities.extend(result)
            except Exception as e:
                error_msg = json.dumps({
                    "type": "error",
                    "data": {"message": f"Error in cryptographic analysis for {file_path}: {str(e)}"}
                })
                print(f"__STREAM__:{error_msg}", flush=True)
        
        # Start all four threads in parallel
        auth_thread = threading.Thread(target=analyze_auth_thread, args=(file_index, suspicious_file))
        injection_thread = threading.Thread(target=analyze_injection_thread, args=(file_index, suspicious_file))
        sensitive_data_thread = threading.Thread(target=analyze_sensitive_data_thread, args=(file_index, suspicious_file))
        cryptographic_thread = threading.Thread(target=analyze_cryptographic_thread, args=(file_index, suspicious_file))
        
        auth_thread.start()
        injection_thread.start()
        sensitive_data_thread.start()
        cryptographic_thread.start()
        
        # Wait for all four to complete before moving to next file
        auth_thread.join()
        injection_thread.join()
        sensitive_data_thread.join()
        cryptographic_thread.join()
        
        # Send combined file_analysis_start event (only once per file)
        # Wait a moment to ensure all agents have streamed their vulnerabilities
        combined_vulns = [v for v in auth_vulnerabilities if v.get("file_index") == file_index] + \
                        [v for v in injection_vulnerabilities if v.get("file_index") == file_index] + \
                        [v for v in sensitive_data_vulnerabilities if v.get("file_index") == file_index] + \
                        [v for v in cryptographic_vulnerabilities if v.get("file_index") == file_index]
        
        risk_level = suspicious_file.get("risk_level", "unknown")
        suspicious_functions = suspicious_file.get("suspicious_functions", [])
        
        file_start_event = json.dumps({
            "type": "file_analysis_start",
            "data": {
                "file_index": file_index,
                "file_path": file_path,
                "file_name": file_path.split("/").pop() if "/" in file_path else file_path,
                "risk_level": risk_level,
                "suspicious_functions": suspicious_functions,
                "vulnerabilities": combined_vulns  # Combined from all agents
            }
        })
        print(f"__STREAM__:{file_start_event}", flush=True)
        
        # Send file_analysis_complete event
        file_complete_event = json.dumps({
            "type": "file_analysis_complete",
            "data": {
                "file_index": file_index,
                "file_path": file_path,
                "vulnerabilities_found": len(combined_vulns)
            }
        })
        print(f"__STREAM__:{file_complete_event}", flush=True)
    
    return {
        "auth_vulnerabilities": auth_vulnerabilities,
        "injection_vulnerabilities": injection_vulnerabilities,
        "sensitive_data_vulnerabilities": sensitive_data_vulnerabilities,
        "cryptographic_vulnerabilities": cryptographic_vulnerabilities
    }
