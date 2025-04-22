#!/usr/bin/env python3
"""
Query NRF Helper

A simplified interface for querying NRF for Network Functions.
This script is designed to better handle natural language queries
and forwards them to the full nrf-query-script.py.

Parameters:
    --nf_type: The type of Network Function to search for (e.g., UDR, PCF, AMF)
    --namespace: The Kubernetes namespace (default: pcf)

Examples:
    # Query for UDR functions
    --nf_type UDR

    # Query for PCF functions in specific namespace
    --nf_type PCF --namespace my-namespace
"""

import argparse
import json
import os
import sys
import subprocess

# Import shared kubectl utilities from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Find the full nrf-query-script.py in the same directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FULL_SCRIPT_PATH = os.path.join(SCRIPT_DIR, "nrf-query-script.py")

# Script metadata - used by the MCP server for tool registration
SCRIPT_METADATA = {
    "description": "Simplified interface for querying NRF for Network Functions",
    "aliases": ["query-nrf", "nrf-query", "find-nf", "get-nf"],
    "common_queries": [
        "query nrf for {nf_type}",
        "find {nf_type} in nrf",
        "search for {nf_type}",
        "get {nf_type} instances",
        "list {nf_type} functions"
    ],
    "parameters": {
        "nf_type": {
            "type": "string",
            "description": "Type of Network Function to search for (e.g., UDR, PCF, AMF)",
            "required": True
        },
        "namespace": {
            "type": "string",
            "description": "Kubernetes namespace to search in (default: pcf)",
            "default": "pcf"
        }
    }
}

def main():
    """
    Parse simplified arguments and forward them to the full nrf-query-script.py.
    
    This script provides a simpler interface specifically for the common case of
    querying NRF for a specific type of Network Function.
    """
    # Check if the --metadata flag is present
    if "--metadata" in sys.argv:
        print(json.dumps(SCRIPT_METADATA))
        return
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="Simplified NRF Query Interface",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--args-file", help="JSON file containing arguments")
    parser.add_argument("--nf_type", help="Type of Network Function to search for (e.g., UDR, PCF, AMF)")
    parser.add_argument("--namespace", default="pcf", help="Kubernetes namespace to search in")
    
    args, _ = parser.parse_known_args()
    
    if args.args_file:
        # Load arguments from file
        with open(args.args_file, 'r') as f:
            arguments = json.load(f)
    else:
        # Get arguments from command line
        args = parser.parse_args()
        arguments = {k: v for k, v in vars(args).items() if v is not None and k != "args_file"}
    
    if "nf_type" not in arguments:
        print("Error: Missing required parameter 'nf_type'")
        return
    
    # Prepare arguments for the full script
    full_args = {
        "action": "discover",
        "nf_type": arguments["nf_type"],
        "namespace": arguments.get("namespace", "pcf")
    }
    
    # Create a temporary file with the arguments
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp:
        json.dump(full_args, temp)
        temp_filename = temp.name
    
    try:
        # Call the full script with the arguments file
        result = subprocess.run(
            [sys.executable, FULL_SCRIPT_PATH, "--args-file", temp_filename],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode != 0:
            print(f"Error executing NRF query: {result.stderr}")
        else:
            print(result.stdout)
    finally:
        os.unlink(temp_filename)

if __name__ == "__main__":
    main() 