#!/usr/bin/env python3
"""
NRF Endpoints Tool

A specialized tool for finding NRF (Network Repository Function) endpoints
in a 5G core network's Kubernetes environment.

This script:
1. Finds NRF endpoints from a specified ConfigMap in the given namespace
2. Lists both discovery and management endpoints

Parameters:
    --namespace: Kubernetes namespace where to find the ConfigMap (default: pcf)
    --configmap: Name of the ConfigMap containing NRF endpoints (default: registration-discovery-configmap)

Examples:
    # Find NRF endpoints in default namespace (pcf)
    python3 nrf-endpoints.py
    
    # Find NRF endpoints in a specific namespace with a different ConfigMap
    python3 nrf-endpoints.py --namespace core --configmap nrf-config
"""

import argparse
import json
import os
import sys
import logging
from typing import Dict, List

# Import the base class from nrf_tools
from nrf_tools import NrfToolBase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("nrf-endpoints")

# Script metadata - used by the MCP server for tool registration
SCRIPT_METADATA = {
    "description": "List NRF (Network Repository Function) endpoints from ConfigMap",
    "aliases": ["get-nrf-endpoints", "find-nrf-endpoints", "list-nrf-endpoints", "show-nrf-urls"],
    "common_queries": [
        "get nrf endpoints",
        "find nrf endpoints",
        "list available nrf endpoints",
        "show nrf endpoints in {namespace}",
        "what nrf endpoints are available",
        "where is nrf located",
        "display nrf urls"
    ],
    "parameters": {
        "namespace": {
            "type": "string",
            "description": "Kubernetes namespace where to find the ConfigMap",
            "default": "pcf"
        },
        "configmap": {
            "type": "string",
            "description": "Name of the ConfigMap containing NRF endpoints",
            "default": "registration-discovery-configmap"
        }
    }
}

class NrfEndpointsTool(NrfToolBase):
    """Tool for listing NRF endpoints"""
    
    def __init__(self, namespace="pcf", configmap="registration-discovery-configmap"):
        """
        Initialize the NRF endpoints tool.
        
        Args:
            namespace: Kubernetes namespace where to find the ConfigMap
            configmap: Name of the ConfigMap containing NRF endpoints
        """
        super().__init__(namespace, configmap)
    
    def list_endpoints(self) -> str:
        """
        List all NRF endpoints from the ConfigMap.
        
        Returns:
            Formatted string with the endpoints information
        """
        endpoints = self.get_nrf_endpoints()
        return self.format_endpoints(endpoints)
    
    def format_endpoints(self, endpoints: Dict[str, List[str]]) -> str:
        """
        Format the endpoints dictionary into a readable string.
        
        Args:
            endpoints: Dictionary of endpoint types and their URLs
            
        Returns:
            Formatted string representation
        """
        output = []
        
        # Add discovery endpoints
        output.append("Discovery Endpoints (nnrf-disc):")
        if endpoints.get("discovery"):
            for idx, endpoint in enumerate(endpoints["discovery"], 1):
                output.append(f"{idx}. {endpoint}")
        else:
            output.append("  No discovery endpoints found")
        
        # Add management endpoints
        output.append("\nManagement Endpoints (nnrf-nfm):")
        if endpoints.get("management"):
            for idx, endpoint in enumerate(endpoints["management"], 1):
                output.append(f"{idx}. {endpoint}")
        else:
            output.append("  No management endpoints found")
        
        return "\n".join(output)

def main():
    """
    Main function to parse arguments and list NRF endpoints.
    """
    # Check if the --metadata flag is present
    if "--metadata" in sys.argv:
        print(json.dumps(SCRIPT_METADATA))
        return
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="List NRF endpoints from ConfigMap",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("--args-file", help="JSON file containing arguments")
    parser.add_argument("--namespace", default="pcf", help="Kubernetes namespace")
    parser.add_argument("--configmap", default="registration-discovery-configmap", help="ConfigMap name containing NRF endpoints")
    
    # Parse known args to get the args-file parameter if present
    args, _ = parser.parse_known_args()
    
    # If args-file is provided, load arguments from it
    if args.args_file:
        try:
            with open(args.args_file, 'r') as f:
                arguments = json.load(f)
        except Exception as e:
            print(f"Error loading arguments from file: {str(e)}")
            return
    else:
        # Otherwise, use command-line arguments
        args = parser.parse_args()
        arguments = {k: v for k, v in vars(args).items() if v is not None and k != "args_file"}
    
    # Get parameters
    namespace = arguments.get("namespace", "pcf")
    configmap = arguments.get("configmap", "registration-discovery-configmap")
    
    # Create and use the NrfEndpointsTool
    endpoints_tool = NrfEndpointsTool(namespace, configmap)
    
    # Display results header
    print(f"NRF Endpoints from ConfigMap '{configmap}' in namespace '{namespace}':")
    
    # List and display the endpoints
    print(endpoints_tool.list_endpoints())

if __name__ == "__main__":
    main() 