#!/usr/bin/env python3
"""
NRF Tools - Base Classes and Utilities

This module provides base classes and utilities for NRF (Network Repository Function) 
related tools in a 5G core network's Kubernetes environment.

Classes:
    NrfToolBase: Base class for NRF-related tools
"""

import json
import os
import sys
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple

# Import shared kubectl utilities from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kubectl_utils import KubernetesClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

class NrfToolBase:
    """Base class for NRF-related tools"""
    
    def __init__(self, namespace: str = "pcf", configmap: str = "registration-discovery-configmap"):
        """
        Initialize the NRF tool base.
        
        Args:
            namespace: Kubernetes namespace where to find the ConfigMap
            configmap: Name of the ConfigMap containing NRF endpoints
        """
        self.namespace = namespace
        self.configmap = configmap
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def get_nrf_endpoints(self) -> Dict[str, List[str]]:
        """
        Get NRF endpoints from the specified ConfigMap in the given namespace.
        
        Returns:
            Dictionary containing endpoint types as keys and lists of endpoints as values.
            Example: {"discovery": ["http://nrf-service:8000/nnrf-disc"], 
                     "management": ["http://nrf-service:8000/nnrf-nfm"]}
        """
        self.logger.info(f"Getting NRF endpoints from ConfigMap '{self.configmap}' in namespace '{self.namespace}'")
        
        # Get the ConfigMap
        result = KubernetesClient.execute_kubectl(["get", "configmap", self.configmap, "-n", self.namespace, "-o", "json"])
        
        if not result.success:
            self.logger.error(f"Failed to get ConfigMap: {result.error}")
            return {"discovery": [], "management": []}
        
        try:
            configmap_data = json.loads(result.output)
            data = configmap_data.get("data", {})
            
            # Initialize results dictionary
            endpoints = {
                "discovery": [],
                "management": []
            }
            
            # Process each key in the ConfigMap data
            for key, value in data.items():
                # Try to parse as JSON first, then as YAML
                try:
                    try:
                        content = json.loads(value)
                    except json.JSONDecodeError:
                        content = yaml.safe_load(value)
                    
                    # Check the content structure based on typical NRF endpoint ConfigMaps
                    if not isinstance(content, dict):
                        continue
                    
                    # Method 1: Look for direct endpoint definitions
                    if "nnrf_discovery" in content:
                        discovery_urls = content["nnrf_discovery"]
                        if isinstance(discovery_urls, list):
                            endpoints["discovery"].extend(discovery_urls)
                        elif isinstance(discovery_urls, str):
                            endpoints["discovery"].append(discovery_urls)
                    
                    if "nnrfm" in content or "nnrf_management" in content:
                        management_key = "nnrfm" if "nnrfm" in content else "nnrf_management"
                        management_urls = content[management_key]
                        if isinstance(management_urls, list):
                            endpoints["management"].extend(management_urls)
                        elif isinstance(management_urls, str):
                            endpoints["management"].append(management_urls)
                    
                    # Method 2: Look for nested endpoint structure
                    if "nrf" in content and isinstance(content["nrf"], dict):
                        nrf_config = content["nrf"]
                        
                        if "endpoints" in nrf_config and isinstance(nrf_config["endpoints"], list):
                            for endpoint in nrf_config["endpoints"]:
                                if not isinstance(endpoint, dict) or "url" not in endpoint:
                                    continue
                                    
                                url = endpoint["url"]
                                endpoint_type = endpoint.get("type", "").lower()
                                
                                if "disc" in endpoint_type or "discovery" in endpoint_type:
                                    endpoints["discovery"].append(url)
                                elif "manag" in endpoint_type or "nfm" in endpoint_type:
                                    endpoints["management"].append(url)
                                else:
                                    # If type not specified, try to guess from URL
                                    if "disc" in url.lower():
                                        endpoints["discovery"].append(url)
                                    elif "nfm" in url.lower() or "manag" in url.lower():
                                        endpoints["management"].append(url)
                except Exception as e:
                    self.logger.error(f"Error processing ConfigMap data for key '{key}': {str(e)}")
                    continue
            
            self.logger.info(f"Found {len(endpoints['discovery'])} discovery endpoints and {len(endpoints['management'])} management endpoints")
            return endpoints
        
        except Exception as e:
            self.logger.error(f"Error processing ConfigMap: {str(e)}")
            return {"discovery": [], "management": []}

    def find_sm_policy_pod(self) -> str:
        """
        Find a suitable SM-policies pod to execute curl commands from.
        
        Returns:
            Name of a suitable pod, or empty string if none found
        """
        self.logger.info(f"Looking for SM-policies pods in namespace '{self.namespace}'")
        
        # Try to find pods with "sm-policy" in the name
        result = KubernetesClient.execute_kubectl(["get", "pods", "-n", self.namespace, "-o", "json"])
        
        if not result.success:
            self.logger.error(f"Failed to get pods: {result.error}")
            return ""
        
        try:
            pods_data = json.loads(result.output)
            pods = pods_data.get("items", [])
            
            # Filter for pods with "sm-policy" in the name that are running
            sm_policy_pods = []
            
            for pod in pods:
                name = pod.get("metadata", {}).get("name", "")
                status = pod.get("status", {}).get("phase", "")
                
                if "sm-policy" in name.lower() and status == "Running":
                    sm_policy_pods.append(name)
            
            if not sm_policy_pods:
                self.logger.warning(f"No SM-policies pods found in namespace '{self.namespace}'")
                return ""
            
            # Return the first match
            selected_pod = sm_policy_pods[0]
            self.logger.info(f"Selected pod: {selected_pod}")
            return selected_pod
        
        except Exception as e:
            self.logger.error(f"Error finding SM-policies pod: {str(e)}")
            return "" 