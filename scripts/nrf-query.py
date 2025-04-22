#!/usr/bin/env python3
"""
NRF Query Tool

A specialized tool for querying NRF (Network Repository Function) in a 5G core network
for specific types of Network Functions.

This script:
1. Uses a discovery endpoint to query for network functions of a specific type
2. Iterates over each NF instance to display basic information
3. Can fetch detailed information for each NF instance
4. Executes curl commands from SM-policies pods in the specified namespace

Parameters:
    --nf_type: Type of Network Function to search for (e.g., UDR, PCF, AMF) [Required]
    --namespace: Kubernetes namespace (default: pcf)
    --endpoint: NRF discovery endpoint URL (if not specified, will try to find from ConfigMap)
    --configmap: ConfigMap containing NRF endpoints (default: registration-discovery-configmap)
    --detailed: Whether to show detailed information for each NF instance (default: false)

Examples:
    # Find all UDR instances
    python3 nrf-query.py --nf_type UDR
    
    # Get detailed information about all PCF instances
    python3 nrf-query.py --nf_type PCF --detailed true
    
    # Query using a specific endpoint
    python3 nrf-query.py --nf_type AMF --endpoint http://nrf:8000/nnrf-disc/v1
"""

import argparse
import json
import os
import sys
import logging
from typing import Dict, List, Any, Optional, Tuple

# Import the base class from nrf_tools
from nrf_tools import NrfToolBase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("nrf-query")

# Script metadata - used by the MCP server for tool registration
SCRIPT_METADATA = {
    "description": "Query NRF for Network Functions in 5G core",
    "aliases": ["query-nrf", "find-nf", "get-nf", "list-nf", "search-nf"],
    "common_queries": [
        "query nrf for {nf_type}",
        "find {nf_type} in nrf",
        "search for {nf_type}",
        "get {nf_type} instances",
        "list {nf_type} functions",
        "show {nf_type} in network",
        "display all {nf_type}",
        "what {nf_type} are registered"
    ],
    "parameters": {
        "nf_type": {
            "type": "string",
            "description": "Type of Network Function to search for (e.g., UDR, PCF, AMF)",
            "required": True
        },
        "namespace": {
            "type": "string",
            "description": "Kubernetes namespace (default: pcf)",
            "default": "pcf"
        },
        "endpoint": {
            "type": "string",
            "description": "NRF discovery endpoint URL (if not specified, will try to find from ConfigMap)"
        },
        "configmap": {
            "type": "string",
            "description": "ConfigMap containing NRF endpoints",
            "default": "registration-discovery-configmap"
        },
        "detailed": {
            "type": "boolean",
            "description": "Whether to show detailed information for each NF instance",
            "default": False
        }
    }
}

class NrfQueryTool(NrfToolBase):
    """Tool for querying NRF for network functions"""
    
    def __init__(self, nf_type: str, namespace: str = "pcf", 
                 configmap: str = "registration-discovery-configmap",
                 endpoint: Optional[str] = None, detailed: bool = False):
        """
        Initialize the NRF query tool.
        
        Args:
            nf_type: Type of Network Function to search for (e.g., UDR, PCF, AMF)
            namespace: Kubernetes namespace where to find the ConfigMap
            configmap: Name of the ConfigMap containing NRF endpoints
            endpoint: NRF discovery endpoint URL (if not specified, will try to find from ConfigMap)
            detailed: Whether to show detailed information for each NF instance
        """
        super().__init__(namespace, configmap)
        self.nf_type = nf_type
        self.discovery_endpoint = endpoint
        self.management_endpoint = None
        self.detailed = detailed
        self.pod_name = None
    
    def query_nrf(self) -> str:
        """
        Query NRF for network functions of the specified type.
        
        Returns:
            Formatted string with the query results
        """
        output_parts = []
        
        # Step 1: Get or validate NRF endpoints
        if not self.discovery_endpoint:
            # No endpoint provided, try to get from ConfigMap
            endpoints = self.get_nrf_endpoints()
            
            # Check if we have discovery endpoints
            if not endpoints.get("discovery"):
                return f"No NRF discovery endpoints found in ConfigMap '{self.configmap}'"
            
            # Use the first discovery endpoint
            self.discovery_endpoint = endpoints["discovery"][0]
            output_parts.append(f"Using discovery endpoint from ConfigMap: {self.discovery_endpoint}")
            
            # Also get management endpoint for detailed information
            if self.detailed and endpoints.get("management"):
                self.management_endpoint = endpoints["management"][0]
        else:
            # Endpoint provided, assume it's a discovery endpoint
            output_parts.append(f"Using provided discovery endpoint: {self.discovery_endpoint}")
            
            # If detailed mode requested but no management endpoint, try to derive it
            if self.detailed:
                # Try to convert discovery endpoint to management endpoint
                # This is a best effort, may not work depending on URL format
                try:
                    self.management_endpoint = self.discovery_endpoint.replace("disc", "nfm").replace("discovery", "management")
                    output_parts.append(f"Derived management endpoint: {self.management_endpoint}")
                except:
                    output_parts.append("Could not derive management endpoint from discovery endpoint. Detailed information may be limited.")
        
        # Step 2: Find an SM-policies pod to execute curl from
        self.pod_name = self.find_sm_policy_pod()
        if not self.pod_name:
            return f"No suitable SM-policies pod found in namespace '{self.namespace}'"
        
        output_parts.append(f"Using pod '{self.pod_name}' to execute curl commands")
        
        # Step 3: Query NRF for the specified NF type
        nf_instances, error = self.query_nrf_for_nf_type()
        
        if error:
            return f"Error querying NRF: {error}"
        
        if not nf_instances:
            return f"No {self.nf_type} instances found"
        
        output_parts.append(f"Found {len(nf_instances)} {self.nf_type} instances:")
        
        # Step 4: Iterate over each NF instance
        for idx, instance in enumerate(nf_instances, 1):
            output_parts.append(f"\n{idx}. {self.format_nf_instance(instance)}")
            
            # If detailed mode is requested and we have a management endpoint, get more information
            if self.detailed and self.management_endpoint:
                nf_id = instance.get("nfInstanceId")
                
                if nf_id:
                    details, error = self.get_nf_details(nf_id)
                    if not error and details:
                        output_parts.append("\nDetailed information:")
                        output_parts.append(self.format_nf_instance_detailed(details))
        
        return "\n".join(output_parts)
    
    def query_nrf_for_nf_type(self) -> Tuple[List[Dict], str]:
        """
        Query the NRF for a specific NF type.
        
        Returns:
            Tuple of (list of NF instances, error message)
        """
        self.logger.info(f"Querying NRF for NF type '{self.nf_type}' using endpoint '{self.discovery_endpoint}'")
        
        # Normalize the endpoint URL
        endpoint = self.discovery_endpoint
        if not endpoint.endswith("/"):
            endpoint += "/"
        
        if not endpoint.endswith("nf-instances") and not endpoint.endswith("nf-instances/"):
            endpoint += "nf-instances"
        
        # Add query parameter for NF type
        query_url = f"{endpoint}?target-nf-type={self.nf_type}"
        
        # Execute curl command from the pod
        curl_cmd = f"curl -s -X GET '{query_url}' -H 'Accept: application/json'"
        result = self.execute_curl_from_pod(curl_cmd)
        
        if not result.success:
            error_msg = f"Failed to execute curl command: {result.error}"
            self.logger.error(error_msg)
            return [], error_msg
        
        try:
            response_data = json.loads(result.output)
            nf_instances = response_data.get("nfInstances", [])
            self.logger.info(f"Found {len(nf_instances)} instances of type '{self.nf_type}'")
            return nf_instances, ""
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse NRF response: {str(e)}"
            self.logger.error(error_msg)
            return [], error_msg
    
    def get_nf_details(self, nf_instance_id: str) -> Tuple[Dict, str]:
        """
        Get detailed information about a specific NF instance.
        
        Args:
            nf_instance_id: ID of the NF instance
            
        Returns:
            Tuple of (NF instance details, error message)
        """
        self.logger.info(f"Getting details for NF instance '{nf_instance_id}'")
        
        if not self.management_endpoint:
            return {}, "No management endpoint available"
        
        # Normalize the endpoint URL
        endpoint = self.management_endpoint
        if endpoint.endswith("/"):
            endpoint = endpoint[:-1]
        
        if endpoint.endswith("/nf-instances"):
            endpoint = endpoint[:-12]
        
        # Construct the URL for the specific NF instance
        instance_url = f"{endpoint}/nf-instances/{nf_instance_id}"
        
        # Execute curl command from the pod
        curl_cmd = f"curl -s -X GET '{instance_url}' -H 'Accept: application/json'"
        result = self.execute_curl_from_pod(curl_cmd)
        
        if not result.success:
            error_msg = f"Failed to get details for NF instance '{nf_instance_id}': {result.error}"
            self.logger.error(error_msg)
            return {}, error_msg
        
        try:
            instance_data = json.loads(result.output)
            return instance_data, ""
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse NF instance details: {str(e)}"
            self.logger.error(error_msg)
            return {}, error_msg
    
    def execute_curl_from_pod(self, curl_cmd: str) -> Any:
        """
        Execute a curl command from the SM-policies pod.
        
        Args:
            curl_cmd: The curl command to execute
            
        Returns:
            The result of the kubectl exec command
        """
        from kubectl_utils import KubernetesClient
        return KubernetesClient.execute_kubectl(["exec", "-n", self.namespace, self.pod_name, "--", "sh", "-c", curl_cmd])
    
    def format_nf_instance(self, instance: Dict) -> str:
        """
        Format an NF instance into a readable string.
        
        Args:
            instance: Dictionary containing NF instance data
            
        Returns:
            Formatted string representation
        """
        nf_type = instance.get("nfType", "Unknown")
        nf_id = instance.get("nfInstanceId", "Unknown")
        status = instance.get("nfStatus", "Unknown")
        
        # Get addresses
        addresses = []
        if "fqdn" in instance:
            addresses.append(f"FQDN: {instance['fqdn']}")
        
        if "ipv4Addresses" in instance and instance["ipv4Addresses"]:
            addresses.append(f"IPv4: {', '.join(instance['ipv4Addresses'])}")
        
        addresses_str = ", ".join(addresses) if addresses else "No address information"
        
        # Get services
        services = []
        if "nfServices" in instance and instance["nfServices"]:
            for service in instance["nfServices"]:
                service_name = service.get("serviceName", "Unknown")
                service_status = service.get("nfServiceStatus", "Unknown")
                services.append(f"{service_name} ({service_status})")
        
        services_str = ", ".join(services) if services else "No services"
        
        # Format the basic information
        output = f"NF Instance: {nf_id}\n"
        output += f"  Type: {nf_type}\n"
        output += f"  Status: {status}\n"
        output += f"  Address: {addresses_str}\n"
        output += f"  Services: {services_str}\n"
        
        return output
    
    def format_nf_instance_detailed(self, instance: Dict) -> str:
        """
        Format an NF instance into a detailed readable string.
        
        Args:
            instance: Dictionary containing NF instance data
            
        Returns:
            Formatted string representation with detailed information
        """
        nf_type = instance.get("nfType", "Unknown")
        nf_id = instance.get("nfInstanceId", "Unknown")
        status = instance.get("nfStatus", "Unknown")
        
        output = f"NF Instance Details: {nf_id}\n"
        output += f"==================={'=' * len(nf_id)}\n\n"
        output += f"Type: {nf_type}\n"
        output += f"Status: {status}\n"
        
        # Basic information
        if "heartBeatTimer" in instance:
            output += f"Heartbeat Timer: {instance['heartBeatTimer']}\n"
        
        if "fqdn" in instance:
            output += f"FQDN: {instance['fqdn']}\n"
        
        if "ipv4Addresses" in instance and instance["ipv4Addresses"]:
            output += f"IPv4 Addresses: {', '.join(instance['ipv4Addresses'])}\n"
        
        # Services
        if "nfServices" in instance and instance["nfServices"]:
            output += "\nServices:\n"
            for service in instance["nfServices"]:
                service_name = service.get("serviceName", "Unknown")
                service_id = service.get("serviceInstanceId", "Unknown")
                service_status = service.get("nfServiceStatus", "Unknown")
                
                output += f"- {service_name} (ID: {service_id}, Status: {service_status})\n"
                
                # API versions
                if "versions" in service and service["versions"]:
                    versions = []
                    for version in service["versions"]:
                        v_uri = version.get("apiVersionInUri", "")
                        v_full = version.get("apiFullVersion", "")
                        versions.append(f"{v_uri}/{v_full}")
                    
                    output += f"  Versions: {', '.join(versions)}\n"
                
                # Endpoints
                if "ipEndPoints" in service and service["ipEndPoints"]:
                    output += "  Endpoints:\n"
                    for endpoint in service["ipEndPoints"]:
                        ip = endpoint.get("ipv4Address", "Unknown")
                        port = endpoint.get("port", "Unknown")
                        output += f"  - {ip}:{port}\n"
        
        # Additional info
        if "nfProfileChangesSupport" in instance:
            output += f"\nProfile Changes Support: {instance['nfProfileChangesSupport']}\n"
        
        if "defaultNotificationSubscriptions" in instance and instance["defaultNotificationSubscriptions"]:
            output += "\nDefault Notification Subscriptions:\n"
            for sub in instance["defaultNotificationSubscriptions"]:
                notif_type = sub.get("notificationType", "Unknown")
                output += f"- {notif_type}\n"
        
        return output

def main():
    """
    Main function to parse arguments and execute the NRF query.
    """
    # Check if the --metadata flag is present
    if "--metadata" in sys.argv:
        print(json.dumps(SCRIPT_METADATA))
        return
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="Query NRF for Network Functions in 5G core",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("--args-file", help="JSON file containing arguments")
    parser.add_argument("--nf_type", help="Type of Network Function to search for (e.g., UDR, PCF, AMF)")
    parser.add_argument("--namespace", default="pcf", help="Kubernetes namespace")
    parser.add_argument("--endpoint", help="NRF discovery endpoint URL")
    parser.add_argument("--configmap", default="registration-discovery-configmap", help="ConfigMap name containing NRF endpoints")
    parser.add_argument("--detailed", type=lambda x: x.lower() == "true", default=False, help="Whether to show detailed information")
    
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
    
    # Validate required parameters
    if "nf_type" not in arguments:
        print("Error: Missing required parameter 'nf_type'")
        return
    
    # Get parameters
    nf_type = arguments["nf_type"]
    namespace = arguments.get("namespace", "pcf")
    endpoint = arguments.get("endpoint")
    configmap = arguments.get("configmap", "registration-discovery-configmap")
    detailed = arguments.get("detailed", False)
    
    # Create the NRF query tool
    query_tool = NrfQueryTool(nf_type, namespace, configmap, endpoint, detailed)
    
    # Execute the query and print the results
    result = query_tool.query_nrf()
    print(result)

if __name__ == "__main__":
    main() 