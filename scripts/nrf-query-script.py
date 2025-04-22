#!/usr/bin/env python3
"""
NRF Query Script

This script provides functionality for querying the NRF service for Network Functions (NFs).
It can search for NFs by type (e.g., UDR, PCF, AMF) and retrieve detailed information.

Parameters:
    --action: Action to perform (discover, get_nf, get_instances, get_all_details)
    --nf_type: NF Type to search for (e.g., UDR, PCF, AMF)
    --nrf_endpoint: NRF endpoint URL (optional)
    --configmap_name: ConfigMap name containing NRF endpoints (default: nrf-config)
    --namespace: Namespace containing the ConfigMap (default: pcf)
    --exec_namespace: Namespace for executing commands (default: same as namespace)
    --pod_name: Specific pod name to execute from (optional)
    --nf_instance_id: NF Instance ID for get_nf action (required for get_nf)

Examples:
    # Discover all UDR instances
    --action discover --nf_type UDR --namespace pcf
    
    # Get detailed information about a specific NF
    --action get_nf --nf_instance_id 123e4567-e89b-12d3-a456-426614174000 --namespace pcf
"""

import argparse
import json
import os
import sys
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple

# Import shared kubectl utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kubectl_utils import KubernetesClient
# Import Pydantic for data models
try:
    from pydantic import BaseModel, Field
except ImportError:
    import subprocess
    print("Installing required packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pydantic"])
    from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("nrf-query")

# Script metadata - used by the MCP server for tool registration
SCRIPT_METADATA = {
    "description": "Query NRF service for Network Functions (NFs)",
    "aliases": ["nrf-query", "search-nf", "find-nf", "discover-nf", "get-network-functions"],
    "common_queries": [
        "query nrf for {nf_type}",
        "find {nf_type} in nrf",
        "search for {nf_type} network functions",
        "get {nf_type} instances",
        "discover {nf_type} in nrf"
    ],
    "parameters": {
        "action": {
            "type": "string", 
            "description": "Action to perform (discover, get_nf, get_instances, get_all_details)",
            "default": "discover"
        },
        "nf_type": {
            "type": "string", 
            "description": "NF Type to search for (e.g., UDR, PCF, AMF)",
            "required": True
        },
        "nrf_endpoint": {
            "type": "string", 
            "description": "NRF endpoint URL (if not provided, will use highest priority endpoint from configmap)"
        },
        "configmap_name": {
            "type": "string", 
            "description": "ConfigMap name containing NRF endpoints (default: nrf-config)",
            "default": "nrf-config"
        },
        "namespace": {
            "type": "string", 
            "description": "Namespace containing the ConfigMap (default: pcf)",
            "default": "pcf"
        },
        "exec_namespace": {
            "type": "string",
            "description": "Namespace to find a pod to execute curl commands from (default: same as namespace parameter)"
        },
        "pod_name": {
            "type": "string",
            "description": "Specific pod name to execute curl commands from (if not provided, will find a suitable pod)"
        },
        "nf_instance_id": {
            "type": "string",
            "description": "NF Instance ID for get_nf action (required for get_nf)"
        }
    }
}

# Pydantic models for NRF data
class NFEndpoint(BaseModel):
    """
    Network Function Endpoint model
    
    Represents an NRF endpoint configuration with URL and priority.
    
    Attributes:
        url: The endpoint URL for accessing the NRF service
        priority: Priority value (lower is higher priority)
        description: Optional description of the endpoint
    """
    url: str
    priority: int
    description: Optional[str] = None

class NFService(BaseModel):
    """
    Network Function Service model
    
    Represents a service offered by a Network Function.
    
    Attributes:
        service_name: Name of the service (e.g., "nudm-sdm")
        service_id: Unique identifier for the service instance
        service_status: Status of the service ("REGISTERED", etc.)
        versions: List of supported API versions
        ip_endpoints: List of IP endpoints for the service
    """
    service_name: str = Field(..., alias="serviceName")
    service_id: Optional[str] = Field(None, alias="serviceInstanceId")
    service_status: Optional[str] = Field(None, alias="nfServiceStatus")
    versions: Optional[List[Dict[str, str]]] = None
    ip_endpoints: Optional[List[Dict[str, Any]]] = Field(None, alias="ipEndPoints")

class NFInstance(BaseModel):
    """
    Network Function Instance model
    
    Represents a single Network Function instance registered with the NRF.
    
    Attributes:
        nf_type: Type of the Network Function (UDR, PCF, AMF, etc.)
        nf_instance_id: Unique identifier for the NF instance
        nf_status: Status of the NF ("REGISTERED", etc.)
        fqdn: Fully Qualified Domain Name of the NF
        ipv4_addresses: List of IPv4 addresses for the NF
        heart_beat_timer: Heartbeat timer value in seconds
        nf_services: List of services offered by this NF
        profile_changes_support: Whether profile changes are supported
        default_notification_subscriptions: Default notification subscriptions
    """
    nf_type: str = Field(..., alias="nfType")
    nf_instance_id: str = Field(..., alias="nfInstanceId")
    nf_status: str = Field(..., alias="nfStatus")
    fqdn: Optional[str] = None
    ipv4_addresses: Optional[List[str]] = Field(None, alias="ipv4Addresses")
    heart_beat_timer: Optional[int] = Field(None, alias="heartBeatTimer")
    nf_services: Optional[List[NFService]] = Field(None, alias="nfServices")
    profile_changes_support: Optional[bool] = Field(None, alias="nfProfileChangesSupport")
    default_notification_subscriptions: Optional[List[Dict[str, str]]] = Field(None, alias="defaultNotificationSubscriptions")

class NFDiscoveryResponse(BaseModel):
    """
    NRF Discovery Response model
    
    Represents the response from the NRF Discovery API.
    
    Attributes:
        nf_instances: List of Network Function instances that match the query
    """
    nf_instances: List[NFInstance] = Field([], alias="nfInstances")

def get_nrf_endpoint(configmap_name="nrf-config", namespace="pcf"):
    """
    Get the highest priority NRF endpoint from the ConfigMap.
    
    Retrieves and parses the NRF endpoint configuration from a ConfigMap.
    Selects the endpoint with the highest priority (lowest priority number).
    
    Parameters:
        configmap_name: Name of the ConfigMap containing NRF endpoints (default: nrf-config)
        namespace: Kubernetes namespace where the ConfigMap is located (default: pcf)
        
    Returns:
        Tuple containing (endpoint_url, error_message)
        - endpoint_url: String URL of the highest priority NRF endpoint, or None if not found
        - error_message: Error description if operation failed, or None if successful
    """
    result = KubernetesClient.get_resource("configmap", configmap_name, namespace=namespace)
    
    if not result.success:
        return None, f"Error getting ConfigMap '{configmap_name}': {result.error}"
    
    try:
        configmap = result.output
        data = configmap.get("data", {})
        all_endpoints = []
        
        # Process each data field
        for key, value in data.items():
            if key.endswith(('.json', '.yaml', '.yml')):
                try:
                    # Try parsing as JSON first, then YAML if JSON fails
                    try:
                        content = json.loads(value)
                    except json.JSONDecodeError:
                        content = yaml.safe_load(value)
                    
                    # Look for NRF configuration
                    if isinstance(content, dict) and 'nrf' in content:
                        nrf_config = content['nrf']
                        if isinstance(nrf_config, dict) and 'endpoints' in nrf_config:
                            for ep in nrf_config['endpoints']:
                                if 'url' in ep and 'priority' in ep:
                                    all_endpoints.append(
                                        NFEndpoint(
                                            url=ep["url"],
                                            priority=ep["priority"],
                                            description=ep.get("description", "")
                                        )
                                    )
                except Exception as e:
                    logger.error(f"Error processing {key}: {str(e)}")
                    continue
        
        if not all_endpoints:
            return None, f"No NRF endpoints found in ConfigMap '{configmap_name}'."
        
        # Sort by priority (lower number = higher priority)
        all_endpoints.sort(key=lambda x: x.priority)
        
        # Return the highest priority endpoint
        return all_endpoints[0].url, None
    
    except Exception as e:
        logger.error(f"Error processing ConfigMap: {str(e)}")
        return None, f"Error processing ConfigMap: {str(e)}"

def discover_nfs(nrf_endpoint, nf_type=None, pod_name=None, namespace="pcf"):
    """
    Discover Network Functions from NRF Discovery service.
    
    Queries the NRF Discovery API to find Network Function instances.
    Can filter by NF type (e.g., UDR, PCF, AMF).
    
    Parameters:
        nrf_endpoint: URL of the NRF service endpoint
        nf_type: Type of Network Function to search for (optional)
        pod_name: Name of the pod to execute curl commands from (optional)
        namespace: Kubernetes namespace to find pods for execution (default: pcf)
        
    Returns:
        Tuple containing (output_text, discovery_response)
        - output_text: Human-readable formatted results or error message
        - discovery_response: NFDiscoveryResponse object or None if operation failed
    """
    # Construct the NRF discovery URL
    discovery_url = f"{nrf_endpoint.rstrip('/')}/nnrf-disc/v1/nf-instances"
    
    # Add query parameter for NF type if specified
    if nf_type:
        discovery_url += f"?target-nf-type={nf_type}"
    
    # Find a pod to execute from if not provided
    if not pod_name:
        pod_name, error = KubernetesClient.find_pod_for_exec(namespace)
        if error:
            return f"Error finding pod for execution: {error}", None
    
    # Set headers for the curl command
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    try:
        # Execute curl command from the pod
        result = KubernetesClient.curl_from_pod(
            pod_name=pod_name,
            namespace=namespace,
            url=discovery_url,
            method="GET",
            headers=headers
        )
        
        if not result.success:
            return f"Error querying NRF discovery service: {result.error}", None
        
        # Parse the response
        try:
            nf_data = json.loads(result.output)
            discovery_response = NFDiscoveryResponse.parse_obj(nf_data)
            formatted_output = format_nf_discovery_results(discovery_response, nf_type)
            return formatted_output, discovery_response
        except Exception as e:
            logger.error(f"Error parsing NRF response data: {str(e)}")
            return f"Error parsing NRF response: {str(e)}", None
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return f"Error executing curl command: {str(e)}", None

def get_nf(nrf_endpoint, nf_instance_id, pod_name=None, namespace="pcf"):
    """
    Get details for a specific NF instance.
    
    Retrieves detailed information about a Network Function instance
    using its unique instance ID from the NRF Management API.
    
    Parameters:
        nrf_endpoint: URL of the NRF service endpoint
        nf_instance_id: Unique identifier of the NF instance to query
        pod_name: Name of the pod to execute curl commands from (optional)
        namespace: Kubernetes namespace to find pods for execution (default: pcf)
        
    Returns:
        Formatted string containing detailed information about the NF instance
        or an error message if the operation failed
    """
    # Construct the NRF management URL for the specific NF
    nf_url = f"{nrf_endpoint.rstrip('/')}/nnrf-nfm/v1/nf-instances/{nf_instance_id}"
    
    # Find a pod to execute from if not provided
    if not pod_name:
        pod_name, error = KubernetesClient.find_pod_for_exec(namespace)
        if error:
            return f"Error finding pod for execution: {error}"
    
    # Set headers for the curl command
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    try:
        # Execute curl command from the pod
        result = KubernetesClient.curl_from_pod(
            pod_name=pod_name,
            namespace=namespace,
            url=nf_url,
            method="GET",
            headers=headers
        )
        
        if not result.success:
            return f"Error querying NRF for NF instance: {result.error}"
        
        # Parse the response
        try:
            nf_data = json.loads(result.output)
            nf_instance = NFInstance.parse_obj(nf_data)
            return format_nf_details(nf_instance)
        except Exception as e:
            logger.error(f"Error parsing NF instance data: {str(e)}")
            return f"Error parsing NF instance data: {str(e)}"
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return f"Error executing curl command: {str(e)}"

def get_nf_instances(nrf_endpoint, nf_type, pod_name=None, namespace="pcf"):
    """
    Get all instances of a specific NF type.
    
    Discovers all Network Function instances of the specified type.
    This is a convenience wrapper around the discover_nfs function.
    
    Parameters:
        nrf_endpoint: URL of the NRF service endpoint
        nf_type: Type of Network Function to search for (e.g., UDR, PCF, AMF)
        pod_name: Name of the pod to execute curl commands from (optional)
        namespace: Kubernetes namespace to find pods for execution (default: pcf)
        
    Returns:
        Formatted string containing information about the NF instances
        or an error message if the operation failed
    """
    result, _ = discover_nfs(nrf_endpoint, nf_type, pod_name, namespace)
    return result

def get_all_nf_details(nrf_endpoint, nf_type, pod_name=None, namespace="pcf"):
    """
    Get detailed information for all instances of a specific NF type.
    
    First discovers all Network Function instances of the specified type,
    then retrieves detailed information for each instance.
    
    Parameters:
        nrf_endpoint: URL of the NRF service endpoint
        nf_type: Type of Network Function to search for (e.g., UDR, PCF, AMF)
        pod_name: Name of the pod to execute curl commands from (optional)
        namespace: Kubernetes namespace to find pods for execution (default: pcf)
        
    Returns:
        Formatted string containing detailed information about all NF instances
        or an error message if the operation failed
    """
    # First discover NFs by type to get their instance IDs
    discovery_result, discovery_response = discover_nfs(nrf_endpoint, nf_type, pod_name, namespace)
    
    # Check for errors or no instances
    if discovery_response is None:
        return discovery_result
    
    if not discovery_response.nf_instances:
        return f"No {nf_type} instances found."
    
    # Get detailed information for each instance
    output = f"Detailed information for {len(discovery_response.nf_instances)} {nf_type} instances:\n\n"
    
    for i, instance in enumerate(discovery_response.nf_instances, 1):
        logger.info(f"Fetching details for {nf_type} instance {i}/{len(discovery_response.nf_instances)}: {instance.nf_instance_id}")
        
        # Get detailed information for this instance
        instance_details = get_nf(nrf_endpoint, instance.nf_instance_id, pod_name, namespace)
        
        # Add separator between instances
        if i > 1:
            output += "\n" + "="*80 + "\n\n"
        
        # Add instance details
        output += instance_details
    
    return output

def format_nf_discovery_results(discovery_response: NFDiscoveryResponse, nf_type=None):
    """
    Format NF discovery results in a readable format.
    
    Takes the discovery response object and generates a human-readable
    tabular representation of the Network Function instances.
    
    Parameters:
        discovery_response: NFDiscoveryResponse object containing NF instances
        nf_type: Type of Network Function that was searched for (optional)
        
    Returns:
        Formatted string containing tabular information about the NF instances
    """
    nf_instances = discovery_response.nf_instances
    
    if not nf_instances:
        return f"No {nf_type if nf_type else 'NF'} instances found."
    
    # Format as a table
    output = f"Found {len(nf_instances)} NF instances"
    if nf_type:
        output += f" of type {nf_type}"
    output += ":\n\n"
    
    # Table header
    output += "NF Type | Instance ID | Status | FQDN/IP | Heartbeat | Services\n"
    output += "--------|-------------|--------|---------|-----------|----------\n"
    
    for instance in nf_instances:
        # Get FQDN/IP
        fqdn = "N/A"
        if instance.fqdn:
            fqdn = instance.fqdn
        elif instance.ipv4_addresses and instance.ipv4_addresses:
            fqdn = instance.ipv4_addresses[0]
        
        # Get heartbeat
        heartbeat = instance.heart_beat_timer if instance.heart_beat_timer else "N/A"
        
        # Get services
        services = []
        if instance.nf_services:
            services = [service.service_name for service in instance.nf_services]
        
        services_str = ", ".join(services) if services else "None"
        
        # Add row to table
        output += f"{instance.nf_type} | {instance.nf_instance_id[:8]}... | {instance.nf_status} | {fqdn} | {heartbeat} | {services_str}\n"
    
    return output

def format_nf_details(instance: NFInstance):
    """
    Format detailed NF information in a readable format.
    
    Takes an NFInstance object and generates a human-readable
    representation of all its attributes and services.
    
    Parameters:
        instance: NFInstance object containing detailed NF information
        
    Returns:
        Formatted string containing detailed information about the NF instance
    """
    output = f"Details for {instance.nf_type} instance {instance.nf_instance_id}:\n\n"
    
    # Basic information
    output += "Basic Information:\n"
    output += f"- Type: {instance.nf_type}\n"
    output += f"- Status: {instance.nf_status}\n"
    
    if instance.heart_beat_timer:
        output += f"- Heartbeat Timer: {instance.heart_beat_timer}\n"
    
    if instance.fqdn:
        output += f"- FQDN: {instance.fqdn}\n"
    
    if instance.ipv4_addresses:
        output += f"- IPv4 Addresses: {', '.join(instance.ipv4_addresses)}\n"
    
    # NF services
    if instance.nf_services:
        output += "\nServices:\n"
        for service in instance.nf_services:
            output += f"- {service.service_name} (ID: {service.service_id or 'Unknown'}, Status: {service.service_status or 'Unknown'})\n"
            
            if service.versions:
                versions = [f"{v.get('apiVersionInUri', '')}/{v.get('apiFullVersion', '')}" 
                          for v in service.versions]
                output += f"  Versions: {', '.join(versions)}\n"
            
            if service.ip_endpoints:
                output += "  Endpoints:\n"
                for endpoint in service.ip_endpoints:
                    ip = endpoint.get("ipv4Address", "Unknown")
                    port = endpoint.get("port", "Unknown")
                    output += f"  - {ip}:{port}\n"
    
    # Additional info
    if instance.profile_changes_support:
        output += f"\nProfile Changes Support: {instance.profile_changes_support}\n"
    
    if instance.default_notification_subscriptions:
        output += "\nDefault Notification Subscriptions:\n"
        for sub in instance.default_notification_subscriptions:
            output += f"- {sub.get('notificationType', 'Unknown')}\n"
    
    return output

def main():
    """
    Main function that parses arguments and executes the script.
    
    Handles command line arguments and supports multiple operations:
    - discover: Find NFs of a specific type
    - get_nf: Get detailed information about a specific NF
    - get_instances: List all instances of a specific NF type
    - get_all_details: Get detailed information about all NFs of a specific type
    
    Supports both direct command line usage and being called from the MCP server
    with arguments in a JSON file.
    
    Command Line Examples:
        python nrf-query-script.py discover --nf-type UDR --namespace pcf
        python nrf-query-script.py get_nf --nf-instance-id 12345 --namespace pcf
    """
    parser = argparse.ArgumentParser(
        description="Query NRF for Network Functions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Check if the --metadata flag is present
    if "--metadata" in sys.argv:
        print(json.dumps(SCRIPT_METADATA))
        return
    
    # Check if the --args-file flag is present
    parser.add_argument("--args-file", help="JSON file containing arguments")
    args, _ = parser.parse_known_args()
    
    if args.args_file:
        # Load arguments from the file
        with open(args.args_file, 'r') as f:
            arguments = json.load(f)
            
        # Handle simplified queries by examining if only a type is specified
        if len(arguments) == 1 and "nf_type" in arguments:
            # This is likely a simple "query nrf for UDR" style command
            arguments["action"] = "discover"
        elif "nf_type" in arguments and "action" not in arguments:
            # Default to discover action if type specified but no action
            arguments["action"] = "discover"
    else:
        # Default arguments for CLI usage
        parser.add_argument("action", choices=["discover", "get_nf", "get_instances", "get_all_details"], 
                          help="Action to perform")
        parser.add_argument("--nf-type", help="NF Type to search for (e.g., UDR, PCF, AMF)")
        parser.add_argument("--nrf-endpoint", help="NRF endpoint URL (optional)")
        parser.add_argument("--configmap-name", default="nrf-config", 
                          help="ConfigMap name containing NRF endpoints")
        parser.add_argument("--namespace", default="pcf", 
                          help="Namespace containing the ConfigMap")
        parser.add_argument("--nf-instance-id", help="NF Instance ID for get_nf action")
        parser.add_argument("--exec-namespace", help="Namespace to find a pod to execute curl commands from")
        parser.add_argument("--pod-name", help="Specific pod name to execute curl commands from")
        
        cli_args = parser.parse_args()
        
        # Convert Namespace to dict
        arguments = {k: v for k, v in vars(cli_args).items() if v is not None}
    
    # Execute the requested action
    action = arguments.get("action")
    nrf_endpoint = arguments.get("nrf_endpoint")
    nf_type = arguments.get("nf_type")
    pod_name = arguments.get("pod_name")
    
    # Get namespace for config map and for pod execution
    namespace = arguments.get("namespace", "pcf")
    exec_namespace = arguments.get("exec_namespace", namespace)
    
    # If no NRF endpoint provided, get from ConfigMap
    if not nrf_endpoint:
        configmap_name = arguments.get("configmap_name", "nrf-config")
        endpoint, error = get_nrf_endpoint(configmap_name, namespace)
        if error:
            print(error)
            return
        nrf_endpoint = endpoint
    
    if not nrf_endpoint:
        print("Error: NRF endpoint not provided and could not be determined from ConfigMap.")
        return
    
    # Process the requested action
    try:
        if action == "discover":
            result, _ = discover_nfs(nrf_endpoint, nf_type, pod_name, exec_namespace)
            print(result)
        elif action == "get_nf":
            nf_instance_id = arguments.get("nf_instance_id")
            if not nf_instance_id:
                print("Error: Missing required parameter 'nf_instance_id' for 'get_nf' action")
                return
            result = get_nf(nrf_endpoint, nf_instance_id, pod_name, exec_namespace)
            print(result)
        elif action == "get_instances":
            if not nf_type:
                print("Error: Missing required parameter 'nf_type' for 'get_instances' action")
                return
            result = get_nf_instances(nrf_endpoint, nf_type, pod_name, exec_namespace)
            print(result)
        elif action == "get_all_details":
            if not nf_type:
                print("Error: Missing required parameter 'nf_type' for 'get_all_details' action")
                return
            result = get_all_nf_details(nrf_endpoint, nf_type, pod_name, exec_namespace)
            print(result)
        else:
            print(f"Unknown action: {action}")
    except Exception as e:
        print(f"Error executing {action}: {str(e)}")
        logger.error(f"Unhandled exception: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()
