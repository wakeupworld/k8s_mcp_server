#!/usr/bin/env python3
"""
NRF Query Script

This script provides functionality for querying the NRF service for Network Functions (NFs).
It can search for NFs by type (e.g., UDR) and other parameters.
"""

import argparse
import json
import os
import sys
import tempfile
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple

# Import shared kubectl utilities
# Adjust the import path as needed for your directory structure
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
    "parameters": {
        "action": {
            "type": "string", 
            "description": "Action to perform (discover, get_nf, get_instances)"
        },
        "nf_type": {
            "type": "string", 
            "description": "NF Type to search for (e.g., UDR, PCF, AMF)"
        },
        "nrf_endpoint": {
            "type": "string", 
            "description": "NRF endpoint URL (if not provided, will use highest priority endpoint from configmap)"
        },
        "configmap_name": {
            "type": "string", 
            "description": "ConfigMap name containing NRF endpoints (default: nrf-config)"
        },
        "namespace": {
            "type": "string", 
            "description": "Namespace containing the ConfigMap (default: pcf)"
        },
        "exec_namespace": {
            "type": "string",
            "description": "Namespace to find a pod to execute curl commands from (default: same as namespace parameter)"
        },
        "pod_name": {
            "type": "string",
            "description": "Specific pod name to execute curl commands from (if not provided, will find a suitable pod)"
        }
    }
}

# Pydantic models for NRF data
class NFEndpoint(BaseModel):
    """Network Function Endpoint"""
    url: str
    priority: int
    description: Optional[str] = None

class NFService(BaseModel):
    """Network Function Service"""
    service_name: str = Field(..., alias="serviceName")
    service_id: Optional[str] = Field(None, alias="serviceInstanceId")
    service_status: Optional[str] = Field(None, alias="nfServiceStatus")
    versions: Optional[List[Dict[str, str]]] = None
    ip_endpoints: Optional[List[Dict[str, Any]]] = Field(None, alias="ipEndPoints")

class NFInstance(BaseModel):
    """Network Function Instance"""
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
    """NRF Discovery Response"""
    nf_instances: List[NFInstance] = Field([], alias="nfInstances")

def get_nrf_endpoint(configmap_name="nrf-config", namespace="pcf"):
    """Get the highest priority NRF endpoint from the ConfigMap"""
    result = KubernetesClient.get_resource("configmap", configmap_name, namespace=namespace)
    
    if not result.success:
        return None, f"Error getting ConfigMap '{configmap_name}': {result['error']}"
    
    try:
        configmap = result.output
        data = configmap.get("data", {})
        
        all_endpoints = []
        
        # Process each data field
        for key, value in data.items():
            if key.endswith('.json') or key.endswith('.yaml') or key.endswith('.yml'):
                try:
                    # Try parsing as JSON first
                    try:
                        content = json.loads(value)
                    except json.JSONDecodeError:
                        # Try parsing as YAML if JSON fails
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
    """Discover Network Functions from NRF Discovery service"""
    # Construct the NRF discovery URL
    discovery_url = f"{nrf_endpoint.rstrip('/')}/nnrf-disc/v1/nf-instances"
    
    # Add query parameter for NF type if specified
    if nf_type:
        discovery_url += f"?target-nf-type={nf_type}"
    
    # Find a pod to execute from if not provided
    if not pod_name:
        pod_name, error = KubernetesClient.find_pod_for_exec(namespace)
        if error:
            return error
    
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
            return f"Error querying NRF discovery service: {result.error}"
        
        # Parse the response
        try:
            nf_data = json.loads(result.output)
            # Use Pydantic model for response parsing
            discovery_response = NFDiscoveryResponse.parse_obj(nf_data)
            # Format the response
            formatted_output = format_nf_discovery_results(discovery_response, nf_type)
            return formatted_output
        except json.JSONDecodeError as e:
            return f"Error parsing NRF response: {str(e)}\nResponse: {result.output}"
        except Exception as e:
            logger.error(f"Error parsing NRF response data: {str(e)}")
            return f"Error parsing NRF response data: {str(e)}\nResponse: {result.output}"
        
    except Exception as e:
        logger.error(f"Error executing curl command in pod: {str(e)}")
        return f"Error executing curl command in pod: {str(e)}"

def get_nf(nrf_endpoint, nf_instance_id, pod_name=None, namespace="pcf"):
    """Get details for a specific NF instance"""
    # Construct the NRF management URL for the specific NF
    nf_url = f"{nrf_endpoint.rstrip('/')}/nnrf-nfm/v1/nf-instances/{nf_instance_id}"
    
    # Find a pod to execute from if not provided
    if not pod_name:
        pod_name, error = KubernetesClient.find_pod_for_exec(namespace)
        if error:
            return error
    
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
            # Use Pydantic model for response parsing
            nf_instance = NFInstance.parse_obj(nf_data)
            # Format the response
            formatted_output = format_nf_details(nf_instance)
            return formatted_output
        except json.JSONDecodeError as e:
            return f"Error parsing NRF response: {str(e)}\nResponse: {result.output}"
        except Exception as e:
            logger.error(f"Error parsing NF instance data: {str(e)}")
            return f"Error parsing NF instance data: {str(e)}\nResponse: {result.output}"
        
    except Exception as e:
        logger.error(f"Error executing curl command in pod: {str(e)}")
        return f"Error executing curl command in pod: {str(e)}"

def get_nf_instances(nrf_endpoint, nf_type, pod_name=None, namespace="pcf"):
    """Get all instances of a specific NF type"""
    # First discover NFs by type
    discovery_result = discover_nfs(nrf_endpoint, nf_type, pod_name, namespace)
    
    # If there's an error, return it
    if discovery_result.startswith("Error"):
        return discovery_result
    
    return discovery_result

def format_nf_discovery_results(discovery_response: NFDiscoveryResponse, nf_type=None):
    """Format NF discovery results in a readable format using Pydantic models"""
    nf_instances = discovery_response.nf_instances
    
    if not nf_instances:
        if nf_type:
            return f"No {nf_type} instances found."
        else:
            return "No NF instances found."
    
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
            for service in instance.nf_services:
                services.append(service.service_name)
        
        services_str = ", ".join(services) if services else "None"
        
        # Add row to table
        output += f"{instance.nf_type} | {instance.nf_instance_id[:8]}... | {instance.nf_status} | {fqdn} | {heartbeat} | {services_str}\n"
    
    return output

def format_nf_details(instance: NFInstance):
    """Format detailed NF information in a readable format using Pydantic models"""
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
    """Main function that parses arguments and executes the script"""
    parser = argparse.ArgumentParser(description="Query NRF for Network Functions")
    
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
    else:
        # Default arguments for CLI usage
        parser.add_argument("action", choices=["discover", "get_nf", "get_instances"], 
                          help="Action to perform")
        parser.add_argument("--nf-type", help="NF Type to search for")
        parser.add_argument("--nrf-endpoint", help="NRF endpoint URL")
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
    
    # If no pod specified, try to find one automatically
    if not pod_name:
        pod_name, error = KubernetesClient.find_pod_for_exec(exec_namespace)
        if error:
            print(f"Warning: Could not find a pod for execution: {error}")
            print("Will attempt to find a pod at execution time.")
    
    # Execute the requested action
    if action == "discover":
        result = discover_nfs(nrf_endpoint, nf_type, pod_name, exec_namespace)
    elif action == "get_nf":
        nf_instance_id = arguments.get("nf_instance_id")
        if not nf_instance_id:
            result = "Error: Missing required parameter 'nf_instance_id' for 'get_nf' action"
        else:
            result = get_nf(nrf_endpoint, nf_instance_id, pod_name, exec_namespace)
    elif action == "get_instances":
        if not nf_type:
            result = "Error: Missing required parameter 'nf_type' for 'get_instances' action"
        else:
            result = get_nf_instances(nrf_endpoint, nf_type, pod_name, exec_namespace)
    else:
        result = f"Unknown action: {action}"
    
    print(result)

if __name__ == "__main__":
    main()
