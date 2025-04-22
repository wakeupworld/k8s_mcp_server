#!/usr/bin/env python3
"""
Kubernetes MCP Server using the official MCP SDK

This server implements the Model Context Protocol (MCP) to
allow interaction with Kubernetes clusters and can call
external scripts for specialized operations.
"""

import os
import sys
import logging
import signal
from typing import Optional, Dict, Any, List

# Find the root directory for proper imports
script_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(script_dir)
sys.path.append(root_dir)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("k8s-mcp-sdk-server")

try:
    # Import the MCP SDK - requires Python 3.10+
    from mcp.server.fastmcp import FastMCP, Context
    
    # Import the original kubernetes utils
    from kubectl_utils import KubernetesClient
except ImportError as e:
    print(f"ERROR: Failed to import required modules: {e}")
    print("\nMake sure you have Python 3.10+ and the MCP SDK installed:")
    print("  pip install git+https://github.com/modelcontextprotocol/python-sdk.git")
    print("\nOr create a virtual environment:")
    print("  python3.10 -m venv mcp_env_py310")
    print("  source mcp_env_py310/bin/activate")
    print("  pip install git+https://github.com/modelcontextprotocol/python-sdk.git")
    sys.exit(1)

# Check if kubectl is available
try:
    import subprocess
    kubectl_version = subprocess.run(
        ["kubectl", "version", "--client", "--output=json"],
        capture_output=True,
        text=True,
        check=False
    )
    
    if kubectl_version.returncode != 0:
        print(f"ERROR: kubectl not found or error checking version: {kubectl_version.stderr}")
        sys.exit(1)
        
    logger.info("kubectl found. Starting MCP server...")
except Exception as e:
    print(f"Error checking kubectl: {str(e)}")
    sys.exit(1)

# Create a FastMCP server
mcp = FastMCP("Kubernetes Manager")

# Define a function to get pods
@mcp.tool()
def get_pods(namespace: str = "default") -> str:
    """Get a list of pods in the specified namespace"""
    from tabulate import tabulate
    
    # Use the KubernetesClient's Pydantic model approach
    pods = KubernetesClient.get_pods(namespace=namespace)
    
    if not pods:
        return f"Error fetching pods in namespace '{namespace}'"
    
    if not pods.items:
        return f"No pods found in namespace '{namespace}'"
    
    # Format the data as a table
    table_data = []
    for pod in pods.items:
        name = pod.metadata.name
        status = pod.status.phase
        
        # Get ready count
        ready_containers = sum(1 for c in (pod.status.container_statuses or []) if c.ready)
        total_containers = len(pod.spec.containers)
        ready = f"{ready_containers}/{total_containers}"
        
        # Get age
        import datetime
        from dateutil import parser
        created = parser.isoparse(pod.metadata.creation_timestamp)
        now = datetime.datetime.now(datetime.timezone.utc)
        age = now - created
        
        if age.days > 0:
            age_str = f"{age.days}d"
        else:
            hours = age.seconds // 3600
            minutes = (age.seconds % 3600) // 60
            if hours > 0:
                age_str = f"{hours}h{minutes}m"
            else:
                age_str = f"{minutes}m"
        
        table_data.append([name, ready, status, age_str])
    
    headers = ["NAME", "READY", "STATUS", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def get_services(namespace: str = "default") -> str:
    """Get a list of services in the specified namespace"""
    from tabulate import tabulate
    
    # Use the KubernetesClient's Pydantic model approach
    services = KubernetesClient.get_services(namespace=namespace)
    
    if not services:
        return f"Error fetching services in namespace '{namespace}'"
    
    if not services.items:
        return f"No services found in namespace '{namespace}'"
    
    # Format the data as a table
    table_data = []
    for svc in services.items:
        name = svc.metadata.name
        svc_type = svc.spec.type
        cluster_ip = svc.spec.cluster_ip
        
        # Get external IP if available
        external_ip = "none"
        if hasattr(svc, "status") and hasattr(svc.status, "load_balancer") and hasattr(svc.status.load_balancer, "ingress"):
            ingress = svc.status.load_balancer.ingress
            if ingress and hasattr(ingress[0], "ip"):
                external_ip = ingress[0].ip
            elif ingress and hasattr(ingress[0], "hostname"):
                external_ip = ingress[0].hostname
        
        # Format ports
        ports = []
        for port in svc.spec.ports:
            port_str = f"{port.port}"
            if hasattr(port, "target_port"):
                port_str += f":{port.target_port}"
            if hasattr(port, "node_port") and port.node_port:
                port_str += f":{port.node_port}"
            ports.append(f"{port_str}/{port.protocol}")
        ports_str = ",".join(ports)
        
        # Get age
        import datetime
        from dateutil import parser
        created = parser.isoparse(svc.metadata.creation_timestamp)
        now = datetime.datetime.now(datetime.timezone.utc)
        age = now - created
        
        if age.days > 0:
            age_str = f"{age.days}d"
        else:
            hours = age.seconds // 3600
            minutes = (age.seconds % 3600) // 60
            if hours > 0:
                age_str = f"{hours}h{minutes}m"
            else:
                age_str = f"{minutes}m"
        
        table_data.append([name, svc_type, cluster_ip, external_ip, ports_str, age_str])
    
    headers = ["NAME", "TYPE", "CLUSTER-IP", "EXTERNAL-IP", "PORT(S)", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def get_deployments(namespace: str = "default") -> str:
    """Get a list of deployments in the specified namespace"""
    from tabulate import tabulate
    
    # Use the KubernetesClient's Pydantic model approach
    deployments = KubernetesClient.get_deployments(namespace=namespace)
    
    if not deployments:
        return f"Error fetching deployments in namespace '{namespace}'"
    
    if not deployments.items:
        return f"No deployments found in namespace '{namespace}'"
    
    # Format the data as a table
    table_data = []
    for deploy in deployments.items:
        name = deploy.metadata.name
        
        # Get ready replicas
        ready = f"{deploy.status.ready_replicas or 0}/{deploy.spec.replicas}"
        up_to_date = deploy.status.updated_replicas or 0
        available = deploy.status.available_replicas or 0
        
        # Get age
        import datetime
        from dateutil import parser
        created = parser.isoparse(deploy.metadata.creation_timestamp)
        now = datetime.datetime.now(datetime.timezone.utc)
        age = now - created
        
        if age.days > 0:
            age_str = f"{age.days}d"
        else:
            hours = age.seconds // 3600
            minutes = (age.seconds % 3600) // 60
            if hours > 0:
                age_str = f"{hours}h{minutes}m"
            else:
                age_str = f"{minutes}m"
        
        table_data.append([name, ready, str(up_to_date), str(available), age_str])
    
    headers = ["NAME", "READY", "UP-TO-DATE", "AVAILABLE", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def get_namespaces() -> str:
    """Get a list of all namespaces in the cluster"""
    from tabulate import tabulate
    
    # Use the KubernetesClient's Pydantic model approach
    namespaces = KubernetesClient.get_namespaces()
    
    if not namespaces:
        return "Error fetching namespaces"
    
    if not namespaces.items:
        return "No namespaces found"
    
    # Format the data as a table
    table_data = []
    for ns in namespaces.items:
        name = ns.metadata.name
        status = ns.status.phase
        
        # Get age
        import datetime
        from dateutil import parser
        created = parser.isoparse(ns.metadata.creation_timestamp)
        now = datetime.datetime.now(datetime.timezone.utc)
        age = now - created
        
        if age.days > 0:
            age_str = f"{age.days}d"
        else:
            hours = age.seconds // 3600
            minutes = (age.seconds % 3600) // 60
            if hours > 0:
                age_str = f"{hours}h{minutes}m"
            else:
                age_str = f"{minutes}m"
        
        table_data.append([name, status, age_str])
    
    headers = ["NAME", "STATUS", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def describe_resource(resource_type: str, resource_name: str, namespace: str = "default") -> str:
    """Describe a Kubernetes resource in detail"""
    result = KubernetesClient.execute_kubectl(["describe", resource_type, resource_name, "-n", namespace])
    
    if not result.success:
        return f"Error describing resource: {result.error}"
    
    return result.output

@mcp.tool()
def get_pod_logs(pod_name: str, namespace: str = "default", container: Optional[str] = None, 
                tail_lines: int = 100) -> str:
    """Get logs from a pod in the specified namespace"""
    cmd = ["logs", pod_name, "-n", namespace, f"--tail={tail_lines}"]
    
    if container:
        cmd.extend(["-c", container])
    
    result = KubernetesClient.execute_kubectl(cmd)
    
    if not result.success:
        return f"Error fetching logs: {result.error}"
    
    return result.output

@mcp.tool()
def create_namespace(namespace: str) -> str:
    """Create a new namespace in the Kubernetes cluster"""
    result = KubernetesClient.execute_kubectl(["create", "namespace", namespace])
    
    if not result.success:
        return f"Error creating namespace: {result.error}"
    
    return result.output

@mcp.tool()
def delete_resource(resource_type: str, resource_name: str, namespace: str = "default") -> str:
    """Delete a Kubernetes resource"""
    result = KubernetesClient.execute_kubectl(["delete", resource_type, resource_name, "-n", namespace])
    
    if not result.success:
        return f"Error deleting resource: {result.error}"
    
    return result.output

@mcp.tool()
def scale_deployment(deployment_name: str, replicas: int, namespace: str = "default") -> str:
    """Scale a deployment to the specified number of replicas"""
    result = KubernetesClient.execute_kubectl(["scale", "deployment", deployment_name, 
                                            f"--replicas={replicas}", "-n", namespace])
    
    if not result.success:
        return f"Error scaling deployment: {result.error}"
    
    return result.output

@mcp.tool()
def get_events(namespace: Optional[str] = None) -> str:
    """Get events from the Kubernetes cluster"""
    cmd = ["get", "events", "--sort-by=.lastTimestamp"]
    
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")
    
    result = KubernetesClient.execute_kubectl(cmd)
    
    if not result.success:
        return f"Error fetching events: {result.error}"
    
    return result.output

@mcp.tool()
def get_current_context() -> str:
    """Get the current kubectl context"""
    result = KubernetesClient.execute_kubectl(["config", "current-context"])
    
    if not result.success:
        return f"Error getting current context: {result.error}"
    
    return result.output

@mcp.tool()
def get_available_contexts() -> str:
    """Get the list of available kubectl contexts"""
    result = KubernetesClient.execute_kubectl(["config", "get-contexts", "-o", "name"])
    
    if not result.success:
        return f"Error getting available contexts: {result.error}"
    
    contexts = result.output.strip().split('\n')
    return "\n".join(contexts)

@mcp.tool()
def switch_context(context_name: str) -> str:
    """Switch the kubectl context"""
    result = KubernetesClient.execute_kubectl(["config", "use-context", context_name])
    
    if not result.success:
        return f"Error switching context: {result.error}"
    
    return result.output

# Add a resource example
@mcp.resource("k8s://namespaces/{namespace}/pods")
def get_pods_resource(namespace: str = "default") -> str:
    """Get pods information as a resource"""
    result = KubernetesClient.execute_kubectl(["get", "pods", "-n", namespace, "-o", "json"])
    
    if not result.success:
        return f"Error fetching pods: {result.error}"
    
    return str(result.output)

# Register scripts directory
scripts_dir = os.environ.get("SCRIPTS_DIR")
if not scripts_dir:
    scripts_dir = os.path.join(root_dir, "scripts")
    if not os.path.exists(scripts_dir):
        os.makedirs(scripts_dir)
        logger.info(f"Created scripts directory: {scripts_dir}")

logger.info(f"Using scripts directory: {scripts_dir}")

# Register scripts (this would need to be expanded to match the original server's script handling)
def register_scripts():
    """Register scripts as tools"""
    if not os.path.exists(scripts_dir):
        logger.warning(f"Scripts directory {scripts_dir} does not exist.")
        return
    
    logger.info(f"Scanning for scripts in: {scripts_dir}")
    
    # List Python scripts in the scripts directory
    for filename in os.listdir(scripts_dir):
        if filename.endswith('.py'):
            script_path = os.path.join(scripts_dir, filename)
            script_name = filename[:-3]  # Remove .py extension
            
            logger.info(f"Found script: {script_name} at {script_path}")
            
            # Define a closure to capture the current script_path and script_name
            def create_script_runner(script_path, script_name):
                @mcp.tool(name=f"script_{script_name}")
                def run_script(**kwargs) -> str:
                    """Run an external script with arguments"""
                    import tempfile
                    import json
                    import subprocess
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp:
                        json.dump(kwargs, temp)
                        temp_filename = temp.name
                    
                    try:
                        result = subprocess.run(
                            [sys.executable, script_path, "--args-file", temp_filename],
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=300  # 5 minute timeout
                        )
                        
                        if result.returncode != 0:
                            return f"Script execution failed: {result.stderr}"
                        
                        return result.stdout
                    finally:
                        os.unlink(temp_filename)
                
                return run_script
            
            # Create and register the tool for this script
            script_tool = create_script_runner(script_path, script_name)
            # The tool is already registered with the decorator, no need to register again

# Register available scripts
register_scripts()

# Handler function for graceful shutdown
def handle_sigterm(signum, frame):
    """Handle termination signal"""
    logger.info("Received termination signal. Shutting down gracefully...")
    sys.exit(0)

# Run the server
if __name__ == "__main__":
    import argparse
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_sigterm)  # Ctrl+C
    signal.signal(signal.SIGTERM, handle_sigterm)  # Terminal 
    
    parser = argparse.ArgumentParser(description="Kubernetes MCP Server using MCP SDK")
    parser.add_argument("--dev", action="store_true", help="Run in development mode")
    parser.add_argument("--dev-port", type=int, default=8000, help="Development server port")
    args = parser.parse_args()
    
    try:
        if args.dev:
            # Development mode runs a web server
            logger.info(f"Starting development server on port {args.dev_port}")
            logger.info("Press Ctrl+C to exit")
            mcp.run_dev(port=args.dev_port)
        else:
            # Normal mode runs stdio server
            logger.info("Starting MCP server (stdio transport)")
            logger.info("Press Ctrl+C to exit")
            mcp.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"Error running MCP server: {str(e)}")
    finally:
        logger.info("MCP server shutdown complete") 