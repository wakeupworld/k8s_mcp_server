#!/usr/bin/env python3
"""
Kubernetes MCP Server using the official MCP SDK

This server implements the Model Context Protocol (MCP) to
allow interaction with Kubernetes clusters and can call
external scripts for specialized operations.

Available Tools:
  get_pods: Get pods in a namespace with detailed status
  get_services: Get services in a namespace with IP and port details
  get_deployments: Get deployments in a namespace with replica status
  get_namespaces: Get all namespaces in the cluster
  describe_resource: Get detailed information about a specific resource
  get_pod_logs: Get logs from a specific pod or container
  create_namespace: Create a new namespace in the cluster
  delete_resource: Delete a specific Kubernetes resource
  scale_deployment: Change the number of replicas for a deployment
  get_events: Get recent events from the cluster
  get_current_context: Get the active kubectl context
  get_available_contexts: List all available kubectl contexts
  switch_context: Change the active kubectl context
  list_scripts: List all available scripts with their parameters
"""

import os
import sys
import logging
import signal
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

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

# Try to import pydantic, install if not available
try:
    from mcp.server.fastmcp import FastMCP, Context
    
    # Import the original kubernetes utils
    from kubectl_utils import KubernetesClient, format_resource_age
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

# Check if tabulate is installed, if not, install it
try:
    import tabulate
except ImportError:
    print("Installing tabulate package...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate"])
    import tabulate

# Check if dateutil is installed, if not, install it
try:
    import dateutil
except ImportError:
    print("Installing python-dateutil package...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-dateutil"])
    import dateutil

# Create a FastMCP server
mcp = FastMCP("Kubernetes Manager")

# Helper functions
def format_age(creation_timestamp):
    """Format a resource age from its creation timestamp"""
    # Try to use the existing utility from kubectl_utils if possible
    try:
        return format_resource_age(creation_timestamp)
    except:
        # Fallback to manual calculation
        try:
            created = dateutil.parser.isoparse(creation_timestamp)
            now = datetime.datetime.now(timezone.utc)
            age = now - created
            
            if age.days > 0:
                return f"{age.days}d"
            else:
                hours = age.seconds // 3600
                minutes = (age.seconds % 3600) // 60
                if hours > 0:
                    return f"{hours}h{minutes}m"
                else:
                    return f"{minutes}m"
        except Exception as e:
            logger.error(f"Error formatting age: {e}")
            return "Unknown"

# Define a function to get pods
@mcp.tool()
def get_pods(namespace: str = "default") -> str:
    """
    Get a list of pods in the specified namespace.
    
    Displays pods with their status, readiness, and age information in a 
    nicely formatted table similar to 'kubectl get pods'.
    
    Parameters:
        namespace: The Kubernetes namespace to search in (default: "default")
        
    Returns:
        A formatted table of pods with columns for NAME, READY, STATUS, and AGE
    """
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
        age_str = format_age(pod.metadata.creation_timestamp)
        
        table_data.append([name, ready, status, age_str])
    
    headers = ["NAME", "READY", "STATUS", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def get_services(namespace: str = "default") -> str:
    """
    Get a list of services in the specified namespace.
    
    Displays services with type, IP addresses, ports, and age information
    in a nicely formatted table similar to 'kubectl get services'.
    
    Parameters:
        namespace: The Kubernetes namespace to search in (default: "default")
        
    Returns:
        A formatted table of services with columns for NAME, TYPE, CLUSTER-IP, 
        EXTERNAL-IP, PORT(S), and AGE
    """
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
        age_str = format_age(svc.metadata.creation_timestamp)
        
        table_data.append([name, svc_type, cluster_ip, external_ip, ports_str, age_str])
    
    headers = ["NAME", "TYPE", "CLUSTER-IP", "EXTERNAL-IP", "PORT(S)", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def get_deployments(namespace: str = "default") -> str:
    """
    Get a list of deployments in the specified namespace.
    
    Displays deployments with replica status and age information
    in a nicely formatted table similar to 'kubectl get deployments'.
    
    Parameters:
        namespace: The Kubernetes namespace to search in (default: "default")
        
    Returns:
        A formatted table of deployments with columns for NAME, READY, 
        UP-TO-DATE, AVAILABLE, and AGE
    """
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
        age_str = format_age(deploy.metadata.creation_timestamp)
        
        table_data.append([name, ready, str(up_to_date), str(available), age_str])
    
    headers = ["NAME", "READY", "UP-TO-DATE", "AVAILABLE", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def get_namespaces() -> str:
    """
    Get a list of all namespaces in the cluster.
    
    Displays all namespaces with their status and age information
    in a nicely formatted table similar to 'kubectl get namespaces'.
    
    Returns:
        A formatted table of namespaces with columns for NAME, STATUS, and AGE
    """
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
        age_str = format_age(ns.metadata.creation_timestamp)
        
        table_data.append([name, status, age_str])
    
    headers = ["NAME", "STATUS", "AGE"]
    return tabulate(table_data, headers=headers, tablefmt="plain")

@mcp.tool()
def describe_resource(resource_type: str, resource_name: str, namespace: str = "default") -> str:
    """
    Describe a Kubernetes resource in detail.
    
    Provides detailed information about a specific Kubernetes resource similar
    to running 'kubectl describe <resource_type> <resource_name>'.
    
    Parameters:
        resource_type: Type of the resource (e.g., pod, service, deployment)
        resource_name: Name of the specific resource to describe
        namespace: The Kubernetes namespace of the resource (default: "default")
        
    Returns:
        Detailed description of the specified resource
    """
    result = KubernetesClient.execute_kubectl(["describe", resource_type, resource_name, "-n", namespace])
    
    if not result.success:
        return f"Error describing resource: {result.error}"
    
    return result.output

@mcp.tool()
def get_pod_logs(pod_name: str, namespace: str = "default", container: Optional[str] = None, 
                tail_lines: int = 100) -> str:
    """
    Get logs from a pod in the specified namespace.
    
    Retrieves logs from a specific pod or container similar to
    'kubectl logs <pod_name> [-c <container>] [--tail=<tail_lines>]'.
    
    Parameters:
        pod_name: Name of the pod to get logs from
        namespace: The Kubernetes namespace of the pod (default: "default")
        container: Container name if the pod has multiple containers
        tail_lines: Number of lines to show from the end of the logs (default: 100)
        
    Returns:
        The logs from the specified pod or container
    """
    cmd = ["logs", pod_name, "-n", namespace, f"--tail={tail_lines}"]
    
    if container:
        cmd.extend(["-c", container])
    
    result = KubernetesClient.execute_kubectl(cmd)
    
    if not result.success:
        return f"Error fetching logs: {result.error}"
    
    return result.output

@mcp.tool()
def create_namespace(namespace: str) -> str:
    """
    Create a new namespace in the Kubernetes cluster.
    
    Creates a new namespace similar to running 'kubectl create namespace <namespace>'.
    
    Parameters:
        namespace: Name of the namespace to create
        
    Returns:
        Success or error message about namespace creation
    """
    result = KubernetesClient.execute_kubectl(["create", "namespace", namespace])
    
    if not result.success:
        return f"Error creating namespace: {result.error}"
    
    return result.output

@mcp.tool()
def delete_resource(resource_type: str, resource_name: str, namespace: str = "default") -> str:
    """
    Delete a Kubernetes resource.
    
    Deletes a specific Kubernetes resource similar to running
    'kubectl delete <resource_type> <resource_name>'.
    
    Parameters:
        resource_type: Type of the resource (e.g., pod, service, deployment)
        resource_name: Name of the specific resource to delete
        namespace: The Kubernetes namespace of the resource (default: "default")
        
    Returns:
        Success or error message about resource deletion
    """
    result = KubernetesClient.execute_kubectl(["delete", resource_type, resource_name, "-n", namespace])
    
    if not result.success:
        return f"Error deleting resource: {result.error}"
    
    return result.output

@mcp.tool()
def scale_deployment(deployment_name: str, replicas: int, namespace: str = "default") -> str:
    """
    Scale a deployment to the specified number of replicas.
    
    Changes the number of pods managed by a deployment similar to
    'kubectl scale deployment <deployment_name> --replicas=<replicas>'.
    
    Parameters:
        deployment_name: Name of the deployment to scale
        replicas: The target number of replicas to scale to
        namespace: The Kubernetes namespace of the deployment (default: "default")
        
    Returns:
        Success or error message about scaling the deployment
    """
    result = KubernetesClient.execute_kubectl(["scale", "deployment", deployment_name, 
                                            f"--replicas={replicas}", "-n", namespace])
    
    if not result.success:
        return f"Error scaling deployment: {result.error}"
    
    return result.output

@mcp.tool()
def get_events(namespace: Optional[str] = None) -> str:
    """
    Get events from the Kubernetes cluster.
    
    Lists recent events from the specified namespace or across all namespaces,
    similar to 'kubectl get events [--namespace=<namespace>]'.
    
    Parameters:
        namespace: Optional namespace to filter events (if None, shows all namespaces)
        
    Returns:
        A list of recent Kubernetes events, sorted by timestamp
    """
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
    """
    Get the current kubectl context.
    
    Shows the currently active kubectl context, similar to
    'kubectl config current-context'.
    
    Returns:
        The name of the current kubectl context
    """
    result = KubernetesClient.execute_kubectl(["config", "current-context"])
    
    if not result.success:
        return f"Error getting current context: {result.error}"
    
    return result.output

@mcp.tool()
def get_available_contexts() -> str:
    """
    Get the list of available kubectl contexts.
    
    Lists all available kubectl contexts, similar to
    'kubectl config get-contexts -o name'.
    
    Returns:
        A list of available kubectl context names
    """
    result = KubernetesClient.execute_kubectl(["config", "get-contexts", "-o", "name"])
    
    if not result.success:
        return f"Error getting available contexts: {result.error}"
    
    contexts = result.output.strip().split('\n')
    return "\n".join(contexts)

@mcp.tool()
def switch_context(context_name: str) -> str:
    """
    Switch the kubectl context.
    
    Changes the active kubectl context, similar to
    'kubectl config use-context <context_name>'.
    
    Parameters:
        context_name: Name of the context to switch to
        
    Returns:
        Success or error message about switching context
    """
    result = KubernetesClient.execute_kubectl(["config", "use-context", context_name])
    
    if not result.success:
        return f"Error switching context: {result.error}"
    
    return result.output

# Add a resource example
@mcp.resource("k8s://namespaces/{namespace}/pods")
def get_pods_resource(namespace: str = "default") -> str:
    """
    Get pods information as a resource.
    
    Provides pods information for a specific namespace in JSON format.
    
    Parameters:
        namespace: The Kubernetes namespace to search in
        
    Returns:
        JSON data about pods in the specified namespace
    """
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
            
            # Try to introspect script parameters by parsing the file
            script_params = detect_script_parameters(script_path)
            logger.info(f"Detected parameters for {script_name}: {script_params}")
            
            # Define a closure to capture the current script_path and script_name
            def create_script_runner(script_path, script_name, params):
                @mcp.tool(name=f"script_{script_name}")
                def run_script(**kwargs) -> str:
                    """Run an external script with arguments"""
                    import tempfile
                    import json
                    import subprocess
                    
                    # Validate parameters if we have param info
                    if params:
                        missing_required = []
                        for param_name, param_info in params.items():
                            if param_info.get('required', False) and param_name not in kwargs:
                                missing_required.append(param_name)
                        
                        if missing_required:
                            return f"Error: Missing required parameters: {', '.join(missing_required)}"
                    
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
                
                # Set docstring with parameter info if available
                if params:
                    param_docs = "\nParameters:\n"
                    for param_name, param_info in params.items():
                        required = " (Required)" if param_info.get('required', False) else ""
                        param_type = param_info.get('type', 'any')
                        description = param_info.get('description', '')
                        param_docs += f"  {param_name}: {param_type}{required} - {description}\n"
                    
                    run_script.__doc__ = f"Run the {script_name} script.{param_docs}"
                
                return run_script
            
            # Create and register the tool for this script
            script_tool = create_script_runner(script_path, script_name, script_params)
            # The tool is already registered with the decorator, no need to register again

def detect_script_parameters(script_path):
    """Try to detect script parameters by parsing the script file"""
    import re
    import ast
    
    params = {}
    
    try:
        # First try the AST approach for more accurate parsing
        with open(script_path, 'r') as f:
            script_content = f.read()
        
        try:
            tree = ast.parse(script_content)
            
            # Look for argparse
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and hasattr(node, 'func'):
                    # Check for argparse.add_argument calls
                    if (isinstance(node.func, ast.Attribute) and 
                        node.func.attr == 'add_argument' and 
                        len(node.args) > 0):
                        
                        # Get argument name
                        arg_name = None
                        for arg in node.args:
                            if isinstance(arg, ast.Str) and arg.s.startswith('--'):
                                arg_name = arg.s[2:]  # Remove '--'
                                break
                        
                        if not arg_name:
                            continue
                        
                        # Get metadata
                        required = False
                        arg_type = 'string'
                        description = ''
                        
                        for keyword in node.keywords:
                            if keyword.arg == 'required' and isinstance(keyword.value, ast.Constant):
                                required = keyword.value.value
                            elif keyword.arg == 'type':
                                if isinstance(keyword.value, ast.Name):
                                    if keyword.value.id == 'int':
                                        arg_type = 'integer'
                                    elif keyword.value.id == 'float':
                                        arg_type = 'number'
                                    elif keyword.value.id == 'bool':
                                        arg_type = 'boolean'
                            elif keyword.arg == 'help' and isinstance(keyword.value, ast.Str):
                                description = keyword.value.s
                        
                        params[arg_name] = {
                            'required': required,
                            'type': arg_type,
                            'description': description
                        }
            
            # If we found parameters via AST, return them
            if params:
                return params
        except SyntaxError:
            logger.warning(f"Failed to parse {script_path} with AST")
        
        # Fallback: Use regex to find arguments
        with open(script_path, 'r') as f:
            for line in f:
                # Look for argparse add_argument lines
                match = re.search(r'add_argument\([\'"]--([^\'"]+)[\'"]', line)
                if match:
                    arg_name = match.group(1)
                    required = 'required=True' in line
                    
                    # Try to determine type
                    arg_type = 'string'
                    if 'type=int' in line:
                        arg_type = 'integer'
                    elif 'type=float' in line:
                        arg_type = 'number'
                    elif 'type=bool' in line:
                        arg_type = 'boolean'
                    
                    # Try to extract description
                    help_match = re.search(r'help=[\'"]([^\'"]+)[\'"]', line)
                    description = help_match.group(1) if help_match else ''
                    
                    params[arg_name] = {
                        'required': required,
                        'type': arg_type,
                        'description': description
                    }
    except Exception as e:
        logger.error(f"Error detecting parameters for {script_path}: {e}")
    
    return params

# Register available scripts
register_scripts()

# Add a tool to list available scripts
@mcp.tool()
def list_scripts() -> str:
    """
    List all available scripts with their parameters.
    
    Scans the scripts directory and displays all available scripts
    with their detected parameters and descriptions.
    
    Returns:
        A formatted list of available scripts and their parameters
    """
    if not os.path.exists(scripts_dir):
        return f"No scripts directory found at {scripts_dir}"
    
    scripts = []
    for filename in os.listdir(scripts_dir):
        if filename.endswith('.py'):
            script_path = os.path.join(scripts_dir, filename)
            script_name = filename[:-3]  # Remove .py extension
            params = detect_script_parameters(script_path)
            
            # Format parameters info
            params_info = ""
            if params:
                for param_name, param_info in params.items():
                    required = "(Required)" if param_info.get('required', False) else "(Optional)"
                    param_type = param_info.get('type', 'string')
                    description = param_info.get('description', 'No description')
                    params_info += f"\n    - {param_name}: {param_type} {required} - {description}"
            else:
                params_info = "\n    No parameters detected"
            
            scripts.append(f"script_{script_name}{params_info}")
    
    if not scripts:
        return f"No Python scripts found in {scripts_dir}"
    
    scripts_list = "\n".join(scripts)
    return f"Available scripts:\n\n{scripts_list}"

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