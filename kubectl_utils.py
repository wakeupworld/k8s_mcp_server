#!/usr/bin/env python3
"""
Kubectl Utilities Module

Shared utilities for interacting with Kubernetes via kubectl commands.
This module is used by both the main MCP server and external scripts.
"""

import json
import logging
import subprocess
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime

# Try to import pydantic, install if not available
try:
    from pydantic import BaseModel, Field
except ImportError:
    import sys
    print("Installing required packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pydantic"])
    from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("kubectl-utils")

# Pydantic models for command responses
class KubectlCommandResult(BaseModel):
    """Represents the result of a kubectl command execution"""
    success: bool
    output: Optional[Union[str, Dict[str, Any], List[Any]]] = None
    error: Optional[str] = None

# Pydantic models for Kubernetes resources
class ObjectMeta(BaseModel):
    """Metadata common to most Kubernetes resources"""
    name: str
    namespace: Optional[str] = None
    uid: Optional[str] = None
    creation_timestamp: Optional[str] = Field(None, alias="creationTimestamp")
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None

# Pod-related models
class ContainerStatus(BaseModel):
    """Status information about a container in a pod"""
    name: str
    ready: bool
    restart_count: int = Field(0, alias="restartCount")
    image: str
    image_id: str = Field("", alias="imageID")
    container_id: Optional[str] = Field(None, alias="containerID")
    started: Optional[bool] = None

class Container(BaseModel):
    """Container specification in a pod"""
    name: str
    image: str
    ports: Optional[List[Dict[str, Any]]] = None
    resources: Optional[Dict[str, Any]] = None
    volume_mounts: Optional[List[Dict[str, Any]]] = Field(None, alias="volumeMounts")
    env: Optional[List[Dict[str, Any]]] = None
    args: Optional[List[str]] = None
    command: Optional[List[str]] = None

class PodStatus(BaseModel):
    """Status information about a pod"""
    phase: str
    pod_ip: Optional[str] = Field(None, alias="podIP")
    host_ip: Optional[str] = Field(None, alias="hostIP")
    start_time: Optional[str] = Field(None, alias="startTime")
    conditions: Optional[List[Dict[str, Any]]] = None
    container_statuses: Optional[List[ContainerStatus]] = Field(None, alias="containerStatuses")

class PodSpec(BaseModel):
    """Specification of a pod"""
    node_name: Optional[str] = Field(None, alias="nodeName")
    containers: List[Container]
    volumes: Optional[List[Dict[str, Any]]] = None
    service_account: Optional[str] = Field(None, alias="serviceAccount")

class Pod(BaseModel):
    """Kubernetes Pod resource"""
    metadata: ObjectMeta
    spec: PodSpec
    status: PodStatus

# Service-related models
class ServicePort(BaseModel):
    """Port specification in a service"""
    name: Optional[str] = None
    protocol: str
    port: int
    target_port: Union[int, str] = Field(alias="targetPort")
    node_port: Optional[int] = Field(None, alias="nodePort")

class ServiceSpec(BaseModel):
    """Specification of a service"""
    cluster_ip: str = Field(alias="clusterIP")
    type: str
    ports: List[ServicePort]
    selector: Optional[Dict[str, str]] = None
    external_name: Optional[str] = Field(None, alias="externalName")
    session_affinity: Optional[str] = Field(None, alias="sessionAffinity")

class Service(BaseModel):
    """Kubernetes Service resource"""
    metadata: ObjectMeta
    spec: ServiceSpec

# Deployment-related models
class DeploymentStrategy(BaseModel):
    """Strategy for deployment updates"""
    type: str
    rolling_update: Optional[Dict[str, Any]] = Field(None, alias="rollingUpdate")

class DeploymentSpec(BaseModel):
    """Specification of a deployment"""
    replicas: int
    selector: Dict[str, Any]
    template: Dict[str, Any]
    strategy: Optional[DeploymentStrategy] = None

class DeploymentStatus(BaseModel):
    """Status information about a deployment"""
    replicas: int
    available_replicas: Optional[int] = Field(0, alias="availableReplicas")
    ready_replicas: Optional[int] = Field(0, alias="readyReplicas")
    updated_replicas: Optional[int] = Field(0, alias="updatedReplicas")
    unavailable_replicas: Optional[int] = Field(0, alias="unavailableReplicas")

class Deployment(BaseModel):
    """Kubernetes Deployment resource"""
    metadata: ObjectMeta
    spec: DeploymentSpec
    status: DeploymentStatus

# Namespace model
class NamespaceStatus(BaseModel):
    """Status information about a namespace"""
    phase: str

class Namespace(BaseModel):
    """Kubernetes Namespace resource"""
    metadata: ObjectMeta
    status: NamespaceStatus

# List models
class PodList(BaseModel):
    """List of Pod resources"""
    items: List[Pod]

class ServiceList(BaseModel):
    """List of Service resources"""
    items: List[Service]

class DeploymentList(BaseModel):
    """List of Deployment resources"""
    items: List[Deployment]

class NamespaceList(BaseModel):
    """List of Namespace resources"""
    items: List[Namespace]

class ResourceAge(BaseModel):
    """Model for representing age of Kubernetes resources"""
    days: int = 0
    hours: int = 0
    minutes: int = 0
    
    def __str__(self) -> str:
        if self.days > 0:
            return f"{self.days}d"
        elif self.hours > 0:
            return f"{self.hours}h"
        else:
            return f"{self.minutes}m"

class KubernetesClient:
    """Helper class for executing kubectl commands"""

    @staticmethod
    def execute_kubectl(args: List[str]) -> KubectlCommandResult:
        """Execute kubectl command with given arguments and return the result"""
        try:
            logger.info(f"Executing kubectl command: kubectl {' '.join(args)}")
            
            # Check if JSON output is expected
            json_output = "-o" in args and "json" in args
            
            result = subprocess.run(
                ["kubectl"] + args,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                return KubectlCommandResult(
                    success=False,
                    error=result.stderr.strip(),
                    output=result.stdout.strip()
                )
            
            # Parse JSON output if expected
            if json_output and result.stdout:
                try:
                    parsed_output = json.loads(result.stdout)
                    return KubectlCommandResult(
                        success=True,
                        output=parsed_output,
                        error=None
                    )
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON output: {e}")
                    return KubectlCommandResult(
                        success=False,
                        error=f"Failed to parse JSON output: {e}",
                        output=result.stdout.strip()
                    )
            
            return KubectlCommandResult(
                success=True,
                output=result.stdout.strip(),
                error=None
            )
        except Exception as e:
            logger.error(f"Error executing kubectl command: {str(e)}")
            return KubectlCommandResult(
                success=False,
                error=str(e),
                output=None
            )

    @staticmethod
    def get_resource(resource_type: str, resource_name: Optional[str] = None, 
                   namespace: Optional[str] = None, output_format: str = "json") -> KubectlCommandResult:
        """Get a Kubernetes resource or list of resources"""
        cmd = ["get", resource_type]
        
        if resource_name:
            cmd.append(resource_name)
        
        if namespace:
            cmd.extend(["-n", namespace])
        
        cmd.extend(["-o", output_format])
        
        return KubernetesClient.execute_kubectl(cmd)
    
    @staticmethod
    def apply_yaml_file(file_path: str) -> KubectlCommandResult:
        """Apply a YAML file to the Kubernetes cluster"""
        return KubernetesClient.execute_kubectl(["apply", "-f", file_path])
    
    @staticmethod
    def describe_resource(resource_type: str, resource_name: str, namespace: Optional[str] = None) -> KubectlCommandResult:
        """Describe a Kubernetes resource"""
        cmd = ["describe", resource_type, resource_name]
        
        if namespace:
            cmd.extend(["-n", namespace])
        
        return KubernetesClient.execute_kubectl(cmd)
    
    @staticmethod
    def delete_resource(resource_type: str, resource_name: str, namespace: Optional[str] = None) -> KubectlCommandResult:
        """Delete a Kubernetes resource"""
        cmd = ["delete", resource_type, resource_name]
        
        if namespace:
            cmd.extend(["-n", namespace])
        
        return KubernetesClient.execute_kubectl(cmd)
    
    @staticmethod
    def get_current_context() -> KubectlCommandResult:
        """Get the current kubectl context"""
        return KubernetesClient.execute_kubectl(["config", "current-context"])
    
    @staticmethod
    def get_pod_logs(pod_name: str, namespace: Optional[str] = None, 
                    container: Optional[str] = None, tail_lines: int = 100) -> KubectlCommandResult:
        """Get logs from a pod"""
        cmd = ["logs", pod_name]
        
        if namespace:
            cmd.extend(["-n", namespace])
        
        if container:
            cmd.extend(["-c", container])
        
        cmd.append(f"--tail={tail_lines}")
        
        return KubernetesClient.execute_kubectl(cmd)
    
    @staticmethod
    def scale_deployment(deployment_name: str, replicas: int, namespace: Optional[str] = None) -> KubectlCommandResult:
        """Scale a deployment to the specified number of replicas"""
        cmd = ["scale", "deployment", deployment_name, f"--replicas={replicas}"]
        
        if namespace:
            cmd.extend(["-n", namespace])
        
        return KubernetesClient.execute_kubectl(cmd)
    
    @staticmethod
    def get_pods(namespace: Optional[str] = None) -> Optional[PodList]:
        """Get pods as typed Pydantic objects"""
        result = KubernetesClient.get_resource("pods", namespace=namespace)
        if result.success and isinstance(result.output, dict):
            try:
                return PodList.parse_obj(result.output)
            except Exception as e:
                logger.error(f"Error parsing pod list: {str(e)}")
        return None
    
    @staticmethod
    def get_services(namespace: Optional[str] = None) -> Optional[ServiceList]:
        """Get services as typed Pydantic objects"""
        result = KubernetesClient.get_resource("services", namespace=namespace)
        if result.success and isinstance(result.output, dict):
            try:
                return ServiceList.parse_obj(result.output)
            except Exception as e:
                logger.error(f"Error parsing service list: {str(e)}")
        return None
    
    @staticmethod
    def get_deployments(namespace: Optional[str] = None) -> Optional[DeploymentList]:
        """Get deployments as typed Pydantic objects"""
        result = KubernetesClient.get_resource("deployments", namespace=namespace)
        if result.success and isinstance(result.output, dict):
            try:
                return DeploymentList.parse_obj(result.output)
            except Exception as e:
                logger.error(f"Error parsing deployment list: {str(e)}")
        return None
    
    @staticmethod
    def get_namespaces() -> Optional[NamespaceList]:
        """Get namespaces as typed Pydantic objects"""
        result = KubernetesClient.get_resource("namespaces")
        if result.success and isinstance(result.output, dict):
            try:
                return NamespaceList.parse_obj(result.output)
            except Exception as e:
                logger.error(f"Error parsing namespace list: {str(e)}")
        return None
    
    @staticmethod
    def find_pod_for_exec(namespace: str, label_selector: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """Find a suitable pod in the namespace to execute commands from"""
        logger.info(f"Looking for a suitable pod in namespace {namespace}")
        
        cmd = ["get", "pods", "-n", namespace]
        
        if label_selector:
            cmd.extend(["-l", label_selector])
            
        cmd.extend(["-o", "json"])
        
        result = KubernetesClient.execute_kubectl(cmd)
        
        if not result.success or not isinstance(result.output, dict):
            error = f"Error getting pods in namespace {namespace}: {result.error}"
            logger.error(error)
            return None, error
        
        pods = result.output.get("items", [])
        
        if not pods:
            error = f"No pods found in namespace {namespace}"
            logger.error(error)
            return None, error
        
        # Find a running pod
        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "")
            pod_status = pod.get("status", {}).get("phase", "")
            
            if pod_status == "Running":
                logger.info(f"Found suitable pod {pod_name} in namespace {namespace}")
                return pod_name, None
        
        error = f"No running pods found in namespace {namespace}"
        logger.error(error)
        return None, error
    
    @staticmethod
    def exec_command_in_pod(pod_name: str, namespace: str, command: str, container: Optional[str] = None) -> KubectlCommandResult:
        """Execute a command in a pod and return the result"""
        logger.info(f"Executing command in pod {pod_name} in namespace {namespace}: {command}")
        
        cmd = ["exec", "-n", namespace, pod_name]
        
        if container:
            cmd.extend(["-c", container])
            
        cmd.extend(["--", "sh", "-c", command])
        
        return KubernetesClient.execute_kubectl(cmd)
    
    @staticmethod
    def curl_from_pod(pod_name: str, namespace: str, url: str, method: str = "GET", 
                     headers: Optional[Dict[str, str]] = None, data: Optional[str] = None,
                     container: Optional[str] = None) -> KubectlCommandResult:
        """Execute a curl command from within a pod to access cluster-internal services"""
        # Build the curl command with appropriate options
        curl_cmd = ["curl", "-s", "-X", method, url]
        
        # Add headers
        if headers:
            for k, v in headers.items():
                curl_cmd.extend(["-H", f"{k}: {v}"])
        else:
            # Default headers for JSON APIs
            curl_cmd.extend(["-H", "Accept: application/json"])
        
        # Add data if provided (for POST, PUT, etc.)
        if data:
            curl_cmd.extend(["-d", data])
        
        # Convert to a single string command for sh -c
        curl_cmd_str = " ".join([f"'{arg}'" if ' ' in arg else arg for arg in curl_cmd])
        
        # Execute the command in the pod
        return KubernetesClient.exec_command_in_pod(pod_name, namespace, curl_cmd_str, container)

# Helper functions for handling common Kubernetes resources
def calculate_resource_age(creation_timestamp: Optional[str]) -> Optional[ResourceAge]:
    """Calculate a Kubernetes resource age from its creation timestamp"""
    if not creation_timestamp:
        return None
    
    try:
        created = datetime.strptime(
            creation_timestamp, 
            "%Y-%m-%dT%H:%M:%SZ"
        )
        now = datetime.utcnow()
        delta = now - created
        
        return ResourceAge(
            days=delta.days,
            hours=delta.seconds // 3600,
            minutes=(delta.seconds % 3600) // 60
        )
    except Exception as e:
        logger.error(f"Error calculating age: {str(e)}")
        return None

def format_resource_age(creation_timestamp: Optional[str]) -> str:
    """Format a Kubernetes resource age from its creation timestamp"""
    age = calculate_resource_age(creation_timestamp)
    return str(age) if age else "Unknown"

# Usage example
if __name__ == "__main__":
    import sys
    
    # Example of using the Pydantic models to interact with Kubernetes
    def demo_kubernetes_models():
        print("\n===== Kubernetes Client with Pydantic Models Demo =====\n")
        
        # Get current context
        context_result = KubernetesClient.get_current_context()
        print(f"Current context: {context_result.output if context_result.success else 'Unknown'}")
        
        # Get pods with typed models
        print("\nFetching pods...\n")
        pods = KubernetesClient.get_pods(namespace="default")
        if pods and pods.items:
            print(f"Found {len(pods.items)} pods in default namespace:")
            for pod in pods.items:
                age = format_resource_age(pod.metadata.creation_timestamp)
                status = pod.status.phase
                ready_containers = sum(1 for c in (pod.status.container_statuses or []) if c.ready)
                total_containers = len(pod.status.container_statuses or [])
                
                print(f"  • {pod.metadata.name}")
                print(f"    - Status: {status}")
                print(f"    - Ready: {ready_containers}/{total_containers}")
                print(f"    - Age: {age}")
                print(f"    - IP: {pod.status.pod_ip or 'None'}")
                print()
        else:
            print("No pods found or error fetching pods")
        
        # Get services with typed models
        print("\nFetching services...\n")
        services = KubernetesClient.get_services(namespace="default")
        if services and services.items:
            print(f"Found {len(services.items)} services in default namespace:")
            for svc in services.items:
                age = format_resource_age(svc.metadata.creation_timestamp)
                
                # Format ports
                ports_str = ", ".join([
                    f"{p.port}:{p.node_port or p.port}/{p.protocol}" 
                    for p in svc.spec.ports
                ])
                
                print(f"  • {svc.metadata.name}")
                print(f"    - Type: {svc.spec.type}")
                print(f"    - Cluster IP: {svc.spec.cluster_ip}")
                print(f"    - Ports: {ports_str}")
                print(f"    - Age: {age}")
                print()
        else:
            print("No services found or error fetching services")
        
        # Get deployments with typed models
        print("\nFetching deployments...\n")
        deployments = KubernetesClient.get_deployments(namespace="default")
        if deployments and deployments.items:
            print(f"Found {len(deployments.items)} deployments in default namespace:")
            for deploy in deployments.items:
                age = format_resource_age(deploy.metadata.creation_timestamp)
                
                print(f"  • {deploy.metadata.name}")
                print(f"    - Replicas: {deploy.status.available_replicas}/{deploy.spec.replicas}")
                print(f"    - Age: {age}")
                
                # Show the image of the first container in the pod template
                if deploy.spec.template and isinstance(deploy.spec.template, dict):
                    template = deploy.spec.template
                    if "spec" in template and "containers" in template["spec"] and template["spec"]["containers"]:
                        container = template["spec"]["containers"][0]
                        if isinstance(container, dict) and "image" in container:
                            print(f"    - Image: {container['image']}")
                print()
        else:
            print("No deployments found or error fetching deployments")
    
    # Run demo if argument is provided
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo_kubernetes_models()
    else:
        print("This module provides Kubernetes utilities with Pydantic models")
        print("Run with --demo argument to see a demonstration")
