# Kubernetes MCP Server

A flexible Machine Communication Protocol (MCP) server that provides Kubernetes management capabilities with support for custom extension scripts.

## Features

- Implements a minimal subset of the MCP protocol
- Provides a wide range of Kubernetes management operations
- Supports dynamic loading of custom extension scripts
- Clean, modular architecture for easy extensibility

## Directory Structure

- **bin/**: Contains main executable components
  - `kubernetes_mcp_server.py`: The main MCP server executable

- **scripts/**: Contains plugin scripts for the MCP server
  - `nrf-query-script.py`: Sample script for querying NRF service for Network Functions

## Prerequisites

- Python 3.9 or higher
- kubectl installed and configured
- Required Python packages (automatically installed if missing):
  - pydantic
  - tabulate

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/k8s-mcp-server.git
   cd k8s-mcp-server
   ```

2. (Optional) Create a virtual environment:
   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install pydantic tabulate
   ```

## Usage

### Running the MCP Server

Execute the MCP server from the `bin` directory:

```bash
cd bin
python3 kubernetes_mcp_server.py
```

The server will:
1. Check if kubectl is available
2. Discover and register scripts from the `scripts/` directory
3. Start listening for MCP protocol commands

### Available Tools

The MCP server provides the following built-in tools:

| Tool Name | Description |
|-----------|-------------|
| get_pods | Get a list of pods in the specified namespace |
| get_services | Get a list of services in the specified namespace |
| get_deployments | Get a list of deployments in the specified namespace |
| get_namespaces | Get a list of all namespaces in the cluster |
| describe_resource | Describe a Kubernetes resource in detail |
| get_pod_logs | Get logs from a pod in the specified namespace |
| create_namespace | Create a new namespace in the Kubernetes cluster |
| apply_yaml | Apply a YAML configuration to the Kubernetes cluster |
| get_current_context | Get the current kubectl context |
| get_available_contexts | Get the list of available kubectl contexts |
| switch_context | Switch the kubectl context |
| delete_resource | Delete a Kubernetes resource |
| scale_deployment | Scale a deployment to the specified number of replicas |
| get_events | Get events from the Kubernetes cluster |
| run_script | Run an external script with arguments |

Additionally, all scripts in the `scripts/` directory are automatically registered as tools with the prefix `script_`.

### Using a Script Directly

Scripts can be executed directly for testing or standalone usage:

```bash
cd scripts
python3 nrf-query-script.py --help
```

## Creating Custom Scripts

You can extend the MCP server's functionality by adding custom scripts to the `scripts/` directory.

### Script Requirements

1. Scripts must be Python files with a `.py` extension
2. Scripts should implement a `--metadata` flag that returns JSON describing the script and its parameters
3. Scripts should support receiving arguments via a JSON file with the `--args-file` flag

### Script Metadata Format

```json
{
  "description": "A brief description of what the script does",
  "parameters": {
    "param1": {
      "type": "string",
      "description": "Description of parameter 1"
    },
    "param2": {
      "type": "integer",
      "description": "Description of parameter 2"
    }
  }
}
```

### Script Template

Here's a basic template for creating a new script:

```python
#!/usr/bin/env python3
"""
Script Name

Brief description of what the script does.
"""

import argparse
import json
import sys
import os

# Script metadata - used by the MCP server for tool registration
SCRIPT_METADATA = {
    "description": "Description of what the script does",
    "parameters": {
        "param1": {
            "type": "string", 
            "description": "Description of parameter 1"
        },
        "param2": {
            "type": "integer", 
            "description": "Description of parameter 2"
        }
    }
}

def main():
    """Main function that parses arguments and executes the script"""
    parser = argparse.ArgumentParser(description="Description of the script")
    
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
        # Define arguments for CLI usage
        parser.add_argument("param1", help="Description of parameter 1")
        parser.add_argument("--param2", type=int, help="Description of parameter 2")
        cli_args = parser.parse_args()
        
        # Convert Namespace to dict
        arguments = {k: v for k, v in vars(cli_args).items() if v is not None}
    
    # Use your arguments here
    print(f"Got arguments: {arguments}")
    
    # Implement your script logic here
    
if __name__ == "__main__":
    main()
```

## Environment Variables

- `SCRIPTS_DIR`: Override the default scripts directory location
  ```
  SCRIPTS_DIR=/path/to/scripts python3 bin/kubernetes_mcp_server.py
  ```

## Architecture

The system consists of the following components:

1. **MCP Server**: Implements the MCP protocol and provides a bridge between tools and Kubernetes
2. **Kubernetes Client**: Handles direct interactions with kubectl
3. **Extension Scripts**: Provide specialized functionality through a simple plugin mechanism

The MCP server handles incoming commands using the following flow:
1. Receives a command through the MCP protocol
2. Routes the command to the appropriate built-in tool or extension script
3. Executes the operation
4. Returns the result through the MCP protocol

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 