# Kubernetes MCP Server

A flexible Machine Communication Protocol (MCP) server that provides Kubernetes management capabilities with support for custom extension scripts.

## Features

- Implements the Model Context Protocol (MCP) using the official MCP SDK
- Provides a wide range of Kubernetes management operations through tabular output
- Supports dynamic loading and auto-detection of custom extension scripts
- Automatic script parameter detection and validation
- Clean, modular architecture with Pydantic models for type safety

## Directory Structure

- **bin/**: Contains main executable components
  - `k8s_mcp_wrapper.py`: The main MCP server executable

- **scripts/**: Contains plugin scripts for the MCP server
  - Add your custom scripts here to extend functionality

## Prerequisites

- Python 3.10 or higher (required by MCP SDK)
- kubectl installed and configured
- Required Python packages (see requirements.txt)

## Installation

### Using pip

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/k8s-mcp-server.git
   cd k8s-mcp-server
   ```

2. (Optional) Create a virtual environment:
   ```
   python3.10 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

### Using uv (faster installation)

1. Install uv if not already installed:
   ```
   pip install uv
   ```

2. Clone the repository:
   ```
   git clone https://github.com/yourusername/k8s-mcp-server.git
   cd k8s-mcp-server
   ```

3. Create a virtual environment and install dependencies using uv:
   ```
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv pip install -r requirements.txt
   ```

## Usage

### Running the MCP Server

Execute the MCP server from the `bin` directory:

```bash
cd bin
python3 k8s_mcp_wrapper.py
```

For development mode with web server (useful for debugging):

```bash
cd bin
python3 k8s_mcp_wrapper.py --dev --dev-port 8000
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
| delete_resource | Delete a Kubernetes resource |
| scale_deployment | Scale a deployment to the specified number of replicas |
| get_events | Get events from the Kubernetes cluster |
| get_current_context | Get the current kubectl context |
| get_available_contexts | Get the list of available kubectl contexts |
| switch_context | Switch the kubectl context |
| list_scripts | List all available scripts with their parameters |

Additionally, all scripts in the `scripts/` directory are automatically registered as tools with the prefix `script_`.

## Creating Custom Scripts

You can extend the MCP server's functionality by adding custom scripts to the `scripts/` directory.

### Script Requirements

1. Scripts must be Python files with a `.py` extension
2. Scripts should use argparse for parameter definitions (they will be auto-detected)
3. Scripts should support receiving arguments via a JSON file with the `--args-file` flag

### Improving Script Detection

If your scripts aren't being properly detected by the MCP server, try these improvements:

1. **Add detailed docstrings at the module level** with parameter descriptions:
   ```python
   """
   My Script Name
   
   Description of what this script does.
   
   Parameters:
       --param1: Description of parameter 1 (required)
       --param2: Description of parameter 2 (default: default_value)
   """
   ```

2. **Use detailed argparse help texts** that match your docstrings:
   ```python
   parser.add_argument(
       "--param1",
       type=str,
       required=True,
       help="Description of parameter 1 (required)"
   )
   ```

3. **Use ArgumentDefaultsHelpFormatter** to include default values in help texts:
   ```python
   parser = argparse.ArgumentParser(
       description="Description of the script",
       formatter_class=argparse.ArgumentDefaultsHelpFormatter
   )
   ```

4. **Make your script executable** with proper permissions:
   ```bash
   chmod +x scripts/your_script.py
   ```

### Script Template

Here's a basic template for creating a new script:

```python
#!/usr/bin/env python3
"""
Script Name

Brief description of what the script does.

Parameters:
    --param1: Description of parameter 1 (required)
    --param2: Description of parameter 2 (default: default_value)
"""

import argparse
import json
import sys
import os

def main():
    """
    Main function that parses arguments and executes the script.
    
    This function demonstrates how to properly structure a script 
    for the Kubernetes MCP Server with clear parameter definitions.
    
    Returns:
        dict: A dictionary with the execution results
    """
    parser = argparse.ArgumentParser(
        description="Description of the script",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Define your parameters with detailed docstrings
    parser.add_argument(
        "--param1", 
        type=str, 
        required=True, 
        help="Description of parameter 1 (required)"
    )
    
    parser.add_argument(
        "--param2", 
        type=int,
        default=42, 
        help="Description of parameter 2"
    )
    
    # Check if the --args-file flag is present
    parser.add_argument("--args-file", help="JSON file containing arguments")
    args, _ = parser.parse_known_args()
    
    if args.args_file:
        # Load arguments from the file
        with open(args.args_file, 'r') as f:
            arguments = json.load(f)
            
        # Convert the loaded JSON arguments into a namespace
        for arg_name, arg_value in arguments.items():
            setattr(args, arg_name, arg_value)
    else:
        # Parse all arguments normally for CLI usage
        args = parser.parse_args()
    
    # Use your arguments here
    print(f"Parameter 1: {args.param1}")
    print(f"Parameter 2: {args.param2}")
    
    # Implement your script logic here
    
if __name__ == "__main__":
    main()
```

## Environment Variables

- `SCRIPTS_DIR`: Override the default scripts directory location
  ```
  SCRIPTS_DIR=/path/to/scripts python3 bin/k8s_mcp_wrapper.py
  ```

## Architecture

The system consists of the following components:

1. **MCP Server**: Uses the FastMCP SDK to implement the MCP protocol
2. **Kubernetes Client**: Handles direct interactions with kubectl using Pydantic models
3. **Extension Scripts**: Provide specialized functionality with auto-detected parameters

## Pydantic Models

The system uses Pydantic for:
- Type-safe models for Kubernetes resources
- Automatic validation of data structures
- Better IDE integration and error detection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 