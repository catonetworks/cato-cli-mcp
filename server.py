from mcp.server.fastmcp import FastMCP
import subprocess
import json
import shlex

# Initialize FastMCP server
mcp = FastMCP("cato-cli-server")

def run_cato_command(args: list[str]) -> str:
    """Helper to run catocli commands."""
    command = ["python3", "-m", "catocli"] + args
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.stderr}"
    except FileNotFoundError:
        return "Error: catocli not found. Please ensure it is installed and in the PATH."

@mcp.tool()
def cato_entity(subcommand: str, args: list[str] = []) -> str:
    """
    Execute 'catocli entity' commands to manage entities.
    
    Args:
        subcommand: The entity subcommand. Options:
            - lookup: Lookup an entity.
            - add: Add a new entity.
            - remove: Remove an entity.
            - update: Update an entity.
        args: Additional arguments for the subcommand.
            Common arguments:
            - --id <ID>: Entity ID.
            - --name <NAME>: Entity name.
            - --type <TYPE>: Entity type.
    """
    return run_cato_command(["entity", subcommand] + args)

@mcp.tool()
def cato_query(operation: str, args: list[str] = []) -> str:
    """
    Execute 'catocli query' commands to retrieve data.
    
    Args:
        operation: The query operation. Options include:
            - accountSnapshot: Get account snapshot.
            - admins: List admins.
            - appStats: Application statistics.
            - auditFeed: Audit logs.
            - entityLookup: Lookup entities.
            - events: Query events.
            - siteStats: Site statistics.
            - socketSite: Socket site information.
            - users: List users.
            - ... and more.
        args: Additional arguments for the query operation.
    """
    return run_cato_command(["query", operation] + args)

@mcp.tool()
def cato_mutation(operation: str, args: list[str] = []) -> str:
    """
    Execute 'catocli mutation' commands to modify configuration.
    
    Args:
        operation: The mutation operation. Options include:
            - accountManagement: Manage account settings.
            - admin: Manage admins.
            - policy: Manage policies.
            - site: Manage sites.
            - socket: Manage sockets.
            - vpnUser: Manage VPN users.
            - ... and more.
        args: Additional arguments for the mutation operation.
    """
    return run_cato_command(["mutation", operation] + args)

@mcp.tool()
def cato_raw(query: str) -> str:
    """
    Execute a raw GraphQL query using 'catocli raw'.
    
    Args:
        query: The GraphQL query string.
    """
    return run_cato_command(["raw", query])

if __name__ == "__main__":
    import argparse
    import sys

    print("Starting Cato MCP Server...", file=sys.stderr)
    print(f"Arguments: {sys.argv}", file=sys.stderr)

    # Ensure catocli is installed
    print("Ensuring catocli is installed...", file=sys.stderr)
    try:
        # Try using uv first as it's likely the environment manager
        subprocess.run(
            ["uv", "pip", "install", "catocli"],
            check=True,
            capture_output=True
        )
        print("Successfully installed/verified catocli using uv", file=sys.stderr)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to pip if uv fails or isn't found
        try:
            subprocess.run(
                ["pip3", "install", "catocli"],
                check=True,
                capture_output=True
            )
            print("Successfully installed/verified catocli using pip", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install catocli: {e}", file=sys.stderr)
            print(f"Stderr: {e.stderr.decode() if e.stderr else 'None'}", file=sys.stderr)
            # We continue, hoping it's already there or the error was transient

    parser = argparse.ArgumentParser()
    parser.add_argument("--account-id", help="Cato Account ID")
    parser.add_argument("--cato-token", help="Cato API Token")
    args, unknown = parser.parse_known_args()

    if args.account_id and args.cato_token:
        print(f"Configuring catocli for account {args.account_id}...", file=sys.stderr)
        try:
        
            subprocess.run(
                ["python3", "-m", "catocli", "configure", "set", "--cato-token", args.cato_token, "--account-id", args.account_id],
                check=True,
                capture_output=True
            )
            print(f"Successfully configured catocli for account {args.account_id}", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Failed to configure catocli: {e}", file=sys.stderr)
            print(f"Stdout: {e.stdout.decode() if e.stdout else 'None'}", file=sys.stderr)
            print(f"Stderr: {e.stderr.decode() if e.stderr else 'None'}", file=sys.stderr)
            #sys.exit(1)
    else:
        print("No configuration arguments provided. Assuming catocli is already configured.", file=sys.stderr)

    # Remove parsed arguments from sys.argv so FastMCP doesn't see them
    sys.argv = [sys.argv[0]] + unknown
    
    print("Starting FastMCP server...", file=sys.stderr)
    mcp.run()
