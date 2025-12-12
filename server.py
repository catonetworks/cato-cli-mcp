from mcp.server.fastmcp import FastMCP
import subprocess
import json
import shlex

# Initialize FastMCP server
# Provides access to real-time Cato Networks data: bandwidth, traffic, sites, users, events, and configuration
mcp = FastMCP("cato-networks")

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
def catocli_help(command: str = "") -> str:
    """
    Get help information for catocli commands.
    Use this tool FIRST before executing any catocli command to understand:
    - Available operations and subcommands
    - Required and optional parameters
    - JSON input format and examples
    - Report format options (-f csv, -f json, etc.)
    - Output options (--csv-filename, --append-timestamp, etc.)
    
    Args:
        command: The command path to get help for. Examples:
            - "" or "query" - List available query operations
            - "query appStatsTimeSeries" - Detailed help with examples
            - "entity" - List entity types
            - "mutation" - List mutation operations
            - "entity site" - Help for site entity operations
    
    Returns:
        Detailed help text including examples, parameters, and usage patterns.
    """
    if not command:
        return run_cato_command(["-h"])
    
    cmd_parts = command.split()
    return run_cato_command(cmd_parts + ["-h"])

@mcp.tool()
def cato_entity(subcommand: str, args: list[str] = []) -> str:
    """
    Execute 'catocli entity' commands to lookup entities in Cato Networks.
    
    USE THIS TOOL to list or search for:
    - Sites, users, hosts, network interfaces
    - VPN users, administrators, locations
    - Services, firewall rules, routing configurations
    
    IMPORTANT: Use catocli_help("entity") first to see available entity types.
    Then use catocli_help("entity <type>") for specific entity help.
    
    Args:
        subcommand: The entity type to lookup. Common types:
            - account, admin, site, vpnUser, host, location, networkInterface
            - simpleService, portProtocol, lanFirewall, localRouting
            - groupSubscription, mailingListSubscription, webhookSubscription
        args: Additional arguments. Use -h to see options for each type.
            Common patterns:
            - ['{"search": "name"}'] - Search by name
            - ['{"id": "123"}'] - Lookup by ID
    
    Example:
        cato_entity("site", ['{"search": "HQ"}'])
        cato_entity("vpnUser", ['{"search": "john@example.com"}'])
    """
    return run_cato_command(["entity", subcommand] + args)

@mcp.tool()
def cato_query(operation: str, args: list[str] = []) -> str:
    """
    Execute 'catocli query' commands to retrieve REAL-TIME data and analytics from Cato Networks.
    
    USE THIS TOOL for ANY questions about:
    - Bandwidth usage, traffic statistics, network metrics
    - Application usage, user activity, site performance  
    - WAN links, socket ports, interface utilization
    - Security events, audit logs, policy information
    - Current network configuration and status
    
    This tool provides direct access to your live Cato network data including bandwidth metrics,
    traffic statistics, network analytics, security events, and configuration.
    
    IMPORTANT: Use catocli_help("query") first to see all available operations.
    Then use catocli_help("query <operation>") for detailed help with:
    - JSON input examples and required parameters
    - Report format options (-f csv, -f json, -f table)
    - Output options (--csv-filename, --append-timestamp)
    - TimeFrame examples (last.P1D, last.PT1H, utc.YYYY-MM-{DD/HH:MM:SS--DD/HH:MM:SS})
    
    Args:
        operation: The query operation name. Key operations by category:
        
        BANDWIDTH & TRAFFIC ANALYTICS:
            - appStats: Application bandwidth usage (aggregated)
            - appStatsTimeSeries: Application bandwidth over time with time buckets
              * Use to answer: "bandwidth by application", "top applications", "app usage trends"
              * CRITICAL: Set "perSecond": false for accurate throughput metrics
              * Dimensions: user_name, application_name, src_site_name, category, traffic_direction
              * Measures: upstream, downstream, traffic, flows_created
              * Bucket examples: 24 buckets + "last.P1D" = hourly data for 1 day
            - socketPortMetrics: WAN port-level bandwidth by site/interface (aggregated)
            - socketPortMetricsTimeSeries: WAN port bandwidth over time with time buckets
              * Use to answer: "site bandwidth", "WAN link usage", "port utilization by site"
              * Dimensions: socket_interface, device_id, site_name
              * Measures: bytes_upstream, bytes_downstream, bytes_total
            - accountMetrics: Account-wide traffic and performance metrics over time
        
        NETWORK & SITES:
            - accountSnapshot: Account configuration and status
              * IMPORTANT: To reduce response size, filter by specific site IDs or user IDs
              * Get IDs first using list_sites() or list_vpn_users() tools
              * Example filter: '{"siteIDs": ["id1", "id2"], "userIDs": ["id1", "id2"]}'
              * Without filters, returns complete account snapshot (may be very large)
            - site: Site information and configuration
            - siteLocation: Site locations and geography
            - entityLookup: Search for any entity (sites, users, hosts, etc.)
        
        SECURITY & EVENTS:
            - events/eventsTimeSeries: Security and network events over time
            - eventsFeed: Enhanced event feed with advanced filtering
            - auditFeed: Audit log entries for configuration changes
        
        ADMINISTRATION:
            - admins: List administrators
            - policy: Policy configuration
            - hardware: Hardware inventory
            Use catocli_help("query") for the complete list.
        
        args: Arguments in JSON format plus options. Common patterns:
            - ['{"timeFrame": "last.P1D"}'] - Last 24 hours of data
            - ['{"buckets": 24, "timeFrame": "last.P1D"}'] - 24 hourly buckets
            - ['{...json...}', '-f', 'table'] - Display as formatted table
            - ['{...json...}', '-f', 'csv'] - Export to CSV format
            - ['{...json...}', '-f', 'json', '-p'] - Pretty-print JSON
    
    Examples:
        # ALWAYS get help first to see required JSON structure and examples
        catocli_help("query appStatsTimeSeries")
        
        # Application bandwidth by site (hourly buckets, last 24 hours)
        # CRITICAL: perSecond=false for accurate throughput
        cato_query("appStatsTimeSeries", [
            '{"buckets": 24, "dimension": [{"fieldName": "src_site_name"}, {"fieldName": "application_name"}], "measure": [{"aggType": "sum", "fieldName": "traffic"}], "timeFrame": "last.P1D", "perSecond": false, "appStatsFilter": []}',
            '-f', 'table'
        ])
        
        # Site bandwidth by socket interface
        cato_query("socketPortMetrics", [
            '{"socketPortMetricsDimension": [{"fieldName": "site_name"}, {"fieldName": "socket_interface"}], "socketPortMetricsMeasure": [{"aggType": "sum", "fieldName": "bytes_total"}], "socketPortMetricsFilter": [], "timeFrame": "last.P1D"}',
            '-f', 'table'
        ])
        
        # Top applications by traffic (aggregated, no time buckets)
        cato_query("appStats", [
            '{"appStatsDimension": [{"fieldName": "application_name"}], "appStatsMeasure": [{"aggType": "sum", "fieldName": "traffic"}], "appStatsSort": [{"fieldName": "traffic", "order": "desc"}], "appStatsFilter": [], "timeFrame": "last.P1D"}',
            '-f', 'table'
        ])
        
        # Account snapshot filtered by specific sites (reduces response size)
        # First get site IDs using list_sites(), then filter:
        cato_query("accountSnapshot", [
            '{"siteIDs": ["12345", "67890"]}',
            '-p'
        ])
    """
    return run_cato_command(["query", operation] + args)

@mcp.tool()
def cato_mutation(operation: str, args: list[str] = []) -> str:
    """
    Execute 'catocli mutation' commands to modify Cato configuration.
    
    IMPORTANT: Use catocli_help("mutation") first to see all available operations.
    Then use catocli_help("mutation <operation>") for detailed help with examples.
    
    WARNING: Mutations modify your Cato account configuration. Always check help
    documentation and test parameters carefully before execution.
    
    Args:
        operation: The mutation operation name. Common operations:
            - accountManagement: Account settings and preferences
            - admin: Add/modify/remove administrators
            - policy: Modify security and routing policies  
            - site: Add/modify/remove sites
            - socket: Manage socket configurations
            - vpnUser: Add/modify/remove VPN users
            - internetFirewall: Firewall rule management
            - wan: WAN link configuration
            Use catocli_help("mutation") for the complete list.
        
        args: Arguments in JSON format plus options. Common patterns:
            - ['{...json...}'] - JSON input with mutation parameters
            - ['{...json...}', '-p'] - Pretty-print response
            - ['--json-file', 'input.json'] - Load JSON from file
    
    Examples:
        # Get help first
        catocli_help("mutation site")
        
        # Execute mutation
        cato_mutation("site", ['{"addSite": {...}}', '-p'])
    """
    return run_cato_command(["mutation", operation] + args)

# Entity-specific tools for easier discovery
@mcp.tool()
def list_sites(search: str = "") -> str:
    """List all Cato Network sites. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "site"] + args)

@mcp.tool()
def list_admins(search: str = "") -> str:
    """List all administrators. Optionally filter by name/email."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "admin"] + args)

@mcp.tool()
def list_vpn_users(search: str = "") -> str:
    """List all VPN users. Optionally filter by name/email."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "vpnUser"] + args)

@mcp.tool()
def list_hosts(search: str = "") -> str:
    """List all hosts. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "host"] + args)

@mcp.tool()
def list_locations(search: str = "") -> str:
    """List all locations. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "location"] + args)

@mcp.tool()
def list_network_interfaces(search: str = "") -> str:
    """List all network interfaces. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "networkInterface"] + args)

@mcp.tool()
def list_simple_services(search: str = "") -> str:
    """List all simple services. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "simpleService"] + args)

@mcp.tool()
def list_port_protocols(search: str = "") -> str:
    """List all port protocols. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "portProtocol"] + args)

@mcp.tool()
def list_lan_firewall_rules(search: str = "") -> str:
    """List all LAN firewall rules. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "lanFirewall"] + args)

@mcp.tool()
def list_local_routing(search: str = "") -> str:
    """List all local routing configurations. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "localRouting"] + args)

@mcp.tool()
def list_group_subscriptions(search: str = "") -> str:
    """List all group subscriptions. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "groupSubscription"] + args)

@mcp.tool()
def list_mailing_list_subscriptions(search: str = "") -> str:
    """List all mailing list subscriptions. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "mailingListSubscription"] + args)

@mcp.tool()
def list_webhook_subscriptions(search: str = "") -> str:
    """List all webhook subscriptions. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "webhookSubscription"] + args)

@mcp.tool()
def list_allocated_ips(search: str = "") -> str:
    """List all allocated IPs. Optionally filter."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "allocatedIP"] + args)

@mcp.tool()
def list_dhcp_relay_groups(search: str = "") -> str:
    """List all DHCP relay groups. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "dhcpRelayGroup"] + args)

@mcp.tool()
def list_site_ranges(search: str = "") -> str:
    """List all site ranges. Optionally filter."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "siteRange"] + args)

@mcp.tool()
def list_timezones(search: str = "") -> str:
    """List all timezones. Optionally filter by name."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "timezone"] + args)

@mcp.tool()
def list_available_pooled_usage(search: str = "") -> str:
    """List available pooled usage. Optionally filter."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "availablePooledUsage"] + args)

@mcp.tool()
def list_available_site_usage(search: str = "") -> str:
    """List available site usage. Optionally filter."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "availableSiteUsage"] + args)

@mcp.tool()
def list_account_info(search: str = "") -> str:
    """Get account information."""
    args = ["list", '{"search": "' + search + '"}'] if search else ["list"]
    return run_cato_command(["entity", "account"] + args)

@mcp.tool()
def cato_raw(query: str, args: list[str] = []) -> str:
    """
    Execute a raw GraphQL query or mutation directly against Cato API.
    
    This tool provides direct access to the Cato GraphQL API for:
    - Custom queries not covered by standard operations
    - Complex multi-field queries
    - Testing and development
    
    Use catocli_help("raw") for detailed syntax and examples.
    
    Args:
        query: The complete GraphQL query or mutation string.
               Can be a query {...} or mutation {...} block.
        args: Additional options:
            - ['-p'] - Pretty-print output
            - ['-v'] - Verbose output
            - ['-f', 'csv'] - Format output (where applicable)
    
    Examples:
        # Simple query
        cato_raw('query { accountSnapshot { id name } }', ['-p'])
        
        # Complex query with variables
        cato_raw('''
        query { 
          entityLookup(type: "site", search: "HQ") { 
            id name 
          } 
        }
        ''', ['-p'])
    """
    return run_cato_command(["raw", query] + args)

if __name__ == "__main__":
    import argparse
    import sys
    import os

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
    parser.add_argument("--endpoint", help="Cato API Endpoint")
    args, unknown = parser.parse_known_args()

    # Priority: command line args > environment variables
    account_id = args.account_id or os.getenv('CATO_ACCOUNT_ID')
    cato_token = args.cato_token or os.getenv('CATO_API_KEY')
    endpoint = args.endpoint or os.getenv('CATO_API_HOST')

    if account_id and cato_token:
        print(f"Configuring catocli for account {account_id}...", file=sys.stderr)
        try:
            config_cmd = ["python3", "-m", "catocli", "configure", "set", "--cato-token", cato_token, "--account-id", account_id, "--skip-validation"]
            if endpoint:
                config_cmd.extend(["--endpoint", endpoint])
        
            result = subprocess.run(
                config_cmd,
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Successfully configured catocli for account {account_id}", file=sys.stderr)
            if result.stdout:
                print(f"Config output: {result.stdout}", file=sys.stderr)
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
