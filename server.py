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

def _inject_filters(operation: str, args: list[str], site_id: str = None, site_name: str = None, user_id: str = None) -> list[str]:
    """Helper to automatically inject filters into query JSON for operations that require them.
    
    Args:
        operation: The query operation name
        args: Original arguments list
        site_id: Site ID to filter by
        site_name: Site name to filter by  
        user_id: User ID to filter by
        
    Returns:
        Modified args list with filters injected
    """
    # Find the JSON argument
    json_arg_index = None
    for i, arg in enumerate(args):
        if arg.strip().startswith('{'):
            json_arg_index = i
            break
    
    if json_arg_index is None:
        return args  # No JSON to modify
    
    try:
        query_data = json.loads(args[json_arg_index])
    except json.JSONDecodeError:
        return args  # Can't parse, return as-is
    
    # Inject filters based on operation type
    if operation in ['appStats', 'appStatsTimeSeries']:
        # Ensure appStatsFilter exists
        if 'appStatsFilter' not in query_data:
            query_data['appStatsFilter'] = []
        
        # Add site filter if provided and not already present
        if site_id and not any(f.get('fieldName') == 'src_site_id' for f in query_data['appStatsFilter']):
            query_data['appStatsFilter'].append({
                'fieldName': 'src_site_id',
                'operator': 'in',
                'values': [site_id]
            })
        elif site_name and not any(f.get('fieldName') == 'src_site_name' for f in query_data['appStatsFilter']):
            query_data['appStatsFilter'].append({
                'fieldName': 'src_site_name',
                'operator': 'in',
                'values': [site_name]
            })
        
        # Add user filter if provided and not already present
        if user_id and not any(f.get('fieldName') == 'vpn_user_id' for f in query_data['appStatsFilter']):
            query_data['appStatsFilter'].append({
                'fieldName': 'vpn_user_id',
                'operator': 'in',
                'values': [user_id]
            })
    
    elif operation == 'accountSnapshot':
        # Add siteIDs or userIDs if provided and not present
        if site_id and 'siteIDs' not in query_data:
            query_data['siteIDs'] = [site_id]
        if user_id and 'userIDs' not in query_data:
            query_data['userIDs'] = [user_id]
    
    elif operation == 'accountMetrics':
        # Add siteIDs if provided and not present
        if site_id and 'siteIDs' not in query_data:
            query_data['siteIDs'] = [site_id]
    
    elif operation in ['socketPortMetrics', 'socketPortMetricsTimeSeries']:
        # Ensure socketPortMetricsFilter exists
        if 'socketPortMetricsFilter' not in query_data:
            query_data['socketPortMetricsFilter'] = []
        
        # Add site filter if provided and not already present
        if site_id and not any(f.get('fieldName') == 'site_id' for f in query_data['socketPortMetricsFilter']):
            query_data['socketPortMetricsFilter'].append({
                'fieldName': 'site_id',
                'operator': 'in',
                'values': [site_id]
            })
        elif site_name and not any(f.get('fieldName') == 'site_name' for f in query_data['socketPortMetricsFilter']):
            query_data['socketPortMetricsFilter'].append({
                'fieldName': 'site_name',
                'operator': 'in',
                'values': [site_name]
            })
    
    elif operation == 'eventsTimeSeries':
        # Ensure eventsFilter exists
        if 'eventsFilter' not in query_data:
            query_data['eventsFilter'] = []
        
        # Add site filter if provided and not already present
        if site_id and not any(f.get('fieldName') == 'site_id' for f in query_data['eventsFilter']):
            query_data['eventsFilter'].append({
                'fieldName': 'site_id',
                'operator': 'in',
                'values': [site_id]
            })
        elif site_name and not any(f.get('fieldName') == 'site_name' for f in query_data['eventsFilter']):
            query_data['eventsFilter'].append({
                'fieldName': 'site_name',
                'operator': 'in',
                'values': [site_name]
            })
    
    # Replace the JSON argument with modified version
    modified_args = args.copy()
    modified_args[json_arg_index] = json.dumps(query_data)
    return modified_args

@mcp.tool()
def cato_query(operation: str, args: list[str] = [], site_id: str = None, site_name: str = None, user_id: str = None) -> str:
    """
    Execute 'catocli query' commands to retrieve REAL-TIME data and analytics from Cato Networks.
    
    CRITICAL FILTERING REQUIREMENTS
    For appStats, appStatsTimeSeries, accountSnapshot, and accountMetrics operations:
    1. FIRST call list_sites() or list_vpn_users() to get IDs
    2. THEN pass the site_id or user_id parameter to this function
    3. Filters will be AUTOMATICALLY injected to reduce response size
    
    REQUIRED TWO-STEP WORKFLOW:
        # Step 1: Get site or user IDs
        sites = list_sites()  # Returns JSON with site data including IDs
        
        # Step 2: Pass site_id parameter (extracted from step 1)
        cato_query(
            "appStats",
            ['{"timeFrame": "last.P1D", ...}'],
            site_id="12345"  # <-- REQUIRED: Automatically adds filter
        )
    
    The site_id, site_name, and user_id parameters automatically inject proper filters into:
    - appStats / appStatsTimeSeries: Adds appStatsFilter
    - accountSnapshot: Adds siteIDs or userIDs  
    - accountMetrics: Adds siteIDs
    - socketPortMetrics / socketPortMetricsTimeSeries: Adds socketPortMetricsFilter
    - eventsTimeSeries: Adds eventsFilter
    
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
    - Report format options (-f csv, -f json) defaults to json
    - Output options (--csv-filename, --append-timestamp)
    - TimeFrame examples (last.P1D, last.PT1H, utc.YYYY-MM-{DD/HH:MM:SS--DD/HH:MM:SS})
    
    Args:
        operation: The query operation name. Key operations by category (see below)
        args: Arguments in JSON format plus options (e.g., ['{"timeFrame": "last.P1D"}', '-f', 'json'])
        site_id: (Optional but RECOMMENDED) Site ID to automatically filter by - get from list_sites()
        site_name: (Optional) Site name to filter by - alternative to site_id
        user_id: (Optional) User ID to automatically filter by - get from list_vpn_users()
    
    Key operations by category:
        
        BANDWIDTH & TRAFFIC ANALYTICS:
            ** WHEN TO USE WHICH TOOL **:
            For Traffic Trends, Peak Usage, User Activity, Application Performance, Capacity Planning:
              - Use appStats for SINGLE time period aggregation (e.g., "last 14 days total")
              - Use appStatsTimeSeries for data OVER TIME (e.g., "14 days broken down by day")
            
            - appStats: Application bandwidth usage (aggregated over entire timeFrame)
              * Use when: Asked for total usage over a time period WITHOUT breakdown
              * Example queries: "bandwidth last 14 days", "top apps this month"
              * CRITICAL: Set "perSecond": false for accurate throughput metrics
              * CRITICAL FIELD NAMES: Use "dimension" and "measure" (NOT appStatsDimension/appStatsMeasure)
                - CORRECT: "dimension": [{"fieldName": "application_name"}]
                - WRONG: "appStatsDimension": [...]
              * Dimensions: user_name, application_name, src_site_name, src_site_id, category, traffic_direction
              * Measures: upstream, downstream, traffic, flows_created
              * FILTERING: Use appStatsFilter to reduce response size:
                - Filter by src_site_name, src_site_id, user_name, or vpn_user_id
                - Example: '{"appStatsFilter": [{"fieldName": "src_site_id", "operator": "in", "values": ["123"]}]}'
            
            - appStatsTimeSeries: Application bandwidth over time with time buckets
              * Use when: Asked to break down data over time (hourly, daily, etc.)
              * Example queries: "14 days by day", "24 hours broken down hourly", "traffic trends"
              * CRITICAL: Set "perSecond": false for accurate throughput metrics
              * CRITICAL FIELD NAMES: Use "dimension" and "measure" (NOT appStatsDimension/appStatsMeasure)
                - CORRECT: "dimension": [{"fieldName": "src_site_name"}]
                - WRONG: "appStatsDimension": [...]
              * Bucket calculation: timeFrame divided by buckets = interval per bucket
                - 24 buckets + "last.P1D" = hourly data for 1 day
                - 14 buckets + "last.P14D" = daily data for 14 days
              * PAGINATION: For large requests (e.g., 14 days hourly = 336 buckets):
                - Break into multiple queries: 14 separate daily queries with 24 buckets each
                - This prevents response size from being too large
              * Dimensions: Same as appStats
              * FILTERING: Use appStatsFilter same as appStats to reduce data volume
            
            - socketPortMetrics: WAN port-level bandwidth by site/interface (aggregated)
              * Use when: Asked for total port/interface usage over a time period WITHOUT breakdown
              * Use for: Temporal analysis, trend identification, capacity planning, performance monitoring, anomaly detection
              * Example queries: "port bandwidth last 14 days", "interface utilization this month"
              * CRITICAL FIELD NAMES: Use "dimension" and "measure" (NOT socketPortMetricsDimension/Measure)
                - CORRECT: "dimension": [{"fieldName": "site_name"}]
                - WRONG: "socketPortMetricsDimension": [...]
              * Dimensions: socket_interface, device_id, site_name, site_id
              * Measures: bytes_upstream, bytes_downstream, bytes_total
              * FILTERING: Use socketPortMetricsFilter to reduce response size:
                - Filter by site_id or site_name to focus on specific sites
                - Example: '{"socketPortMetricsFilter": [{"fieldName": "site_id", "operator": "in", "values": ["123"]}]}'
            
            - socketPortMetricsTimeSeries: WAN port bandwidth over time with time buckets
              * Use when: Asked to break down port/interface data over time (hourly, daily, etc.)
              * Use for: Performance tracking over time, peak hour identification, historical trends
              * Example queries: "14 days by day", "24 hours broken down hourly", "port usage trends"
              * CRITICAL FIELD NAMES: Use "dimension" and "measure" (NOT socketPortMetricsDimension/Measure)
                - CORRECT: "dimension": [{"fieldName": "socket_interface"}]
                - WRONG: "socketPortMetricsDimension": [...]
              * Bucket calculation: timeFrame divided by buckets = interval per bucket
                - 24 buckets + "last.P1D" = hourly data for 1 day
                - 14 buckets + "last.P14D" = daily data for 14 days
              * PAGINATION: For large requests (e.g., 14 days hourly = 336 buckets):
                - Break into multiple queries: 14 separate daily queries with 24 buckets each
                - This prevents response size from being too large
              * Dimensions: Same as socketPortMetrics
              * FILTERING: Use socketPortMetricsFilter same as socketPortMetrics to reduce data volume
            
            - accountMetrics: Account-wide traffic and performance metrics over time
              * Use when: Asked about network performance, bandwidth, throughput, traffic patterns,
                connection quality (latency, jitter, packet loss, health scores),
                interface statistics, or user activity
              * Use for: Per-device metrics, per-interface statistics, per-user performance
              * Example queries: "network performance last 14 days", "connection quality", "user bandwidth"
              * Bucket usage:
                - For SINGLE time period (e.g., "last 14 days total"): NO buckets parameter
                  Example: '{"siteIDs": ["123"], "timeFrame": "last.P14D"}'
                - For data OVER TIME (e.g., "14 days by day"): Divide timeFrame by buckets
                  24 buckets + "last.P1D" = hourly metrics for 1 day
                  14 buckets + "last.P14D" = daily metrics for 14 days
              * PAGINATION: For large requests (e.g., 14 days hourly = 336 buckets):
                - Break into multiple queries: 14 separate daily queries with 24 buckets each
                - This prevents response size from being too large
              * CRITICAL FILTERING: ALWAYS filter to reduce response size:
                - Filter by exactly ONE siteID (required): '{"siteIDs": ["123"]}'
                - Optionally also filter by ONE userID: '{"siteIDs": ["123"], "userIDs": ["456"]}'
                - Never query without siteID filter - response will be too large
                - Consider per-user filtering for user activity analysis
        
        NETWORK & SITES:
            - accountSnapshot: Account configuration and status
              * CRITICAL: ALWAYS filter to reduce response size:
                - Filter by exactly ONE siteID, OR
                - Filter by exactly ONE userID, OR
                - Filter by exactly ONE siteID AND ONE userID
              * Get IDs first using list_sites() or list_vpn_users() tools
              * Example: '{"siteIDs": ["12345"]}' or '{"userIDs": ["67890"]}'
              * DO NOT query multiple sites/users - response will be too large
              * Without filters, returns complete account snapshot (extremely large)
            - site: Site information and configuration
            - siteLocation: Site locations and geography
            - entityLookup: Search for any entity (sites, users, hosts, etc.)
        
        SECURITY & EVENTS:
            ** WHEN TO USE eventsTimeSeries **:
            For Security Events, Connectivity Events, Threat Analysis, Operational Events,
            Forensic Analysis, and Trend Detection - ALWAYS use eventsTimeSeries
            
            - eventsTimeSeries: Security and network events over time with time buckets
              * Use when: Asked about security events, threats, firewall blocks, connectivity,
                system status, configuration changes, or any event analysis
              * Use for: Threat detection, risk assessment, forensic investigation, pattern identification
              * Example queries: "security events last 14 days", "firewall blocks today", "threat trends"
              * Bucket usage:
                - For SINGLE time period (e.g., "last 14 days total"): Use 1 bucket
                  Example: '{"buckets": 1, "timeFrame": "last.P14D"}'
                - For data OVER TIME (e.g., "14 days by day"): Divide timeFrame by buckets
                  24 buckets + "last.P1D" = hourly events for 1 day
                  14 buckets + "last.P14D" = daily events for 14 days
              * PAGINATION: For large requests (e.g., 14 days hourly = 336 buckets):
                - Break into multiple queries: 14 separate daily queries with 24 buckets each
                - This prevents response size from being too large
              * FILTERING: Use eventsFilter to reduce response size:
                - Filter by site_id, site_name, event type, severity, etc.
                - Example: '{"eventsFilter": [{"fieldName": "site_id", "operator": "in", "values": ["123"]}]}'
            
            - events: Legacy events query (prefer eventsTimeSeries instead)
            - eventsFeed: Enhanced event feed with advanced filtering
            - auditFeed: Audit log entries for configuration changes
        
        ADMINISTRATION:
            - admins: List administrators
            - policy: Policy configuration
            - hardware: Hardware inventory
            Use catocli_help("query") for the complete list.
    
    Examples:
        # ALWAYS get help first to see required JSON structure and examples
        catocli_help("query appStatsTimeSeries")
        
        # Application bandwidth by site (hourly buckets, last 24 hours)
        # CRITICAL: Use "dimension" and "measure" field names (not appStatsDimension/appStatsMeasure)
        # CRITICAL: Set perSecond=false for accurate throughput
        cato_query("appStatsTimeSeries", [
            '{"buckets": 24, "dimension": [{"fieldName": "src_site_name"}, {"fieldName": "application_name"}], "measure": [{"aggType": "sum", "fieldName": "traffic"}], "timeFrame": "last.P1D", "perSecond": false, "appStatsFilter": []}',
            '-f', 'json'
        ])
        
        # Site bandwidth by socket interface
        # CRITICAL: Use "dimension" and "measure" field names (not socketPortMetricsDimension/Measure)
        cato_query("socketPortMetrics", [
            '{"dimension": [{"fieldName": "site_name"}, {"fieldName": "socket_interface"}], "measure": [{"aggType": "sum", "fieldName": "bytes_total"}], "socketPortMetricsFilter": [], "timeFrame": "last.P1D"}',
            '-f', 'json'
        ])
        
        # Top applications by traffic (aggregated, no time buckets)
        # CRITICAL: Use "dimension" and "measure" field names (not appStatsDimension/appStatsMeasure)
        cato_query("appStats", [
            '{"dimension": [{"fieldName": "application_name"}], "measure": [{"aggType": "sum", "fieldName": "traffic"}], "sort": [{"fieldName": "traffic", "order": "desc"}], "appStatsFilter": [], "timeFrame": "last.P1D", "perSecond": false}',
            '-f', 'json'
        ])
        
        # Account snapshot filtered by ONE site (REQUIRED to reduce response size)
        # First get site IDs using list_sites(), then filter by exactly ONE:
        cato_query("accountSnapshot", [
            '{"siteIDs": ["12345"]}',
            '-p'
        ])
        
        # Account metrics for ONE site (REQUIRED - never query without siteID)
        cato_query("accountMetrics", [
            '{"siteIDs": ["12345"], "timeFrame": "last.P1D"}',
            '-p'
        ])
    """
    # Enforce filtering for high-volume operations to avoid oversized responses
    REQUIRES_FILTERING = ['appStats', 'appStatsTimeSeries', 'accountSnapshot', 'accountMetrics']

    def _has_json_filter(op: str, arguments: list[str]) -> bool:
        """Check if the JSON args already contain the required filters."""
        try:
            json_arg = next((a for a in arguments if a.strip().startswith('{')), None)
            if not json_arg:
                return False
            data = json.loads(json_arg)
        except Exception:
            return False

        if op in ['appStats', 'appStatsTimeSeries']:
            flt = data.get('appStatsFilter', [])
            return any(
                isinstance(f, dict) and f.get('fieldName') in ['src_site_id', 'src_site_name', 'vpn_user_id', 'user_name']
                for f in flt
            )
        if op == 'accountSnapshot':
            return (
                isinstance(data.get('siteIDs'), list) and len(data.get('siteIDs')) == 1
            ) or (
                isinstance(data.get('userIDs'), list) and len(data.get('userIDs')) == 1
            )
        if op == 'accountMetrics':
            return isinstance(data.get('siteIDs'), list) and len(data.get('siteIDs')) == 1
        return False

    # If operation requires filtering and neither parameters nor JSON include it, return actionable error
    if operation in REQUIRES_FILTERING and not (site_id or site_name or user_id) and not _has_json_filter(operation, args):
        return (
            f"ERROR: {operation} requires a site or user filter to prevent oversized responses.\n"
            "Do this first: list_sites() or list_vpn_users() to get IDs.\n"
            "Then call cato_query again with site_id/site_name or user_id parameters.\n\n"
            "Example: cato_query(\"appStats\", ['{\"timeFrame\": \"last.P1D\", \"dimension\": [{\"fieldName\": \"application_name\"}], \"measure\": [{\"aggType\": \"sum\", \"fieldName\": \"traffic\"}], \"perSecond\": false, \"appStatsFilter\": []}'], site_id='12345')"
        )

    # Automatically inject filters if site_id, site_name, or user_id are provided
    filtered_args = _inject_filters(operation, args, site_id, site_name, user_id)
    return run_cato_command(["query", operation] + filtered_args)

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
