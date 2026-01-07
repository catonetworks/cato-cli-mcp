from mcp.server.fastmcp import FastMCP
import subprocess
import json
import shlex
import os
import sys
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from pathlib import Path

# Environment variable configuration for response limits
MAX_RESPONSE_RECORDS = int(os.getenv('CATO_MCP_MAX_RECORDS', '50'))
MAX_RESPONSE_SIZE_MB = float(os.getenv('CATO_MCP_MAX_SIZE_MB', '5'))

# Timeout configuration (in seconds)
QUERY_TIMEOUT_SECONDS = int(os.getenv('CATO_MCP_TIMEOUT_SECONDS', '120'))

# Cache configuration
CACHE_TTL_SECONDS = int(os.getenv('CATO_MCP_CACHE_TTL', '300'))  # 5 minutes default

# Event type to event subtype mapping for eventsFeed and eventsTimeSeries
EVENT_TYPE_SUBTYPE_MAPPING = {
    'Connectivity': [
        'Always-On Bypass',
        'ApiKey',
        'Cato Management Application',
        'Changed Pop',
        'Client Connectivity Policy',
        'Connected',
        'DHCP Lease',
        'Disconnected',
        'Fail-Over',
        'IP Conflict',
        'LAN Monitoring',
        'Last-Mile Quality',
        'Link-Aggregation',
        'Off-Cloud Recovery',
        'Off-Cloud Transport Connect',
        'Off-Cloud Transport Disconnect',
        'Passive Connected',
        'Passive Disconnected',
        'Reconnected',
        'Recovery via Alt. WAN',
        'Registration Code',
        'SDP Portal',
        'Socket Fail-Over'
    ],
    'Detection and Response': [
        'XDR Anomaly',
        'XDR Endpoint',
        'XDR Network',
        'XDR Threat'
    ],
    'Routing': [
        'BFD Session',
        'BGP Events Discarded',
        'BGP Routing',
        'BGP Session'
    ],
    'Security': [
        'Anti Malware',
        'Application Sign-in',
        'Apps Security',
        'Apps Security API',
        'DNS Protection',
        'Endpoint Alert',
        'Endpoint Protection',
        'IPS',
        'Identity Alert',
        'Internet Firewall',
        'LAN Firewall',
        'MAC Address Authentication',
        'MDR',
        'Misclassification',
        'NG Anti Malware',
        'RPF',
        'SDP Activity',
        'SaaS Security API Anti Malware',
        'SaaS Security API Data Protection',
        'Suspicious Activity',
        'TLS',
        'WAN Firewall'
    ],
    'Sockets Management': [
        'Socket Password Reset',
        'Socket Upgrade',
        'Socket WebUI Access'
    ],
    'System': [
        'Apps Security API Notification',
        'DC Connectivity Failure',
        'Directory Services',
        'ILMM Link Update',
        'LDAP Provisioning',
        'Multiple Users Detected',
        'New External Access Request Created',
        'QUOTA LIMIT',
        'SCIM Provisioning',
        'Sdp license',
        'User'
    ]
}

# Valid values for eventsFilter fields in eventsTimeSeries
# Maps filter field names to their possible valid values
EVENTS_FILTER_VALID_VALUES = {
    'action': [
        'Access denied',
        'Alert',
        'Allow',
        'Block',
        'Clear Alert',
        'Failed',
        'Monitor',
        'Prompt',
        'RBI',
        'SDP application activity',
        'SDP portal activity',
        'Succeeded',
        'Successful login'
    ],
    # Add other filter field names and their valid values here as they are discovered
    # Examples:
    # 'event_type': list(EVENT_TYPE_SUBTYPE_MAPPING.keys()),
    # 'severity': ['Low', 'Medium', 'High', 'Critical'],
    # 'status': ['Active', 'Resolved', 'Acknowledged'],
}

# Query optimization hints
QUERY_OPTIMIZATION_HINTS = {
    'appStats': {
        'recommended_timeframe': 'last.PT6H',
        'recommended_measures': ['traffic', 'upstream', 'downstream'],
        'max_dimensions': 2,
        'warning_threshold': 10000,
        'invalid_dimension_combinations': [
            # Add known invalid combinations here as they are discovered
        ],
        'invalid_standalone_dimensions': [
            # Add known invalid standalone dimensions here as they are discovered
        ]
    },
    'appStatsTimeSeries': {
        'recommended_buckets': 24,
        'max_buckets': 168,
        'recommended_timeframe': 'last.P1D',
        'invalid_dimension_combinations': [
            ['domain','application_name','application_id']
        ],
        'invalid_standalone_dimensions': [
            # Add known invalid standalone dimensions here as they are discovered
        ]
    },
    'socketPortMetrics': {
        'recommended_timeframe': 'last.P1D',
        'max_dimensions': 2,
        'invalid_dimension_combinations': [
            # Add known invalid combinations here as they are discovered
        ],
        'invalid_standalone_dimensions': [
            # Add known invalid standalone dimensions here as they are discovered
        ]
    },
    'socketPortMetricsTimeSeries': {
        'recommended_buckets': 24,
        'max_buckets': 168,
        'invalid_dimension_combinations': [
            [ "socket_interface", "ha_role", "sim_num", "account_id", "bytes_downstream", "bytes_upstream" ]
        ],
        'invalid_standalone_dimensions': [
            # Add known invalid standalone dimensions here as they are discovered
        ]
    },
    'accountMetrics': {
        'recommended_timeframe': 'last.P1D',
        'recommended_buckets': 24,
        'requires_site_filter': True,
        'invalid_dimension_combinations': [
            # Add known invalid combinations here as they are discovered
        ],
        'invalid_standalone_dimensions': [
            # Add known invalid standalone dimensions here as they are discovered
        ]
    },
    'eventsTimeSeries': {
        'recommended_buckets': 24,
        'max_buckets': 168,
        'requires_filter': True,
        'invalid_dimension_combinations': [
            # These dimension combinations will cause internal server errors
            ['rule_name', 'event_sub_type'],
            ['user_name', 'user_id'],
            ['application_id', 'domain'],
            ['application_name', 'domain']
        ],
        'invalid_standalone_dimensions': [
            # These dimensions cannot be used alone and will cause internal server errors
            'domain_name'
        ]
    }
}

# Initialize FastMCP server
# Provides access to real-time Cato Networks data: bandwidth, traffic, sites, users, events, and configuration
mcp = FastMCP("cato-networks")

# Query cache
class QueryCache:
    """Simple in-memory cache for query results."""
    
    def __init__(self, ttl_seconds=CACHE_TTL_SECONDS):
        self.cache = {}
        self.ttl = timedelta(seconds=ttl_seconds)
    
    def get_key(self, operation, params):
        """Generate cache key from query parameters."""
        key_str = f"{operation}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, operation, params):
        """Get cached result if available and not expired."""
        key = self.get_key(operation, params)
        if key in self.cache:
            result, timestamp = self.cache[key]
            if datetime.now() - timestamp < self.ttl:
                return result
            else:
                del self.cache[key]
        return None
    
    def set(self, operation, params, result):
        """Cache query result."""
        key = self.get_key(operation, params)
        self.cache[key] = (result, datetime.now())
    
    def clear(self):
        """Clear all cached results."""
        self.cache.clear()

# Initialize cache
query_cache = QueryCache(ttl_seconds=CACHE_TTL_SECONDS)

# Rate limiter
class RateLimiter:
    """Simple rate limiter to prevent API abuse."""
    
    def __init__(self, max_calls=10, period_seconds=60):
        self.max_calls = max_calls
        self.period = timedelta(seconds=period_seconds)
        self.calls = defaultdict(list)
    
    def acquire(self, key="default"):
        """Check if rate limit would be exceeded. Returns True if allowed."""
        now = datetime.now()
        
        # Remove old calls outside the window
        self.calls[key] = [
            call_time for call_time in self.calls[key]
            if now - call_time < self.period
        ]
        
        # Check if we're at the limit
        if len(self.calls[key]) >= self.max_calls:
            return False
        
        # Record this call
        self.calls[key].append(now)
        return True
    
    def get_wait_time(self, key="default"):
        """Get seconds to wait before next call is allowed."""
        now = datetime.now()
        if key not in self.calls or len(self.calls[key]) < self.max_calls:
            return 0
        
        oldest_call = min(self.calls[key])
        wait_time = (oldest_call + self.period - now).total_seconds()
        return max(0, wait_time)

# Initialize rate limiter (disabled by default, can be enabled via env var)
rate_limiter = RateLimiter(
    max_calls=int(os.getenv('CATO_MCP_RATE_LIMIT_CALLS', '999')),
    period_seconds=int(os.getenv('CATO_MCP_RATE_LIMIT_PERIOD', '60'))
)

def validate_query_params(operation, args):
    """Validate and suggest optimizations for query parameters."""
    hints = QUERY_OPTIMIZATION_HINTS.get(operation, {})
    warnings = []
    
    # Try to parse JSON args
    json_arg = None
    for arg in args:
        if arg.strip().startswith('{'):
            try:
                json_arg = json.loads(arg)
                break
            except json.JSONDecodeError:
                pass
    
    if not json_arg:
        return warnings
    
    # Check bucket count for time series operations
    if operation.endswith('TimeSeries'):
        buckets = json_arg.get('buckets', 0)
        max_buckets = hints.get('max_buckets', 999)
        recommended_buckets = hints.get('recommended_buckets', 24)
        
        if buckets > max_buckets:
            warnings.append(
                f"High bucket count ({buckets}). Consider using {recommended_buckets} "
                f"or split into multiple queries to avoid timeouts."
            )
    
    # Check for required filters
    if hints.get('requires_site_filter') and operation == 'accountMetrics':
        if 'siteIDs' not in json_arg or not json_arg.get('siteIDs'):
            warnings.append(
                f"{operation} requires siteIDs filter for optimal performance. "
                "Use list_sites() to get site IDs."
            )
    
    if hints.get('requires_filter') and operation == 'eventsTimeSeries':
        if 'eventsFilter' not in json_arg or not json_arg.get('eventsFilter'):
            warnings.append(
                f"{operation} should include eventsFilter for better performance. "
                "Consider filtering by site_id or event type."
            )
    
    # Validate dimension combinations for operations that support dimensions
    # Map operation names to their dimension parameter names
    dimension_param_map = {
        'eventsTimeSeries': 'eventsDimension',
        'appStats': 'dimension',
        'appStatsTimeSeries': 'dimension',
        'socketPortMetrics': 'dimension',
        'socketPortMetricsTimeSeries': 'dimension',
        'accountMetrics': 'dimension'
    }
    
    if operation in dimension_param_map:
        dimension_param_name = dimension_param_map[operation]
        dimensions_param = json_arg.get(dimension_param_name, [])
        
        if isinstance(dimensions_param, list):
            # Extract dimension field names
            dimension_names = []
            for dim in dimensions_param:
                if isinstance(dim, dict) and 'fieldName' in dim:
                    dimension_names.append(dim['fieldName'])
                elif isinstance(dim, str):
                    dimension_names.append(dim)
            
            # Check for invalid dimension combinations
            invalid_combinations = hints.get('invalid_dimension_combinations', [])
            for invalid_combo in invalid_combinations:
                if all(dim in dimension_names for dim in invalid_combo):
                    warnings.append(
                        f"ERROR: Invalid dimension combination detected in {operation}: {', '.join(invalid_combo)}. "
                        f"These dimensions cause internal server errors when used together. "
                        f"Use them in separate queries instead."
                    )
            
            # Check for invalid standalone dimensions
            invalid_standalone = hints.get('invalid_standalone_dimensions', [])
            for invalid_dim in invalid_standalone:
                if invalid_dim in dimension_names and len(dimension_names) == 1:
                    warnings.append(
                        f"ERROR: Dimension '{invalid_dim}' cannot be used alone in {operation} and will cause an internal server error. "
                        f"Combine it with other dimensions in your query."
                    )
    
    return warnings

def limit_response_size(data: str, max_records: int = MAX_RESPONSE_RECORDS, max_size_mb: float = MAX_RESPONSE_SIZE_MB) -> str:
    """Limit response size to prevent overwhelming the client.
    
    Args:
        data: The response data as a string (typically JSON)
        max_records: Maximum number of records to return
        max_size_mb: Maximum response size in MB
    
    Returns:
        Limited response data or error message if too large
    """
    # Check size
    size_mb = sys.getsizeof(data) / (1024 * 1024)
    
    if size_mb > max_size_mb:
        return json.dumps({
            "error": "Response too large",
            "size_mb": round(size_mb, 2),
            "max_size_mb": max_size_mb,
            "suggestion": "Use more specific filters to reduce data volume (e.g., filter by site_id, limit timeFrame, or break into multiple smaller queries)",
            "help": "You can adjust limits via CATO_MCP_MAX_SIZE_MB environment variable"
        }, indent=2)
    
    # Try to parse as JSON and limit records if applicable
    try:
        parsed = json.loads(data)
        
        # Handle different response structures
        records_field = None
        if isinstance(parsed, dict):
            # Check common record field names
            for field in ['records', 'items', 'data', 'results']:
                if field in parsed and isinstance(parsed[field], list):
                    records_field = field
                    break
        
        if records_field and len(parsed[records_field]) > max_records:
            original_count = len(parsed[records_field])
            parsed[records_field] = parsed[records_field][:max_records]
            parsed['_mcp_truncated'] = True
            parsed['_mcp_original_count'] = original_count
            parsed['_mcp_returned_count'] = max_records
            parsed['_mcp_suggestion'] = f"Response truncated to {max_records} records. Use more specific filters or break into smaller queries. Adjust via CATO_MCP_MAX_RECORDS environment variable."
            return json.dumps(parsed, indent=2)
    except (json.JSONDecodeError, TypeError):
        # Not JSON or can't parse, return as-is
        pass
    
    return data

def run_cato_command(args: list[str], timeout: int = QUERY_TIMEOUT_SECONDS) -> str:
    """Helper to run catocli commands with timeout support.
    
    Args:
        args: Command arguments to pass to catocli
        timeout: Timeout in seconds (default from CATO_MCP_TIMEOUT_SECONDS env var)
    
    Returns:
        Command output or error message
    """
    command = ["python3", "-m", "catocli"] + args
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        return limit_response_size(result.stdout)
    except subprocess.TimeoutExpired:
        return json.dumps({
            "error": f"Query timeout after {timeout}s",
            "suggestion": "Try reducing timeFrame, limiting buckets, or filtering by specific sites",
            "help": "Adjust timeout via CATO_MCP_TIMEOUT_SECONDS environment variable"
        }, indent=2)
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.stderr}"
    except FileNotFoundError:
        return "Error: catocli not found. Please ensure it is installed and in the PATH."

def extract_field_name_reference(help_text: str) -> dict:
    """Extract Field Name Reference section from help text.
    
    Args:
        help_text: The complete help text output
    
    Returns:
        Dictionary with field name information or empty dict if not found
    """
    import re
    
    result = {}
    
    # Look for "## Field Name Reference" section
    field_ref_match = re.search(
        r'## Field Name Reference\s*\n+(.*?)(?=\n##|\n####|$)',
        help_text,
        re.DOTALL
    )
    
    if not field_ref_match:
        return result
    
    field_section = field_ref_match.group(1)
    
    # Extract subsections like "### Valid values for appStatsFilter, dimension and measure"
    # The pattern needs to match: "Valid values: `field1`, `field2`, `field3`"
    subsection_pattern = r'### Valid values for ([^\n]+)\s*\nValid values: (.+?)(?=\n###|\n####|$)'
    
    for match in re.finditer(subsection_pattern, field_section, re.DOTALL):
        param_types = match.group(1).strip()
        valid_values_text = match.group(2).strip()
        
        # Extract all backtick-quoted field names
        fields = re.findall(r'`([^`]+)`', valid_values_text)
        
        result[param_types] = {
            'description': f'Valid values for {param_types}',
            'fields': fields,
            'count': len(fields)
        }
    
    return result

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
    - Field Name Reference - valid field names for filters, dimensions, and measures
    
    Args:
        command: The command path to get help for. Examples:
            - "" or "query" - List available query operations
            - "query appStatsTimeSeries" - Detailed help with examples
            - "entity" - List entity types
            - "mutation" - List mutation operations
            - "entity site" - Help for site entity operations
    
    Returns:
        Detailed help text including examples, parameters, field references, and usage patterns.
    """
    if not command:
        return run_cato_command(["-h"])
    
    cmd_parts = command.split()
    help_output = run_cato_command(cmd_parts + ["-h"])
    
    # Try to extract and enhance field name reference if present
    field_refs = extract_field_name_reference(help_output)
    if field_refs:
        # Add a summary at the beginning of the help output
        summary = "\n" + "="*80 + "\n"
        summary += "FIELD NAME REFERENCE SUMMARY\n"
        summary += "="*80 + "\n"
        for param_type, info in field_refs.items():
            summary += f"\n{info['description']} ({info['count']} fields):\n"
            # Group fields in rows of 5 for readability
            fields = info['fields']
            for i in range(0, len(fields), 5):
                row = fields[i:i+5]
                summary += "  " + ", ".join(row) + "\n"
        summary += "\n" + "="*80 + "\n\n"
        
        # Prepend summary to help output
        return summary + help_output
    
    return help_output

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
            ** WHEN TO USE eventsTimeSeries vs eventsFeed **:
            For ANY questions about security events, connectivity issues, threat analysis,
            operational events, forensics, or trend detection - ALWAYS use eventsTimeSeries.
            NEVER use eventsFeed for event analysis or questions about events.
            
            XDR (Extended Detection and Response):
            - xdr stories: Query XDR security stories (threat detections, incidents, investigations)
              * Use when: Asked about security incidents, threat detections, XDR alerts, or investigations
              * Example queries: "show me XDR stories", "security incidents last month", "threat detections"
              * REQUIRED: storyInput with filter and paging parameters
              * Filter options: timeFrame (required), status, severity, producer, analystVerdict, etc.
              * Paging: Use "from" and "limit" for pagination (limit max 100 per request)
              * Example:
                cato_query("xdr stories", [
                    '{"storyInput": {"filter": [{"timeFrame": {"time": "last.P1M"}}], "paging": {"from": 0, "limit": 100}}}'
                ])
            
            - xdr story: Get details for a specific XDR story by ID
              * Use when: Need detailed information about a specific security incident
              * REQUIRED: storyId parameter
              * Example: cato_query("xdr story", ['{"storyId": "abc123"}'])
            
            - eventsTimeSeries: Security and network events over time with time buckets
              * Use when: Asked about security events, threats, firewall blocks, connectivity,
                system status, configuration changes, or any event analysis
              * Use for: Threat detection, risk assessment, forensic investigation, pattern identification,
                event counts, event types, event trends, ANY questions about events
              * Example queries: "security events last 14 days", "firewall blocks today", "threat trends",
                "how many events occurred", "what types of events happened"
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
            
            - eventsFeed: Real-time event streaming ONLY - NOT for event analysis
              * CRITICAL: DO NOT use eventsFeed for questions about events, event analysis, or metrics
              * Use ONLY for: Pulling the latest real-time events for a specific marker/position
              * Requires: A marker (position) from a previous eventsFeed call to get the next batch
              * Purpose: Continuous event streaming and incremental feed updates
              * eventsFeed is NOT a query tool - it's a streaming feed for real-time monitoring
              * For ANY event questions, metrics, or analysis: Use eventsTimeSeries instead
            
            - events: Legacy events query (prefer eventsTimeSeries instead)
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
    
    # Validate query parameters and provide optimization warnings
    warnings = validate_query_params(operation, args)
    
    # Check rate limit
    if not rate_limiter.acquire(key=f"cato_query_{operation}"):
        wait_time = rate_limiter.get_wait_time(key=f"cato_query_{operation}")
        return json.dumps({
            "error": "Rate limit exceeded",
            "wait_seconds": round(wait_time, 1),
            "suggestion": f"Please wait {round(wait_time, 1)}s before retrying",
            "help": "Adjust rate limits via CATO_MCP_RATE_LIMIT_CALLS and CATO_MCP_RATE_LIMIT_PERIOD environment variables"
        }, indent=2)
    
    # Automatically inject filters if site_id, site_name, or user_id are provided
    filtered_args = _inject_filters(operation, args, site_id, site_name, user_id)
    
    # Check cache first (only for read-only query operations)
    cache_key_params = {'operation': operation, 'args': filtered_args, 'site_id': site_id, 'site_name': site_name, 'user_id': user_id}
    cached_result = query_cache.get(operation, cache_key_params)
    if cached_result:
        # Parse and add cache indicator
        try:
            result_data = json.loads(cached_result)
            if isinstance(result_data, dict):
                result_data['_mcp_cached'] = True
                result_data['_mcp_cache_ttl_seconds'] = CACHE_TTL_SECONDS
                if warnings:
                    result_data['_mcp_warnings'] = warnings
                return json.dumps(result_data, indent=2)
        except json.JSONDecodeError:
            pass
        # Return cached non-JSON result
        return cached_result
    
    # Execute query
    result = run_cato_command(["query", operation] + filtered_args)
    
    # Add warnings if any
    if warnings:
        try:
            result_data = json.loads(result)
            if isinstance(result_data, dict):
                result_data['_mcp_warnings'] = warnings
                result = json.dumps(result_data, indent=2)
        except json.JSONDecodeError:
            pass
    
    # Cache successful results (not errors)
    try:
        result_data = json.loads(result)
        if not result_data.get('error'):
            query_cache.set(operation, cache_key_params, result)
    except json.JSONDecodeError:
        # Cache non-JSON results too
        if not result.startswith('Error'):
            query_cache.set(operation, cache_key_params, result)
    
    return result

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

    # Silent startup mode (no stderr output) for MCP protocol compatibility
    # Can be disabled with CATO_MCP_VERBOSE=1 environment variable
    VERBOSE = os.getenv('CATO_MCP_VERBOSE', '0') == '1'
    
    if VERBOSE:
        print("Starting Cato MCP Server...", file=sys.stderr)
        print(f"Arguments: {sys.argv}", file=sys.stderr)

    # Ensure catocli is installed
    if VERBOSE:
        print("Ensuring catocli is installed...", file=sys.stderr)
    try:
        # Try using uv first as it's likely the environment manager
        subprocess.run(
            ["uv", "pip", "install", "catocli"],
            check=True,
            capture_output=True
        )
        if VERBOSE:
            print("Successfully installed/verified catocli using uv", file=sys.stderr)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to pip if uv fails or isn't found
        try:
            subprocess.run(
                ["pip3", "install", "catocli"],
                check=True,
                capture_output=True
            )
            if VERBOSE:
                print("Successfully installed/verified catocli using pip", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            if VERBOSE:
                print(f"Failed to install catocli: {e}", file=sys.stderr)
                print(f"Stderr: {e.stderr.decode() if e.stderr else 'None'}", file=sys.stderr)
            # We continue, hoping it's already there or the error was transient

    parser = argparse.ArgumentParser()
    parser.add_argument("--account-id", help="Cato Account ID")
    parser.add_argument("--cato-token", help="Cato API Token")
    parser.add_argument("--api-host", help="Cato API hostname (e.g., api.catonetworks.com)")
    args, unknown = parser.parse_known_args()

    # Priority: command line args > environment variables
    account_id = args.account_id or os.getenv('CATO_ACCOUNT_ID')
    cato_token = args.cato_token or os.getenv('CATO_API_KEY')
    api_host = args.api_host or os.getenv('CATO_API_HOST')
    
    # Construct full endpoint URL from hostname
    endpoint = None
    if api_host:
        # Strip any protocol and path if accidentally included
        api_host = api_host.replace('https://', '').replace('http://', '')
        api_host = api_host.split('/')[0]  # Take only hostname part
        # Construct full API URL
        endpoint = f"https://{api_host}/api/v1/graphql2"

    if account_id and cato_token:
        if VERBOSE:
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
            if VERBOSE:
                print(f"Successfully configured catocli for account {account_id}", file=sys.stderr)
                if result.stdout:
                    print(f"Config output: {result.stdout}", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            if VERBOSE:
                print(f"Failed to configure catocli: {e}", file=sys.stderr)
                print(f"Stdout: {e.stdout.decode() if e.stdout else 'None'}", file=sys.stderr)
                print(f"Stderr: {e.stderr.decode() if e.stderr else 'None'}", file=sys.stderr)
            #sys.exit(1)
    else:
        if VERBOSE:
            print("No configuration arguments provided. Assuming catocli is already configured.", file=sys.stderr)

    # Remove parsed arguments from sys.argv so FastMCP doesn't see them
    sys.argv = [sys.argv[0]] + unknown
    
    if VERBOSE:
        print("Starting FastMCP server...", file=sys.stderr)
    mcp.run()
