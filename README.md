# Cato CLI MCP Server

An MCP (Model Context Protocol) server that provides tools for interacting with Cato Networks API through the catocli command-line interface.

## Quick Start with Docker

### Using Docker Run

Run the MCP server directly with Docker:

```bash
docker run --rm -i \
  -e CATO_API_HOST=api.catonetworks.com \
  -e CATO_ACCOUNT_ID=your_account_id \
  -e CATO_API_KEY=your_api_key \
  catonetworks/cato-cli-mcp:latest
```

### Using Docker Compose

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and fill in your Cato credentials:
   ```properties
   CATO_API_HOST=api.catonetworks.com
   CATO_ACCOUNT_ID=your_account_id
   CATO_API_KEY=your_api_key
   ```

3. Start the server:
   ```bash
   docker-compose up -d
   ```

4. View logs:
   ```bash
   docker-compose logs -f
   ```

5. Stop the server:
   ```bash
   docker-compose down
   ```

## Configuration

The server requires the following environment variables:

| Variable | Description | Example | Default |
|----------|-------------|---------|----------|
| `CATO_API_HOST` | The hostname of the Cato API (hostname only, no protocol or path) | `api.catonetworks.com` | *required* |
| `CATO_ACCOUNT_ID` | Your Cato account ID | `1234567` | *required* |
| `CATO_API_KEY` | Your Cato API key for authentication | `123abc` | *required* |
| **Performance & Limits** |
| `CATO_MCP_MAX_RECORDS` | Maximum records to return before truncation | `30` | `50` |
| `CATO_MCP_MAX_SIZE_MB` | Maximum response size in MB before rejection | `3` | `5` |
| `CATO_MCP_TIMEOUT_SECONDS` | Query timeout in seconds | `180` | `120` |
| `CATO_MCP_CACHE_TTL` | Cache TTL in seconds (0 to disable) | `600` | `300` |
| `CATO_MCP_RATE_LIMIT_CALLS` | Max API calls per period | `20` | `999` (disabled) |
| `CATO_MCP_RATE_LIMIT_PERIOD` | Rate limit period in seconds | `60` | `60` |

**Note:** `CATO_API_HOST` should contain **only the hostname** (e.g., `api.catonetworks.com`). The server will automatically construct the full URL `https://api.catonetworks.com/api/v1/graphql2` when configuring catocli.

For details about your Cato API hostname, see: [What is the Cato API](https://support.catonetworks.com/hc/en-us/articles/20564679978397-What-is-the-Cato-API)

### Performance Features

The server includes several performance optimizations to prevent overwhelming AI clients (like Claude) and improve reliability:

#### Response Size Limits
- **Record Limits**: If a response contains more than `CATO_MCP_MAX_RECORDS` items (default: 50), it will be truncated and a warning will be added to the response.
- **Size Limits**: If a response exceeds `CATO_MCP_MAX_SIZE_MB` megabytes (default: 5), an error is returned with suggestions to use filters.

#### Query Timeouts
- **Timeout Protection**: Queries that exceed `CATO_MCP_TIMEOUT_SECONDS` (default: 120s) will be terminated with a helpful error message.
- Prevents hanging queries that could lock up the MCP server.

#### Response Caching
- **Automatic Caching**: Query results are cached for `CATO_MCP_CACHE_TTL` seconds (default: 300s/5 minutes).
- Reduces API load and improves response times for repeated queries.
- Cached responses include `_mcp_cached: true` metadata.
- Set to `0` to disable caching.

#### Rate Limiting
- **API Protection**: Limits calls to prevent API abuse (disabled by default).
- Configure via `CATO_MCP_RATE_LIMIT_CALLS` and `CATO_MCP_RATE_LIMIT_PERIOD`.
- Returns clear error with wait time when limit exceeded.

#### Query Optimization Hints
- **Automatic Validation**: Warns about high bucket counts, missing filters, and other performance issues.
- Suggestions appear in `_mcp_warnings` field of response.

When limits are hit, you'll receive helpful suggestions to:
- Use more specific filters (e.g., filter by `site_id`)
- Limit the timeFrame for time-series queries
- Break large queries into smaller batches

**Example configuration with custom settings:**
```json
{
  "mcpServers": {
    "cato": {
      "env": {
        "CATO_API_HOST": "api.catonetworks.com",
        "CATO_ACCOUNT_ID": "12345",
        "CATO_API_KEY": "YOUR_KEY",
        "CATO_MCP_MAX_RECORDS": "30",
        "CATO_MCP_MAX_SIZE_MB": "3",
        "CATO_MCP_TIMEOUT_SECONDS": "180",
        "CATO_MCP_CACHE_TTL": "600",
        "CATO_MCP_RATE_LIMIT_CALLS": "20",
        "CATO_MCP_RATE_LIMIT_PERIOD": "60"
      }
    }
  }
}
```

## Claude Desktop Configuration

Add the following to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cato": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e",
        "CATO_API_HOST=api.catonetworks.com",
        "-e",
        "CATO_ACCOUNT_ID=12345",
        "-e",
        "CATO_API_KEY=XXXXXXXXXXX",
        "catonetworks/cato-cli-mcp:latest"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}

```

## Available Tools

The server provides the following MCP tools:

- **catocli_help**: Get detailed help for any catocli command with examples and syntax
- **cato_entity**: Lookup entities (sites, users, hosts, network interfaces, etc.)
- **cato_query**: Execute query operations to retrieve analytics and configuration data:
  - **Bandwidth & Traffic Analytics**: `appStats`, `appStatsTimeSeries`, `socketPortMetrics`, `socketPortMetricsTimeSeries`
  - **Network & Sites**: `accountSnapshot`, `site`, `siteLocation`, `entityLookup`
  - **Security & Events**: `events`, `eventsTimeSeries`, `eventsFeed`, `auditFeed`
  - **Administration**: `admins`, `policy`, `hardware`
- **cato_mutation**: Execute mutation operations (manage account, policies, sites, etc.)
- **cato_raw**: Execute raw GraphQL queries

### Common Use Cases

**Get bandwidth by application per site:**
```
Ask Claude: "Show me application bandwidth usage by site for the last 24 hours"
```

**Get WAN link utilization:**
```
Ask Claude: "Show me WAN port bandwidth metrics for all sites"
```

**List all sites:**
```
Ask Claude: "List all my Cato sites"
```

**View security events:**
```
Ask Claude: "Show me security events from the last hour"
```

## Development

### Building the Docker Image

```bash
docker build -t catonetworks/cato-cli-mcp .
```

### Local Development

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the server locally:
   ```bash
   python server.py --account-id YOUR_ID --cato-token YOUR_TOKEN --endpoint api.catonetworks.com
   ```

   Or use environment variables:
   ```bash
   export CATO_ACCOUNT_ID=your_account_id
   export CATO_API_KEY=your_api_key
   export CATO_API_HOST=api.catonetworks.com
   python server.py
   ```

## License

See LICENSE file for details.