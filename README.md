# Cato CLI MCP Server

An MCP (Model Context Protocol) server that provides tools for interacting with Cato Networks API through the catocli command-line interface.

## Prerequisites

Before using this MCP server, you need to have Docker installed on your system.

<details>
<summary><b>Install Docker Desktop</b> (click to expand)</summary>

### macOS

1. Download Docker Desktop for Mac from the [official Docker website](https://www.docker.com/products/docker-desktop/)
   - For Apple Silicon (M1/M2/M3): Download the **Apple Chip** version
   - For Intel processors: Download the **Intel Chip** version

2. Open the downloaded `.dmg` file and drag Docker to your Applications folder

3. Launch Docker Desktop from Applications

4. Follow the on-screen instructions to complete the installation

5. Verify Docker is installed:
   ```bash
   docker --version
   docker compose version
   ```

### Windows

1. **System Requirements:**
   - Windows 10 64-bit: Pro, Enterprise, or Education (Build 19041 or higher)
   - Windows 11 64-bit: Pro, Enterprise, or Education
   - WSL 2 feature enabled

2. **Enable WSL 2:**
   ```powershell
   wsl --install
   ```
   Restart your computer if prompted.

3. **Download and Install Docker Desktop:**
   - Download Docker Desktop for Windows from the [official Docker website](https://www.docker.com/products/docker-desktop/)
   - Run the installer and follow the installation wizard
   - Ensure "Use WSL 2 instead of Hyper-V" option is selected

4. **Launch Docker Desktop** and complete the initial setup

5. **Verify Docker is installed:**
   ```powershell
   docker --version
   docker compose version
   ```

For detailed installation instructions, see the [official Docker documentation](https://docs.docker.com/get-docker/).

</details>

## Add the following to Claude-Desktop config file:

## Claude Desktop Configuration

Add the following to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cato": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--pull", "always",
        "-e", "CATO_API_HOST=api.catonetworks.com",
        "-e", "CATO_ACCOUNT_ID=12345",
        "-e", "CATO_API_KEY=XXXXXXXXX",
        "ghcr.io/catonetworks/cato-cli-mcp:latest"
      ]
    }
  }
}
```

### Windows Configuration
File location: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cato": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "--rm", "-i", "--pull", "always",
        "-e", "CATO_API_HOST=api.catonetworks.com",
        "-e", "CATO_ACCOUNT_ID=12345",
        "-e", "CATO_API_KEY=XXXXXXXXX",
        "ghcr.io/catonetworks/cato-cli-mcp:latest"
      ]
    }
  }
}
```

**Note:** On Windows, you can access the config file by:
1. Press `Win + R`
2. Type `%APPDATA%\Claude` and press Enter
3. Edit `claude_desktop_config.json` with your preferred text editor


### Notes:
- The `--pull always` option ensures that the AI Agent application (e.g. Claude-Desktop) uses cato-mcp-server's most updated version.\
The AI Agent application running cato-mcp-server might open a popup asking for permissions to access data from other apps.\
<img width="262" height="250" alt="image" src="https://github.com/user-attachments/assets/584ce9d3-8bcf-4109-9dcc-3b7ca948e6e4" />\
  - If you don't wish to allow this, you can remove the `--pull always` option, but then you will need to manually update the image when a new version is released by executing:
  ```bash
  docker pull ghcr.io/catonetworks/cato-mcp-server:latest
  ```

## Configuration
The server requires the following environment variables:
```properties
# The hostname of the Cato API (without protocol). e.g.: api.catonetworks.com
# For details about your Cato API hostname, please see: https://support.catonetworks.com/hc/en-us/articles/20564679978397-What-is-the-Cato-API
CATO_API_HOST: "api.catonetworks.com"
# The Cato account-id
CATO_ACCOUNT_ID: "1234567"
# The Cato API-KEY for authentication
CATO_API_KEY: "123abc"
```

<details>
<summary><b>Configuration Options</b> (click to expand)</summary>

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
|| **Debugging** |
|| `CATO_MCP_VERBOSE` | Enable verbose startup logging to stderr (for debugging) | `1` | `0` (silent) |

**Note:** `CATO_API_HOST` should contain **only the hostname** (e.g., `api.catonetworks.com`). The server will automatically construct the full URL `https://api.catonetworks.com/api/v1/graphql2` when configuring catocli.

For details about your Cato API hostname, see: [What is the Cato API](https://support.catonetworks.com/hc/en-us/articles/20564679978397-What-is-the-Cato-API)

## Performance Features

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

</details>



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