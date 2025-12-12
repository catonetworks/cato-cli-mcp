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

| Variable | Description | Example |
|----------|-------------|----------|
| `CATO_API_HOST` | The hostname of the Cato API (without protocol) | `api.catonetworks.com` |
| `CATO_ACCOUNT_ID` | Your Cato account ID | `1234567` |
| `CATO_API_KEY` | Your Cato API key for authentication | `123abc` |

For details about your Cato API hostname, see: [What is the Cato API](https://support.catonetworks.com/hc/en-us/articles/20564679978397-What-is-the-Cato-API)

## Claude Desktop Configuration

Add the following to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cato-cli": {
      "command": "docker",
      "args": [
          "run",
          "--rm",
          "-i",
          "-e", "CATO_API_HOST=api.catonetworks.com",
          "-e", "CATO_ACCOUNT_ID=<your_account_id>",
          "-e", "CATO_API_KEY=<your_api_key>",
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