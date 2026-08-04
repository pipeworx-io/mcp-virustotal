# @pipeworx/virustotal

VirusTotal MCP — file / URL / domain / IP reputation. BYO API key.

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1394+ live data sources.

## Tools

- `lookup_file(hash)`
- `lookup_url(url)`
- `lookup_domain(domain)`
- `lookup_ip(ip)`

## Auth

BYO only — free tier is 4 req/min and 500/day per key. Pass `?_apiKey=<key>` on the gateway URL. Register at https://www.virustotal.com/gui/join-us.

## Data source

`https://www.virustotal.com/api/v3` — header `x-apikey`.

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "virustotal": {
      "url": "https://gateway.pipeworx.io/virustotal/mcp"
    }
  }
}
```

Or connect to the full Pipeworx gateway for access to all 1394+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Virustotal data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
