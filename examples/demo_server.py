"""Demo MCP server with mcp-guard protection.

Run with:
    python examples/demo_server.py

Then connect with any MCP client. Pass `x-mcp-role: admin` or
`x-mcp-role: viewer` header to see different tool sets.
"""

from mcp.server.mcpserver.server import MCPServer

from mcp_guard import Guard, HeaderResolver

# 1. Create your MCP server as usual
server = MCPServer("demo-support-server")


@server.tool()
def read_incident(incident_id: str) -> str:
    """Read an incident by ID."""
    return f"Incident {incident_id}: Server CPU at 99%"


@server.tool()
def search_kb(query: str) -> str:
    """Search the knowledge base."""
    return f"Found 3 articles matching '{query}'"


@server.tool()
def get_dashboard() -> str:
    """Get the operations dashboard."""
    return "Dashboard: 5 open incidents, 2 critical"


@server.tool()
def close_incident(incident_id: str, resolution: str) -> str:
    """Close an incident with a resolution."""
    return f"Incident {incident_id} closed: {resolution}"


@server.tool()
def reassign_incident(incident_id: str, assignee: str) -> str:
    """Reassign an incident to another team member."""
    return f"Incident {incident_id} reassigned to {assignee}"


@server.tool()
def delete_incident(incident_id: str) -> str:
    """Permanently delete an incident. Admin only."""
    return f"Incident {incident_id} permanently deleted"


# 2. Protect it with mcp-guard — one line
guard = Guard.from_yaml(
    "examples/policy.yaml",
    resolver=HeaderResolver("x-mcp-role"),
)
guard.protect(server)

# 3. Run
if __name__ == "__main__":
    server.run(transport="stdio")
