"""Demo using mcp-guard with the low-level Server class.

This approach uses the SDK's ServerMiddleware protocol for full per-request
context (headers, session). Recommended for Streamable HTTP / SSE transports
where you need per-user role resolution.
"""

from mcp.server.lowlevel.server import Server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

from mcp_guard import Guard, HeaderResolver, Policy


# Define tools
TOOLS = [
    Tool(name="get_status", description="Get system status", inputSchema={"type": "object", "properties": {}}),
    Tool(name="restart_service", description="Restart a service", inputSchema={"type": "object", "properties": {"service": {"type": "string"}}}),
    Tool(name="drop_database", description="Drop a database (dangerous!)", inputSchema={"type": "object", "properties": {"db": {"type": "string"}}}),
]


async def handle_list_tools(ctx, params: PaginatedRequestParams | None) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


async def handle_call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=f"Called {params.name}")])


# Create low-level server
server = Server(
    "demo-lowlevel",
    on_list_tools=handle_list_tools,
    on_call_tool=handle_call_tool,
)

# Create guard and attach as middleware — full per-request context
policy = Policy.from_dict({
    "default_role": "monitor",
    "roles": {
        "monitor": {
            "can_see": ["get_status"],
            "can_call": ["get_status"],
        },
        "admin": {
            "can_see": ["*"],
            "can_call": ["*"],
        },
    },
})

guard = Guard(policy=policy, resolver=HeaderResolver("x-mcp-role"))
server.middleware.append(guard.as_middleware())
