"""Demo: Agent Runtime Safety Engine

Shows all mcp-control-plane features:
- Tool budgeting (prevent loops)
- Argument validation (block dangerous values)
- Dry-run mode (preview before destructive actions)
- Execution trace (flight recorder)
- Role-based access control

Run with:
    python examples/agent_safety_demo.py
"""

from mcp.server.mcpserver.server import MCPServer

from mcp_guard import Guard, HeaderResolver

server = MCPServer("safety-demo")


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
def close_incident(incident_id: str) -> str:
    """Close an incident."""
    return f"Incident {incident_id} closed"


@server.tool()
def refund_customer(customer_id: str, amount: float, reason: str) -> str:
    """Issue a refund to a customer."""
    return f"Refunded ${amount:.2f} to customer {customer_id}: {reason}"


@server.tool()
def delete_user(user_id: str, confirm: bool = False) -> str:
    """Permanently delete a user account."""
    return f"User {user_id} permanently deleted"


@server.tool()
def drop_database(database_name: str) -> str:
    """Drop a database. Extremely dangerous."""
    return f"Database '{database_name}' dropped"


@server.tool()
def restart_service(service_name: str) -> str:
    """Restart a running service."""
    return f"Service '{service_name}' restarted"


# Protect with full safety policy + tracing enabled
guard = Guard.from_yaml(
    "examples/safety_policy.yaml",
    resolver=HeaderResolver("x-mcp-role"),
    enable_trace=True,
)
guard.protect(server)

# What happens now:
#
# 1. RBAC: viewer only sees 3 tools, operator sees 5, admin sees all 8
#
# 2. Budgets: max 100 calls per session, max 20 per tool, but:
#    - refund_customer: max 5 calls (stricter)
#    - drop_database: max 1 call
#
# 3. Validation:
#    - refund_customer(amount=99999) → DENIED (max 500)
#    - refund_customer(reason="ok")  → DENIED (min_length 10)
#    - restart_service(service_name="INVALID NAME!") → DENIED (pattern)
#
# 4. Dry-run:
#    - delete_user(user_id="123") → preview only
#    - delete_user(user_id="123", _dry_run_confirm=True) → executes for real
#    - drop_database("prod") → preview only, must confirm
#
# 5. Trace: guard.export_trace() returns full JSON history

if __name__ == "__main__":
    server.run(transport="stdio")
