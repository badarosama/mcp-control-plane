# mcp-control-plane

**Prevent AI agents from calling dangerous tools in production.**

Your MCP server exposes 20 tools to an AI agent. It's 3am. The agent is in a loop, calling `refund_customer` with $99,999 amounts because the LLM hallucinated a batch operation. Nobody is watching. There's no record of what happened.

**mcp-control-plane** is the runtime safety layer between your AI agent and your MCP tools. It prevents loops, validates arguments, enforces dry-runs for destructive actions, and records every decision for post-incident replay.

```
pip install mcp-control-plane
```

## The Problem

The [MCP protocol](https://modelcontextprotocol.io) gives you `tools/list` and `tools/call` — but says nothing about safety. Every tool call goes straight through.

| Risk | What happens | mcp-control-plane |
|------|-------------|-------------------|
| Agent loops | 200 calls to the same tool | **Tool budgets**: max N calls per session/tool |
| Bad arguments | `refund($999,999)` | **Argument rules**: max, min, pattern, one_of |
| Destructive actions | `delete_user` without thinking | **Dry-run mode**: preview first, confirm to execute |
| "What happened?" | No trace after incident | **Execution trace**: full flight recorder as JSON |
| Wrong permissions | Intern's agent calls admin tools | **Role-based access**: filter visibility + block calls |

## Quick Start

### 1. Define a safety policy

```yaml
# policy.yaml
default_role: operator
deny_by_default: true

budgets:
  max_calls_per_session: 100
  max_calls_per_tool: 20

roles:
  operator:
    can_see: [read_incident, close_incident, refund_customer]
    can_call: [read_incident, close_incident, refund_customer]
  admin:
    can_see: ["*"]
    can_call: ["*"]

tools:
  refund_customer:
    rules:
      amount: { max: 500, min: 0.01 }
      reason: { min_length: 10 }
    max_calls: 5

  delete_user:
    require_dry_run: true
```

### 2. Protect your server

```python
from mcp.server.mcpserver.server import MCPServer
from mcp_guard import Guard

server = MCPServer("my-server")

# ... define your tools with @server.tool() ...

guard = Guard.from_yaml("policy.yaml", enable_trace=True)
guard.protect(server)
```

That's it. Every tool call now passes through the safety pipeline.

## Features

### 1. Tool Budgeting — Prevent Agent Loops

Agents loop. An LLM decides "I need to check status" and calls the same tool 200 times. Budgets cap this.

```yaml
budgets:
  max_calls_per_session: 100    # total across all tools
  max_calls_per_tool: 20        # default per-tool cap

tools:
  expensive_api:
    max_calls: 3                # override: stricter limit for costly tools
```

When exceeded:
```
tools/call expensive_api → DENIED "Tool budget exceeded: 'expensive_api' called 3/3 times"
```

### 2. Argument Validation — Block Dangerous Values

The agent is authorized to call `refund`, but tries `refund(amount=99999)`. RBAC says yes. The safety policy says no.

```yaml
tools:
  refund_customer:
    rules:
      amount:
        max: 500
        min: 0.01
      reason:
        min_length: 10
  
  restart_service:
    rules:
      service_name:
        pattern: "^[a-z][a-z0-9-]+$"    # no spaces, no injection
        max_length: 63

  set_priority:
    rules:
      level:
        one_of: [low, medium, high, critical]
```

Available rule types:
| Rule | Type | Example |
|------|------|---------|
| `max` | number | `{ max: 500 }` |
| `min` | number | `{ min: 0.01 }` |
| `equals` | any | `{ equals: true }` |
| `min_length` | string | `{ min_length: 10 }` |
| `max_length` | string | `{ max_length: 255 }` |
| `pattern` | regex | `{ pattern: "^[a-z]+$" }` |
| `one_of` | list | `{ one_of: [low, medium, high] }` |

### 3. Dry-Run Mode — Preview Before You Destroy

Dangerous tools require a preview execution before the real thing runs.

```yaml
tools:
  delete_user:
    require_dry_run: true
  drop_database:
    require_dry_run: true
```

Flow:
```
# First call — preview only, nothing destructive happens
tools/call delete_user { user_id: "123" }
→ [DRY RUN PREVIEW] User 123 would be deleted. Call again with _dry_run_confirm: true to execute.

# Second call — confirmed, executes for real
tools/call delete_user { user_id: "123", _dry_run_confirm: true }
→ User 123 permanently deleted
```

The agent sees what would happen before it happens. Audit log records both the preview and the confirmation.

### 4. Execution Trace — The Flight Recorder

After an incident, you need to know: what did the agent do? The trace records every tool interaction — not just allow/deny, but arguments, results, and timing.

```python
guard = Guard.from_yaml("policy.yaml", enable_trace=True)
guard.protect(server)

# Later, after an incident:
print(guard.export_trace())
```

Output:
```json
[
  {
    "timestamp": "2026-06-15T10:00:00+00:00",
    "tool": "refund_customer",
    "arguments": {"customer_id": "C-789", "amount": 99999, "reason": "batch"},
    "decision": "VALIDATION_FAILED",
    "role": "operator",
    "violations": ["amount: value 99999 exceeds maximum 500.0"]
  },
  {
    "timestamp": "2026-06-15T10:00:01+00:00",
    "tool": "refund_customer",
    "arguments": {"customer_id": "C-789", "amount": 50, "reason": "customer complaint about service"},
    "decision": "ALLOW",
    "role": "operator",
    "duration_ms": 145.2
  },
  {
    "timestamp": "2026-06-15T10:00:02+00:00",
    "tool": "delete_user",
    "arguments": {"user_id": "U-456"},
    "decision": "DRY_RUN_PREVIEW",
    "role": "operator"
  }
]
```

### 5. Role-Based Access Control

Different roles see different tools. Same server, different views.

```yaml
roles:
  viewer:
    can_see: [read_incident, search_kb]
    can_call: [read_incident, search_kb]
  operator:
    can_see: [read_incident, close_incident, refund_customer]
    can_call: [read_incident, close_incident, refund_customer]
  admin:
    can_see: ["*"]
    can_call: ["*"]
```

Two layers of enforcement:
- **tools/list**: filter what the client sees (cosmetic)
- **tools/call**: block what the client executes (enforcement)

Even if a client caches the tool list or ignores `notifications/tools/list_changed`, the call-time check always blocks unauthorized execution.

### 6. Audit Logging

Every decision is logged as structured JSON:

```json
{"timestamp": "2026-06-15T10:00:00+00:00", "action": "tools/call", "tool": "refund_customer", "role": "operator", "decision": "VALIDATION_FAILED", "reason": "amount: value 99999 exceeds maximum 500.0"}
{"timestamp": "2026-06-15T10:00:01+00:00", "action": "tools/call", "tool": "delete_user", "role": "operator", "decision": "DRY_RUN_PREVIEW"}
{"timestamp": "2026-06-15T10:00:02+00:00", "action": "tools/call", "tool": "read_incident", "role": "viewer", "decision": "ALLOW"}
```

Decision types: `ALLOW`, `DENY`, `BUDGET_EXCEEDED`, `VALIDATION_FAILED`, `DRY_RUN_PREVIEW`, `DRY_RUN_CONFIRMED`

Custom loggers:
```python
# JSON to stderr (default)
guard = Guard.from_yaml("policy.yaml")

# Python standard logging
from mcp_guard import PythonLoggingAuditLogger
guard = Guard.from_yaml("policy.yaml", audit_logger=PythonLoggingAuditLogger())

# Custom — send to Datadog, Splunk, wherever
class MyLogger:
    def log(self, event):
        send_to_datadog(event.to_dict())

guard = Guard.from_yaml("policy.yaml", audit_logger=MyLogger())
```

## Safety Pipeline

Every `tools/call` passes through this pipeline in order:

```
1. RBAC check         → DENY if role cannot call this tool
2. Budget check       → DENY if session or tool budget exceeded
3. Argument validation → DENY if arguments violate safety rules
4. Dry-run check      → PREVIEW if tool requires confirmation
5. Execute tool
6. Record trace       → full execution record for replay
7. Record budget      → increment call counters
```

Each layer is independent. If RBAC denies, budget is never checked. If budget exceeds, arguments are never validated. Fast-fail, minimal overhead.

## Role Resolvers

How does mcp-control-plane know who's calling?

```python
# HTTP header (default)
Guard.from_yaml("policy.yaml", resolver=HeaderResolver("x-mcp-role"))

# JWT token claim
Guard.from_yaml("policy.yaml", resolver=JWTResolver(claim="role", secret="..."))

# API key mapping
Guard.from_yaml("policy.yaml", resolver=APIKeyResolver({"sk-abc": "admin", "sk-xyz": "viewer"}))

# Static (testing)
Guard.from_yaml("policy.yaml", resolver=StaticResolver("admin"))

# Custom function
Guard.from_yaml("policy.yaml", resolver=CallableResolver(lambda ctx: lookup_role(ctx)))
```

## Integration Paths

### MCPServer (FastMCP) — Recommended

```python
from mcp.server.mcpserver.server import MCPServer
from mcp_guard import Guard

server = MCPServer("my-server")
guard = Guard.from_yaml("policy.yaml")
guard.protect(server)
```

Wraps `list_tools()` and `call_tool()` — public, stable API that survives SDK upgrades.

### Low-level Server — Full Per-Request Context

```python
from mcp.server.lowlevel.server import Server
from mcp_guard import Guard

server = Server("my-server", on_list_tools=..., on_call_tool=...)
guard = Guard.from_yaml("policy.yaml")
server.middleware.append(guard.as_middleware())
```

Uses the SDK's `ServerMiddleware` protocol. Full access to per-request headers and session for role resolution.

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                     MCP Client                         │
│               (Claude, Cursor, etc.)                   │
└───────────────────────┬───────────────────────────────┘
                        │ JSON-RPC
┌───────────────────────▼───────────────────────────────┐
│              mcp-control-plane                         │
│                                                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │  RBAC    │→│  Budget  │→│ Argument │→│ Dry-Run  │ │
│  │  Filter  │ │  Limits  │ │ Validate │ │ Enforce  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                        │
│  ┌──────────────────┐  ┌──────────────────────────┐   │
│  │   Audit Logger   │  │   Execution Trace        │   │
│  │  (every decision) │  │  (args + results + time) │   │
│  └──────────────────┘  └──────────────────────────┘   │
└───────────────────────┬───────────────────────────────┘
                        │
┌───────────────────────▼───────────────────────────────┐
│                    MCP Server                          │
│              (your tools, untouched)                   │
└───────────────────────────────────────────────────────┘
```

## Policy Reference

```yaml
# Defaults when role cannot be resolved
default_role: viewer
deny_by_default: true

# Global call budgets (optional)
budgets:
  max_calls_per_session: 100    # total across all tools
  max_calls_per_tool: 20        # default per-tool cap

# Role-based access (optional, but recommended)
roles:
  <role_name>:
    can_see: [tool1, tool2, "prefix_*", "*"]
    can_call: [tool1, "prefix_*"]

# Per-tool safety rules (optional)
tools:
  <tool_name>:
    max_calls: 5                 # overrides budgets.max_calls_per_tool
    require_dry_run: true        # must preview before executing
    rules:
      <argument_name>:
        max: 500                 # numeric maximum
        min: 0                   # numeric minimum
        equals: true             # exact match
        min_length: 10           # string minimum length
        max_length: 255          # string maximum length
        pattern: "^[a-z]+$"      # regex match
        one_of: [a, b, c]        # allowed values
```

All sections are optional. An empty policy file with just `deny_by_default: false` allows everything through.

## Installation

```bash
pip install mcp-control-plane             # core
pip install mcp-control-plane[jwt]        # + JWT role resolver
pip install mcp-control-plane[otel]       # + OpenTelemetry tracing
pip install mcp-control-plane[dev]        # + dev tools
```

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
