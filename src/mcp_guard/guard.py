"""Guard — the core runtime safety engine for mcp-control-plane.

Intercepts MCP tool calls with a layered enforcement pipeline:
1. RBAC         — can this role call this tool?
2. Budget       — has the session/tool exceeded call limits?
3. Validation   — do the arguments pass safety rules?
4. Dry-run      — does this tool require preview before execution?
5. Execute
6. Trace        — record full execution for replay
7. Budget tick  — increment counters
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mcp_guard.audit import AuditEvent, AuditLogger, ConsoleAuditLogger, _now_iso
from mcp_guard.budget import SessionBudget
from mcp_guard.dryrun import DRY_RUN_CONFIRM_KEY, DryRunTracker
from mcp_guard.policy import Policy
from mcp_guard.resolvers import HeaderResolver, RoleResolver
from mcp_guard.trace import AgentTrace, TraceEntry
from mcp_guard.validation import ArgumentValidator

logger = logging.getLogger("mcp_guard")


class Guard:
    """Agent runtime safety engine for MCP servers.

    Usage:
        guard = Guard(policy=Policy.from_yaml("policy.yaml"))
        guard.protect(server)  # wraps MCPServer (FastMCP)

        # OR for low-level Server:
        server.middleware.append(guard.as_middleware())
    """

    def __init__(
        self,
        policy: Policy,
        resolver: RoleResolver | None = None,
        audit_logger: AuditLogger | None = None,
        audit: bool = True,
        on_deny: str = "error",
        enable_trace: bool = False,
        trace: AgentTrace | None = None,
    ) -> None:
        self.policy = policy
        self.resolver = resolver or HeaderResolver()
        self.audit_logger = audit_logger or (ConsoleAuditLogger() if audit else None)
        self.on_deny = on_deny
        self.trace = trace or (AgentTrace() if enable_trace else None)
        self._budgets: dict[str, SessionBudget] = {}
        self._dry_run_tracker = DryRunTracker()

    @classmethod
    def from_yaml(
        cls,
        path: str | Path,
        resolver: RoleResolver | None = None,
        audit_logger: AuditLogger | None = None,
        audit: bool = True,
        enable_trace: bool = False,
    ) -> Guard:
        """Create a Guard from a YAML policy file."""
        return cls(
            policy=Policy.from_yaml(path),
            resolver=resolver,
            audit_logger=audit_logger,
            audit=audit,
            enable_trace=enable_trace,
        )

    def _get_budget(self, session_id: str = "__default__") -> SessionBudget:
        if session_id not in self._budgets:
            self._budgets[session_id] = SessionBudget(
                max_calls_per_session=self.policy.budgets.max_calls_per_session,
                max_calls_per_tool=self.policy.budgets.max_calls_per_tool,
            )
        return self._budgets[session_id]

    def _audit(
        self, action: str, tool: str, role: str | None, decision: str, reason: str | None = None
    ) -> None:
        if self.audit_logger is None:
            return
        event = AuditEvent(
            timestamp=_now_iso(),
            action=action,
            tool=tool,
            role=role,
            decision=decision,
            reason=reason,
        )
        self.audit_logger.log(event)

    def _trace(
        self,
        tool: str,
        arguments: dict[str, Any],
        decision: str,
        role: str | None = None,
        session_id: str | None = None,
        result_summary: str | None = None,
        duration_ms: float | None = None,
        violations: list[str] | None = None,
    ) -> None:
        if self.trace is None:
            return
        self.trace.record(TraceEntry(
            timestamp=_now_iso(),
            tool=tool,
            arguments=arguments,
            decision=decision,
            role=role,
            session_id=session_id,
            result_summary=result_summary,
            duration_ms=duration_ms,
            violations=violations,
        ))

    def _deny(self, message: str) -> None:
        """Raise an MCPError or return None based on on_deny setting."""
        if self.on_deny == "error":
            from mcp.shared.exceptions import MCPError
            raise MCPError(code=-32600, message=message)

    def protect(self, server: Any) -> None:
        """Wrap an MCPServer (FastMCP) instance with the safety engine.

        Wraps list_tools() and call_tool() — public, stable API.
        """
        self._wrap_list_tools(server)
        self._wrap_call_tool(server)
        logger.info(
            "mcp-control-plane: protecting server %r — %d roles, %d tool policies",
            getattr(server, "name", "unknown"),
            len(self.policy.roles),
            len(self.policy.tools),
        )

    def _wrap_list_tools(self, server: Any) -> None:
        original_list_tools = server.list_tools

        async def guarded_list_tools() -> list[Any]:
            tools = await original_list_tools()
            filtered = []
            for tool in tools:
                tool_name = getattr(tool, "name", str(tool))
                if self.policy.can_see(self.policy.default_role, tool_name):
                    filtered.append(tool)
                else:
                    self._audit("tools/list", tool_name, self.policy.default_role, "DENY", "not in can_see")
            return filtered

        server.list_tools = guarded_list_tools

    def _wrap_call_tool(self, server: Any) -> None:
        original_call_tool = server.call_tool

        async def guarded_call_tool(name: str, arguments: dict[str, Any], context: Any = None) -> Any:
            role = None
            session_id = "__default__"
            if context is not None:
                request_ctx = getattr(context, "_request_context", None) or getattr(context, "request_context", None)
                if request_ctx is not None:
                    role = self.resolver.resolve(request_ctx)
            if role is None:
                role = self.policy.default_role

            # 1. RBAC check
            if not self.policy.can_call(role, name):
                self._audit("tools/call", name, role, "DENY", "not in can_call")
                self._trace(name, arguments, "DENY", role, session_id)
                self._deny(f"Unauthorized: role '{role or 'unknown'}' cannot call '{name}'")
                return None

            # 2. Budget check
            budget = self._get_budget(session_id)
            tool_max = self.policy.get_max_calls_for_tool(name)
            budget_error = budget.check(name, tool_max)
            if budget_error:
                self._audit("tools/call", name, role, "BUDGET_EXCEEDED", budget_error)
                self._trace(name, arguments, "BUDGET_EXCEEDED", role, session_id)
                self._deny(f"Budget exceeded: {budget_error}")
                return None

            # 3. Argument validation
            violations = self.policy.validate_arguments(name, arguments)
            if violations:
                reason = "; ".join(violations)
                self._audit("tools/call", name, role, "VALIDATION_FAILED", reason)
                self._trace(name, arguments, "VALIDATION_FAILED", role, session_id, violations=violations)
                self._deny(f"Argument validation failed: {reason}")
                return None

            # 4. Dry-run check
            tool_policy = self.policy.get_tool_policy(name)
            if tool_policy and tool_policy.require_dry_run:
                if self._dry_run_tracker.needs_dry_run(session_id, name, arguments):
                    start = time.monotonic()
                    result = await original_call_tool(name, arguments, context)
                    duration = (time.monotonic() - start) * 1000
                    preview = f"[DRY RUN PREVIEW] {_result_summary(result)}"
                    self._dry_run_tracker.record_dry_run(session_id, name, arguments, result)
                    self._audit("tools/call", name, role, "DRY_RUN_PREVIEW")
                    self._trace(name, arguments, "DRY_RUN_PREVIEW", role, session_id, preview, duration)
                    budget.record(name)
                    return _wrap_dry_run_result(result)

                if self._dry_run_tracker.is_confirmation(session_id, name, arguments):
                    self._dry_run_tracker.consume_dry_run(session_id, name)
                    clean_args = {k: v for k, v in arguments.items() if k != DRY_RUN_CONFIRM_KEY}
                    start = time.monotonic()
                    result = await original_call_tool(name, clean_args, context)
                    duration = (time.monotonic() - start) * 1000
                    self._audit("tools/call", name, role, "DRY_RUN_CONFIRMED")
                    self._trace(name, clean_args, "DRY_RUN_CONFIRMED", role, session_id, _result_summary(result), duration)
                    budget.record(name)
                    return result

            # 5. Execute
            start = time.monotonic()
            result = await original_call_tool(name, arguments, context)
            duration = (time.monotonic() - start) * 1000

            # 6. Trace + audit
            self._audit("tools/call", name, role, "ALLOW")
            self._trace(name, arguments, "ALLOW", role, session_id, _result_summary(result), duration)

            # 7. Budget tick
            budget.record(name)

            return result

        server.call_tool = guarded_call_tool

    def as_middleware(self) -> Any:
        """Return a ServerMiddleware for the low-level Server class.

        Full per-request context for role resolution.
        """
        guard = self

        async def middleware(
            ctx: Any,
            method: str,
            params: Mapping[str, Any] | None,
            call_next: Any,
        ) -> Any:
            if method == "tools/list":
                result = await call_next()
                if result is None:
                    return result

                role = guard.resolver.resolve(ctx)
                if role is None:
                    role = guard.policy.default_role

                tools = None
                if hasattr(result, "tools"):
                    tools = result.tools
                elif isinstance(result, dict):
                    tools = result.get("tools")

                if tools is not None:
                    filtered = []
                    for tool in tools:
                        tool_name = getattr(tool, "name", None) or (tool.get("name") if isinstance(tool, dict) else str(tool))
                        if guard.policy.can_see(role, tool_name):
                            filtered.append(tool)
                        else:
                            guard._audit("tools/list", tool_name, role, "DENY", "not in can_see")

                    if hasattr(result, "tools"):
                        result.tools = filtered
                    elif isinstance(result, dict):
                        result["tools"] = filtered

                return result

            if method == "tools/call":
                tool_name = params.get("name", "") if params else ""
                arguments = dict(params.get("arguments", {})) if params else {}
                role = guard.resolver.resolve(ctx)
                if role is None:
                    role = guard.policy.default_role

                session_id = _extract_session_id(ctx)

                # 1. RBAC
                if not guard.policy.can_call(role, tool_name):
                    guard._audit("tools/call", tool_name, role, "DENY", "not in can_call")
                    guard._trace(tool_name, arguments, "DENY", role, session_id)
                    guard._deny(f"Unauthorized: role '{role or 'unknown'}' cannot call '{tool_name}'")
                    return None

                # 2. Budget
                budget = guard._get_budget(session_id)
                tool_max = guard.policy.get_max_calls_for_tool(tool_name)
                budget_error = budget.check(tool_name, tool_max)
                if budget_error:
                    guard._audit("tools/call", tool_name, role, "BUDGET_EXCEEDED", budget_error)
                    guard._trace(tool_name, arguments, "BUDGET_EXCEEDED", role, session_id)
                    guard._deny(f"Budget exceeded: {budget_error}")
                    return None

                # 3. Validation
                violations = guard.policy.validate_arguments(tool_name, arguments)
                if violations:
                    reason = "; ".join(violations)
                    guard._audit("tools/call", tool_name, role, "VALIDATION_FAILED", reason)
                    guard._trace(tool_name, arguments, "VALIDATION_FAILED", role, session_id, violations=violations)
                    guard._deny(f"Argument validation failed: {reason}")
                    return None

                # 4. Dry-run
                tool_policy = guard.policy.get_tool_policy(tool_name)
                if tool_policy and tool_policy.require_dry_run:
                    if guard._dry_run_tracker.needs_dry_run(session_id, tool_name, arguments):
                        start = time.monotonic()
                        result = await call_next()
                        duration = (time.monotonic() - start) * 1000
                        guard._dry_run_tracker.record_dry_run(session_id, tool_name, arguments, result)
                        guard._audit("tools/call", tool_name, role, "DRY_RUN_PREVIEW")
                        guard._trace(tool_name, arguments, "DRY_RUN_PREVIEW", role, session_id, duration_ms=duration)
                        budget.record(tool_name)
                        return result  # middleware returns raw result; wrapping happens at MCPServer level

                    if guard._dry_run_tracker.is_confirmation(session_id, tool_name, arguments):
                        guard._dry_run_tracker.consume_dry_run(session_id, tool_name)
                        start = time.monotonic()
                        result = await call_next()
                        duration = (time.monotonic() - start) * 1000
                        guard._audit("tools/call", tool_name, role, "DRY_RUN_CONFIRMED")
                        guard._trace(tool_name, arguments, "DRY_RUN_CONFIRMED", role, session_id, duration_ms=duration)
                        budget.record(tool_name)
                        return result

                # 5. Execute
                start = time.monotonic()
                result = await call_next()
                duration = (time.monotonic() - start) * 1000

                # 6. Trace + audit
                guard._audit("tools/call", tool_name, role, "ALLOW")
                guard._trace(tool_name, arguments, "ALLOW", role, session_id, duration_ms=duration)

                # 7. Budget tick
                budget.record(tool_name)

                return result

            return await call_next()

        return middleware

    def export_trace(self, session_id: str | None = None, pretty: bool = True) -> str:
        """Export the execution trace as JSON."""
        if self.trace is None:
            return "[]"
        return self.trace.to_json(session_id=session_id, pretty=pretty)


def _result_summary(result: Any, max_len: int = 200) -> str:
    """Create a short summary of a tool result for tracing."""
    try:
        if result is None:
            return "null"
        text = str(result)
        if len(text) > max_len:
            return text[:max_len] + "..."
        return text
    except Exception:
        return "<unserializable>"


def _wrap_dry_run_result(result: Any) -> Any:
    """Wrap a tool result to indicate it was a dry-run preview."""
    if hasattr(result, "content") and isinstance(result.content, list):
        from mcp.types import TextContent
        preview_note = TextContent(
            type="text",
            text="[DRY RUN PREVIEW] This was a preview. To execute for real, "
                 f"call again with _dry_run_confirm: true",
        )
        result.content.insert(0, preview_note)
        return result
    return result


def _extract_session_id(ctx: Any) -> str:
    """Best-effort session ID extraction from context."""
    session = getattr(ctx, "session", None)
    if session is not None:
        sid = getattr(session, "session_id", None)
        if sid:
            return str(sid)
    return "__default__"
