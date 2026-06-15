"""Session budget tracking for mcp-control-plane.

Prevents agent loops by enforcing per-session and per-tool call limits.
"""

from __future__ import annotations

from typing import Any


class SessionBudget:
    """Tracks call counts and enforces budget limits for a single session."""

    def __init__(
        self,
        max_calls_per_session: int | None = None,
        max_calls_per_tool: int | None = None,
    ) -> None:
        self.max_calls_per_session = max_calls_per_session
        self.max_calls_per_tool = max_calls_per_tool
        self._total_calls: int = 0
        self._tool_calls: dict[str, int] = {}

    def check(self, tool_name: str, tool_max_override: int | None = None) -> str | None:
        """Check if calling this tool would exceed budgets.

        Returns an error message if budget is exceeded, None if OK.
        """
        if self.max_calls_per_session is not None and self._total_calls >= self.max_calls_per_session:
            return (
                f"Session budget exceeded: {self._total_calls}/{self.max_calls_per_session} "
                f"total calls used"
            )

        effective_max = tool_max_override if tool_max_override is not None else self.max_calls_per_tool
        if effective_max is not None:
            current = self._tool_calls.get(tool_name, 0)
            if current >= effective_max:
                return (
                    f"Tool budget exceeded: '{tool_name}' called {current}/{effective_max} times"
                )

        return None

    def record(self, tool_name: str) -> None:
        """Record a successful tool call."""
        self._total_calls += 1
        self._tool_calls[tool_name] = self._tool_calls.get(tool_name, 0) + 1

    def reset(self) -> None:
        """Reset all counters."""
        self._total_calls = 0
        self._tool_calls.clear()

    @property
    def total_calls(self) -> int:
        return self._total_calls

    def tool_call_count(self, tool_name: str) -> int:
        return self._tool_calls.get(tool_name, 0)

    def snapshot(self) -> dict[str, Any]:
        """Current state as a dict for debugging."""
        return {
            "total_calls": self._total_calls,
            "max_calls_per_session": self.max_calls_per_session,
            "max_calls_per_tool": self.max_calls_per_tool,
            "tool_calls": dict(self._tool_calls),
        }
