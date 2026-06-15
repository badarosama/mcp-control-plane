"""Dry-run enforcement for mcp-control-plane.

Requires preview execution before dangerous tools can run for real.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from mcp_guard.audit import _now_iso

DRY_RUN_CONFIRM_KEY = "_dry_run_confirm"


def _canonical_args(arguments: dict[str, Any]) -> str:
    """Canonical JSON string for argument comparison (ignoring confirm key)."""
    filtered = {k: v for k, v in sorted(arguments.items()) if k != DRY_RUN_CONFIRM_KEY}
    return json.dumps(filtered, sort_keys=True, default=str)


@dataclass
class DryRunState:
    """Tracks a pending dry-run for a tool."""

    tool_name: str
    arguments_key: str
    preview: Any = None
    timestamp: str = ""
    confirmed: bool = False


class DryRunTracker:
    """Tracks dry-run state per session per tool."""

    def __init__(self) -> None:
        self._pending: dict[str, dict[str, DryRunState]] = {}

    def needs_dry_run(self, session_id: str, tool_name: str, arguments: dict[str, Any]) -> bool:
        """True if this tool has no matching pending dry-run (needs preview first)."""
        if DRY_RUN_CONFIRM_KEY in arguments:
            return False
        session = self._pending.get(session_id, {})
        state = session.get(tool_name)
        if state is None:
            return True
        return state.arguments_key != _canonical_args(arguments)

    def is_confirmation(self, session_id: str, tool_name: str, arguments: dict[str, Any]) -> bool:
        """True if this call is confirming a pending dry-run."""
        if DRY_RUN_CONFIRM_KEY not in arguments:
            return False
        session = self._pending.get(session_id, {})
        state = session.get(tool_name)
        if state is None:
            return False
        clean_args = {k: v for k, v in arguments.items() if k != DRY_RUN_CONFIRM_KEY}
        return state.arguments_key == _canonical_args(clean_args)

    def record_dry_run(
        self, session_id: str, tool_name: str, arguments: dict[str, Any], preview: Any
    ) -> None:
        """Record that a dry-run preview was performed."""
        if session_id not in self._pending:
            self._pending[session_id] = {}
        self._pending[session_id][tool_name] = DryRunState(
            tool_name=tool_name,
            arguments_key=_canonical_args(arguments),
            preview=preview,
            timestamp=_now_iso(),
        )

    def consume_dry_run(self, session_id: str, tool_name: str) -> DryRunState | None:
        """Consume a pending dry-run (mark as confirmed and remove)."""
        session = self._pending.get(session_id, {})
        state = session.pop(tool_name, None)
        if state:
            state.confirmed = True
        return state

    def clear_session(self, session_id: str) -> None:
        """Clear all pending dry-runs for a session."""
        self._pending.pop(session_id, None)
