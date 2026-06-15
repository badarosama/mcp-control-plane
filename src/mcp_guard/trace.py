"""Agent execution trace for mcp-control-plane.

Full flight recorder: what the agent called, with what arguments,
what came back, how long it took. For post-incident replay and debugging.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from mcp_guard.audit import _now_iso


@dataclass
class TraceEntry:
    """A single tool execution record."""

    timestamp: str
    tool: str
    arguments: dict[str, Any]
    decision: str  # ALLOW, DENY, BUDGET_EXCEEDED, VALIDATION_FAILED, DRY_RUN_PREVIEW, DRY_RUN_CONFIRMED
    role: str | None = None
    session_id: str | None = None
    result_summary: str | None = None
    duration_ms: float | None = None
    violations: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class AgentTrace:
    """Full execution trace for agent sessions.

    Goes beyond audit (allow/deny) to record arguments, results, and timing.
    The flight recorder you wish you had after an incident.
    """

    def __init__(self, max_entries: int = 10000) -> None:
        self._entries: list[TraceEntry] = []
        self._max_entries = max_entries

    def record(self, entry: TraceEntry) -> None:
        """Record a trace entry."""
        if len(self._entries) >= self._max_entries:
            self._entries.pop(0)
        self._entries.append(entry)

    def get_entries(
        self,
        session_id: str | None = None,
        tool: str | None = None,
        decision: str | None = None,
    ) -> list[TraceEntry]:
        """Filter entries by session, tool, and/or decision."""
        entries = self._entries
        if session_id is not None:
            entries = [e for e in entries if e.session_id == session_id]
        if tool is not None:
            entries = [e for e in entries if e.tool == tool]
        if decision is not None:
            entries = [e for e in entries if e.decision == decision]
        return list(entries)

    def to_json(self, session_id: str | None = None, pretty: bool = True) -> str:
        """Export trace as JSON."""
        entries = self.get_entries(session_id=session_id)
        indent = 2 if pretty else None
        return json.dumps([e.to_dict() for e in entries], indent=indent, default=str)

    def to_dicts(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Export trace as list of dicts."""
        return [e.to_dict() for e in self.get_entries(session_id=session_id)]

    def clear(self, session_id: str | None = None) -> None:
        """Clear entries. If session_id given, only clear that session."""
        if session_id is None:
            self._entries.clear()
        else:
            self._entries = [e for e in self._entries if e.session_id != session_id]

    @property
    def size(self) -> int:
        return len(self._entries)
