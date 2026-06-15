"""Audit logging for mcp-control-plane.

Structured logging of every authorization decision — allow or deny.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

logger = logging.getLogger("mcp_guard.audit")


@dataclass
class AuditEvent:
    """A single authorization decision."""

    timestamp: str
    action: str  # "tools/list" or "tools/call"
    tool: str
    role: str | None
    decision: str  # "ALLOW" or "DENY"
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class AuditLogger(Protocol):
    """Protocol for audit loggers — implement this to send events anywhere."""

    def log(self, event: AuditEvent) -> None: ...


class ConsoleAuditLogger:
    """Logs audit events as structured JSON to stderr."""

    def __init__(self, stream: Any = None, pretty: bool = False) -> None:
        self.stream = stream or sys.stderr
        self.pretty = pretty

    def log(self, event: AuditEvent) -> None:
        indent = 2 if self.pretty else None
        line = json.dumps(event.to_dict(), indent=indent, default=str)
        self.stream.write(line + "\n")
        self.stream.flush()


class PythonLoggingAuditLogger:
    """Routes audit events through Python's standard logging."""

    def __init__(self, logger_name: str = "mcp_guard.audit") -> None:
        self.logger = logging.getLogger(logger_name)

    def log(self, event: AuditEvent) -> None:
        level = logging.WARNING if event.decision == "DENY" else logging.INFO
        self.logger.log(level, "%s | %s | %s | %s | %s",
                        event.decision, event.role or "unknown",
                        event.action, event.tool, event.timestamp)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
