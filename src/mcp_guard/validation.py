"""Argument validation for mcp-control-plane.

Validates tool call arguments against policy-defined rules before execution.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_guard.policy import ArgumentRule, _UNSET


class ArgumentValidator:
    """Stateless validator for tool call arguments."""

    @staticmethod
    def validate(arguments: dict[str, Any], rules: dict[str, ArgumentRule]) -> list[str]:
        """Validate arguments against rules. Returns list of violation strings.

        Empty list means all checks passed. Arguments not mentioned in rules
        are allowed (open-world model).
        """
        violations: list[str] = []
        for arg_name, rule in rules.items():
            if arg_name not in arguments:
                continue
            violation = ArgumentValidator._check_rule(arg_name, arguments[arg_name], rule)
            if violation:
                violations.append(violation)
        return violations

    @staticmethod
    def _check_rule(arg_name: str, value: Any, rule: ArgumentRule) -> str | None:
        """Check a single argument against a single rule. Returns violation or None."""
        if rule.max is not None and isinstance(value, (int, float)) and value > rule.max:
            return f"{arg_name}: value {value} exceeds maximum {rule.max}"

        if rule.min is not None and isinstance(value, (int, float)) and value < rule.min:
            return f"{arg_name}: value {value} below minimum {rule.min}"

        if rule.equals is not _UNSET and value != rule.equals:
            return f"{arg_name}: must equal {rule.equals!r}, got {value!r}"

        if rule.min_length is not None and isinstance(value, str) and len(value) < rule.min_length:
            return f"{arg_name}: length {len(value)} below minimum {rule.min_length}"

        if rule.max_length is not None and isinstance(value, str) and len(value) > rule.max_length:
            return f"{arg_name}: length {len(value)} exceeds maximum {rule.max_length}"

        if rule.pattern is not None and isinstance(value, str) and not re.search(rule.pattern, value):
            return f"{arg_name}: does not match pattern '{rule.pattern}'"

        if rule.one_of is not None and value not in rule.one_of:
            return f"{arg_name}: {value!r} not in allowed values {rule.one_of}"

        return None
