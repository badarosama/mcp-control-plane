"""Policy engine for mcp-control-plane.

Loads role-based policies from YAML/dict and evaluates permissions,
tool budgets, argument rules, and dry-run requirements.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_UNSET = object()


@dataclass
class ArgumentRule:
    """Validation rule for a single tool argument."""

    max: float | None = None
    min: float | None = None
    equals: Any = field(default=_UNSET)
    min_length: int | None = None
    max_length: int | None = None
    pattern: str | None = None
    one_of: list[Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArgumentRule:
        rule = cls()
        if "max" in data:
            rule.max = float(data["max"])
        if "min" in data:
            rule.min = float(data["min"])
        if "equals" in data:
            rule.equals = data["equals"]
        if "min_length" in data:
            rule.min_length = int(data["min_length"])
        if "max_length" in data:
            rule.max_length = int(data["max_length"])
        if "pattern" in data:
            rule.pattern = str(data["pattern"])
        if "one_of" in data:
            rule.one_of = list(data["one_of"])
        return rule


@dataclass
class ToolPolicy:
    """Per-tool safety configuration."""

    rules: dict[str, ArgumentRule] = field(default_factory=dict)
    max_calls: int | None = None
    require_dry_run: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolPolicy:
        rules: dict[str, ArgumentRule] = {}
        for arg_name, rule_data in data.get("rules", {}).items():
            rules[arg_name] = ArgumentRule.from_dict(rule_data)
        return cls(
            rules=rules,
            max_calls=data.get("max_calls"),
            require_dry_run=data.get("require_dry_run", False),
        )


@dataclass
class BudgetConfig:
    """Global budget limits for tool calls."""

    max_calls_per_session: int | None = None
    max_calls_per_tool: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BudgetConfig:
        return cls(
            max_calls_per_session=data.get("max_calls_per_session"),
            max_calls_per_tool=data.get("max_calls_per_tool"),
        )


@dataclass
class RolePolicy:
    """Permissions for a single role."""

    can_see: list[str] = field(default_factory=list)
    can_call: list[str] = field(default_factory=list)

    def _matches(self, tool_name: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(tool_name, p) for p in patterns)

    def allows_see(self, tool_name: str) -> bool:
        return self._matches(tool_name, self.can_see)

    def allows_call(self, tool_name: str) -> bool:
        return self._matches(tool_name, self.can_call)


class Policy:
    """Policy engine for agent runtime safety.

    Supports role-based access, tool budgets, argument validation,
    and dry-run requirements. All features are opt-in.
    """

    def __init__(
        self,
        roles: dict[str, RolePolicy] | None = None,
        default_role: str | None = None,
        deny_by_default: bool = True,
        budgets: BudgetConfig | None = None,
        tools: dict[str, ToolPolicy] | None = None,
    ) -> None:
        self.roles: dict[str, RolePolicy] = roles or {}
        self.default_role = default_role
        self.deny_by_default = deny_by_default
        self.budgets = budgets or BudgetConfig()
        self.tools: dict[str, ToolPolicy] = tools or {}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        """Create a Policy from a dictionary."""
        roles: dict[str, RolePolicy] = {}
        for role_name, role_data in data.get("roles", {}).items():
            roles[role_name] = RolePolicy(
                can_see=role_data.get("can_see", []),
                can_call=role_data.get("can_call", []),
            )

        budgets = BudgetConfig.from_dict(data["budgets"]) if "budgets" in data else BudgetConfig()

        tools: dict[str, ToolPolicy] = {}
        for tool_name, tool_data in data.get("tools", {}).items():
            tools[tool_name] = ToolPolicy.from_dict(tool_data)

        return cls(
            roles=roles,
            default_role=data.get("default_role"),
            deny_by_default=data.get("deny_by_default", True),
            budgets=budgets,
            tools=tools,
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        """Load a policy from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    def get_role(self, role_name: str | None) -> RolePolicy | None:
        """Resolve a role name to its policy."""
        if role_name and role_name in self.roles:
            return self.roles[role_name]
        if self.default_role and self.default_role in self.roles:
            return self.roles[self.default_role]
        return None

    def can_see(self, role_name: str | None, tool_name: str) -> bool:
        """Check if a role is allowed to see a tool in tools/list."""
        role = self.get_role(role_name)
        if role is None:
            return not self.deny_by_default
        return role.allows_see(tool_name)

    def can_call(self, role_name: str | None, tool_name: str) -> bool:
        """Check if a role is allowed to call a tool via tools/call."""
        role = self.get_role(role_name)
        if role is None:
            return not self.deny_by_default
        return role.allows_call(tool_name)

    def get_tool_policy(self, tool_name: str) -> ToolPolicy | None:
        """Get per-tool safety configuration."""
        return self.tools.get(tool_name)

    def get_max_calls_for_tool(self, tool_name: str) -> int | None:
        """Get effective max calls for a tool (per-tool override > global default)."""
        tool_policy = self.tools.get(tool_name)
        if tool_policy and tool_policy.max_calls is not None:
            return tool_policy.max_calls
        return self.budgets.max_calls_per_tool

    def validate_arguments(self, tool_name: str, arguments: dict[str, Any]) -> list[str]:
        """Validate tool arguments against policy rules. Returns list of violations."""
        tool_policy = self.tools.get(tool_name)
        if not tool_policy or not tool_policy.rules:
            return []

        violations: list[str] = []
        for arg_name, rule in tool_policy.rules.items():
            if arg_name not in arguments:
                continue
            value = arguments[arg_name]

            if rule.max is not None and isinstance(value, (int, float)) and value > rule.max:
                violations.append(f"{arg_name}: value {value} exceeds max {rule.max}")

            if rule.min is not None and isinstance(value, (int, float)) and value < rule.min:
                violations.append(f"{arg_name}: value {value} below min {rule.min}")

            if rule.equals is not _UNSET and value != rule.equals:
                violations.append(f"{arg_name}: value must equal {rule.equals}, got {value}")

            if rule.min_length is not None and isinstance(value, str) and len(value) < rule.min_length:
                violations.append(f"{arg_name}: length {len(value)} below min_length {rule.min_length}")

            if rule.max_length is not None and isinstance(value, str) and len(value) > rule.max_length:
                violations.append(f"{arg_name}: length {len(value)} exceeds max_length {rule.max_length}")

            if rule.pattern is not None and isinstance(value, str) and not re.search(rule.pattern, value):
                violations.append(f"{arg_name}: value does not match pattern '{rule.pattern}'")

            if rule.one_of is not None and value not in rule.one_of:
                violations.append(f"{arg_name}: value {value} not in allowed values {rule.one_of}")

        return violations
