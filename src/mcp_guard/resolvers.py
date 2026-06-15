"""Role resolvers for mcp-control-plane.

Pluggable strategies to extract the caller's role from request context.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol


class RoleResolver(Protocol):
    """Protocol for role resolvers — implement to add custom resolution."""

    def resolve(self, ctx: Any) -> str | None: ...


class HeaderResolver:
    """Resolve role from an HTTP header (e.g., x-mcp-role).

    Works with Streamable HTTP and SSE transports where headers are available.
    """

    def __init__(self, header_name: str = "x-mcp-role") -> None:
        self.header_name = header_name.lower()

    def resolve(self, ctx: Any) -> str | None:
        # ServerRequestContext -> request -> headers
        request = getattr(ctx, "request", None)
        if request is None:
            return None
        headers = getattr(request, "headers", None)
        if headers is None:
            return None
        if isinstance(headers, Mapping):
            # Case-insensitive lookup
            for key, value in headers.items():
                if key.lower() == self.header_name:
                    return value
        return None


class JWTResolver:
    """Resolve role from a JWT token claim.

    Extracts a claim (default: "role") from a JWT Bearer token in the
    Authorization header. Requires the `jwt` extra: pip install mcp-control-plane[jwt]
    """

    def __init__(
        self,
        claim: str = "role",
        secret: str = "",
        algorithms: list[str] | None = None,
        audience: str | None = None,
    ) -> None:
        self.claim = claim
        self.secret = secret
        self.algorithms = algorithms or ["HS256"]
        self.audience = audience

    def resolve(self, ctx: Any) -> str | None:
        try:
            import jwt
        except ImportError:
            raise ImportError("JWTResolver requires pyjwt. Install with: pip install mcp-control-plane[jwt]")

        request = getattr(ctx, "request", None)
        if request is None:
            return None
        headers = getattr(request, "headers", None)
        if headers is None:
            return None

        auth_header = None
        if isinstance(headers, Mapping):
            for key, value in headers.items():
                if key.lower() == "authorization":
                    auth_header = value
                    break

        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]
        try:
            decode_opts: dict[str, Any] = {
                "algorithms": self.algorithms,
            }
            if self.secret:
                payload = jwt.decode(token, self.secret, **decode_opts)
            else:
                payload = jwt.decode(token, options={"verify_signature": False}, **decode_opts)
            return payload.get(self.claim)
        except jwt.PyJWTError:
            return None


class APIKeyResolver:
    """Resolve role from an API key mapping.

    Maps API keys to roles. Keys are read from a header (default: x-api-key).
    """

    def __init__(
        self,
        key_role_map: dict[str, str],
        header_name: str = "x-api-key",
    ) -> None:
        self.key_role_map = key_role_map
        self.header_name = header_name.lower()

    def resolve(self, ctx: Any) -> str | None:
        request = getattr(ctx, "request", None)
        if request is None:
            return None
        headers = getattr(request, "headers", None)
        if headers is None:
            return None

        api_key = None
        if isinstance(headers, Mapping):
            for key, value in headers.items():
                if key.lower() == self.header_name:
                    api_key = value
                    break

        if api_key is None:
            return None
        return self.key_role_map.get(api_key)


class StaticResolver:
    """Always returns the same role. Useful for testing or single-tenant setups."""

    def __init__(self, role: str) -> None:
        self.role = role

    def resolve(self, ctx: Any) -> str | None:
        return self.role


class CallableResolver:
    """Wraps any function as a role resolver.

    The function receives the request context and returns a role string or None.
    """

    def __init__(self, fn: Callable[[Any], str | None]) -> None:
        self.fn = fn

    def resolve(self, ctx: Any) -> str | None:
        return self.fn(ctx)
