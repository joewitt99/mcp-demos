"""Per-category OAuth scope enforcement for the 100 swiss-army-mcp tools.

Each tool category maps to a single scope. The customer's Okta custom
authorization server is expected to be configured with these scopes and to
grant them to the workload application(s) calling the MCP server.

A wildcard scope grants access to every category — useful for admin testing.

Enforcement is toggled by the tenant config's `enforce_scopes` flag (set via
the /admin UI). When disabled, the middleware is a no-op so customers can
bring up the server before their auth server is fully scope-aware.
"""

from __future__ import annotations

import logging

from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.middleware.authorization import AuthorizationError

from tenant_config import TenantStore

logger = logging.getLogger(__name__)


# Tool name prefix → required scope. Order doesn't matter; prefixes are unique.
TOOL_PREFIX_TO_SCOPE: dict[str, str] = {
    "text_":   "swiss-army-mcp:text",
    "math_":   "swiss-army-mcp:math",
    "encode_": "swiss-army-mcp:encoding",
    "hash_":   "swiss-army-mcp:hashing",
    "time_":   "swiss-army-mcp:datetime",
    "rand_":   "swiss-army-mcp:random",
    "color_":  "swiss-army-mcp:color",
    "unit_":   "swiss-army-mcp:units",
    "data_":   "swiss-army-mcp:data",
    "fun_":    "swiss-army-mcp:fun",
}

WILDCARD_SCOPE = "swiss-army-mcp:*"

ALL_SCOPES: list[str] = sorted({*TOOL_PREFIX_TO_SCOPE.values(), WILDCARD_SCOPE})


def required_scope(tool_name: str) -> str | None:
    """Return the scope needed to invoke `tool_name`, or None if unmapped."""
    for prefix, scope in TOOL_PREFIX_TO_SCOPE.items():
        if tool_name.startswith(prefix):
            return scope
    return None


def _token_has_scope(token, scope: str) -> bool:
    if token is None:
        return False
    have = set(token.scopes or [])
    return WILDCARD_SCOPE in have or scope in have


class ScopeMiddleware(Middleware):
    """Enforce per-category scopes on tool calls; filter unauthorized tools out
    of tools/list.

    Multi-tenant: the request's token tells us which tenant's `enforce_scopes`
    flag to consult. If the token can't be mapped to a tenant (or the tenant
    has scope enforcement off), the middleware is a no-op.
    """

    def __init__(self, store: TenantStore):
        self._store = store

    def _enforcement_for_current_token(self) -> bool:
        token = get_access_token()
        if token is None or not getattr(token, "claims", None):
            return False
        tenant = self._store.find_by_workload_issuer(token.claims.get("iss") or "")
        return bool(tenant and tenant.enforce_scopes)

    async def on_call_tool(self, context: MiddlewareContext, call_next: CallNext):
        if not self._enforcement_for_current_token():
            return await call_next(context)

        tool_name = context.message.name
        scope = required_scope(tool_name)
        if scope is None:
            return await call_next(context)

        token = get_access_token()
        if not _token_has_scope(token, scope):
            have = list(token.scopes) if token and token.scopes else []
            logger.warning(
                "Denying tool call %s: required scope %s not in token scopes %s",
                tool_name, scope, have,
            )
            raise AuthorizationError(
                f"Missing required scope '{scope}' for tool '{tool_name}'"
            )
        return await call_next(context)

    async def on_list_tools(self, context: MiddlewareContext, call_next: CallNext):
        tools = await call_next(context)
        if not self._enforcement_for_current_token():
            return tools
        token = get_access_token()
        return [
            t for t in tools
            if (scope := required_scope(t.name)) is None or _token_has_scope(token, scope)
        ]
