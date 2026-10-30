"""Per-category OAuth scopes for the 25 swiss-army-api operations.

Same shape as ``swiss-army-mcp/scopes.py``: each tool category maps to one
scope, and a wildcard grants every category. The scope names use the
``swiss-army-api:`` prefix so a custom auth server can grant API access
independently of MCP access.

Every operation advertises its required scope in the OpenAPI document
regardless of enforcement. Enforcement itself is toggled by
``API_ENFORCE_SCOPES`` so the API can be brought up before the auth server
is scope-aware.
"""

from __future__ import annotations

# Tool name prefix → (URL path segment, required scope).
TOOL_PREFIX_TO_CATEGORY: dict[str, tuple[str, str]] = {
    "text_":   ("text",     "swiss-army-api:text"),
    "math_":   ("math",     "swiss-army-api:math"),
    "encode_": ("encoding", "swiss-army-api:encoding"),
    "hash_":   ("hashing",  "swiss-army-api:hashing"),
    "time_":   ("datetime", "swiss-army-api:datetime"),
    "rand_":   ("random",   "swiss-army-api:random"),
    "color_":  ("color",    "swiss-army-api:color"),
    "unit_":   ("units",    "swiss-army-api:units"),
    "data_":   ("data",     "swiss-army-api:data"),
    "fun_":    ("fun",      "swiss-army-api:fun"),
}

WILDCARD_SCOPE = "swiss-army-api:*"

ALL_SCOPES: list[str] = sorted(
    {*(scope for _, scope in TOOL_PREFIX_TO_CATEGORY.values()), WILDCARD_SCOPE}
)


def category_for(tool_name: str) -> tuple[str, str, str]:
    """Return ``(prefix, path_segment, scope)`` for ``tool_name``."""
    for prefix, (segment, scope) in TOOL_PREFIX_TO_CATEGORY.items():
        if tool_name.startswith(prefix):
            return prefix, segment, scope
    raise ValueError(f"tool {tool_name!r} has no known category prefix")


def has_scope(token_scopes: list[str], scope: str) -> bool:
    have = set(token_scopes)
    return WILDCARD_SCOPE in have or scope in have
