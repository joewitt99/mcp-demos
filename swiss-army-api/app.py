"""Swiss Army API — 25 of swiss-army-mcp's tools as Okta-protected REST.

Built to be fronted by an OpenAPI→MCP bridge: the OpenAPI document at
``/openapi.json`` is the contract. Each tool becomes one operation whose
``operationId`` is the swiss-army-mcp tool name (``text_uppercase``,
``math_add``, ...), so bridged tools keep the names clients already know.

  - Tools with arguments  →  POST /v1/<category>/<name>   (JSON body)
  - Tools without         →  GET  /v1/<category>/<name>
  - Every response        →  {"result": <value>}

Every ``/v1/*`` call requires ``Authorization: Bearer <okta-access-token>``
minted by a customer's Okta custom authorization server. Like swiss-army-mcp,
one deployment serves many customers: each self-onboards at ``/config``, their
settings persist to SSM, and each token is routed to its tenant by ``iss``.

Run locally:    API_AUTH_DISABLED=true python app.py
Docker/ECS:     PORT and HOST env vars are honored.
"""

import inspect
import logging
import os
import re
from typing import get_type_hints

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes
from pydantic import create_model

from config_routes import config_router
from okta_auth import AccessToken, MultiTenantOktaVerifier
from scopes import ALL_SCOPES, category_for, has_scope
from tenant_config import TenantStore
from tools import TOOLS

__version__ = "1.0.0"

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("swiss-army-api")

_PUBLIC_BASE_URL = (os.environ.get("API_BASE_URL") or "").rstrip("/") or None
_AUTH_DISABLED = os.environ.get("API_AUTH_DISABLED", "").lower() == "true"
if _AUTH_DISABLED:
    logger.warning("API_AUTH_DISABLED=true — Okta auth is OFF. Do not use in prod.")

_store: TenantStore | None = None if _AUTH_DISABLED else TenantStore()
_verifier: MultiTenantOktaVerifier | None = (
    None if _store is None else MultiTenantOktaVerifier(store=_store)
)

_PRM_URL = (
    f"{_PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"
    if _PUBLIC_BASE_URL else None
)

app = FastAPI(
    title="swiss-army-api",
    version=__version__,
    description=(
        "25 demo utility tools (text, math, encoding, hashing, date/time, random, "
        "color, units, data, fun) exposed as REST. A subset of swiss-army-mcp. "
        "Every /v1 operation requires an Okta access token from the caller's "
        "custom authorization server, registered at /config."
    ),
    servers=[{"url": _PUBLIC_BASE_URL}] if _PUBLIC_BASE_URL else None,
)


# ============================================================================
# Auth
# ============================================================================

_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="OktaBearer",
    bearerFormat="JWT",
    description=(
        "Okta access token minted by the custom authorization server registered "
        "for your Okta org at /config. Each operation lists the scope it requires."
    ),
)


def _challenge(status: int, error: str, description: str, scope: str | None = None):
    """RFC 6750 error with a WWW-Authenticate challenge (plus the RFC 9728
    resource_metadata pointer when our public URL is known)."""
    parts = [f'error="{error}"', f'error_description="{description}"']
    if scope:
        parts.append(f'scope="{scope}"')
    if _PRM_URL:
        parts.append(f'resource_metadata="{_PRM_URL}"')
    return HTTPException(
        status_code=status,
        detail=description,
        headers={"WWW-Authenticate": "Bearer " + ", ".join(parts)},
    )


def authorize(
    security_scopes: SecurityScopes,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> AccessToken | None:
    if _verifier is None:
        return None
    if credentials is None:
        raise _challenge(401, "invalid_request", "Missing bearer token")
    verified = _verifier.verify_token(credentials.credentials)
    if verified is None:
        raise _challenge(401, "invalid_token", "Token is invalid or expired")
    tenant, token = verified
    # Read per request so a /config change applies without a restart.
    if tenant.enforce_scopes:
        for scope in security_scopes.scopes:
            if not has_scope(token.scopes, scope):
                logger.warning(
                    "Denying tenant %s: required scope %s not in token scopes %s",
                    tenant.okta_domain, scope, token.scopes,
                )
                raise _challenge(
                    403, "insufficient_scope", f"Missing required scope '{scope}'", scope
                )
    return token


# ============================================================================
# Routes
# ============================================================================

# Unauthenticated liveness probe for the ALB.
@app.get("/healthz", include_in_schema=False)
def healthz() -> PlainTextResponse:
    return PlainTextResponse("ok")


# RFC 9728 protected-resource metadata. No `authorization_servers`: each
# tenant brings its own, and listing them would disclose who the tenants are.
@app.get("/.well-known/oauth-protected-resource", include_in_schema=False)
def protected_resource_metadata() -> JSONResponse:
    return JSONResponse({
        "resource": _PUBLIC_BASE_URL,
        "scopes_supported": ALL_SCOPES,
        "bearer_methods_supported": ["header"],
    })


def _pascal(name: str) -> str:
    return "".join(p.capitalize() for p in name.split("_"))


def _register(fn) -> None:
    """Expose one tool function as a REST operation."""
    name = fn.__name__
    prefix, segment, scope = category_for(name)
    path = f"/v1/{segment}/{name[len(prefix):].replace('_', '-')}"
    hints = get_type_hints(fn)
    params = inspect.signature(fn).parameters

    response_model = create_model(f"{_pascal(name)}Response", result=(hints["return"], ...))

    if params:
        request_model = create_model(
            f"{_pascal(name)}Request",
            **{
                p.name: (hints[p.name], ... if p.default is inspect.Parameter.empty else p.default)
                for p in params.values()
            },
        )

        if any(p.default is inspect.Parameter.empty for p in params.values()):
            def endpoint(body: request_model):  # type: ignore[valid-type]
                return {"result": _call(fn, **body.model_dump())}
        else:
            # Every argument has a default (rand_password): the body is optional.
            def endpoint(body: request_model | None = None):  # type: ignore[valid-type]
                return {"result": _call(fn, **(body.model_dump() if body else {}))}

        method = "POST"
    else:
        def endpoint():
            return {"result": _call(fn)}

        method = "GET"

    app.add_api_route(
        path,
        endpoint,
        methods=[method],
        operation_id=name,
        summary=name,
        description=f"{inspect.getdoc(fn)}\n\nRequired scope: `{scope}`",
        response_model=response_model,
        tags=[segment],
        dependencies=[Security(authorize, scopes=[scope])],
        responses={
            400: {"description": "Invalid input for this tool"},
            401: {"description": "Missing, invalid or expired Okta access token"},
            403: {"description": f"Token lacks scope `{scope}`"},
        },
    )


def _call(fn, **kwargs):
    """Run a tool; bad input (the tools raise ValueError) becomes a 400."""
    try:
        return fn(**kwargs)
    except (ValueError, re.error) as e:
        raise HTTPException(status_code=400, detail=f"{fn.__name__}: {e}")


for _fn in TOOLS:
    _register(_fn)

if _store is not None and _verifier is not None:
    app.include_router(config_router(
        store=_store, workload_verifier=_verifier, public_base_url=_PUBLIC_BASE_URL,
    ))


# ============================================================================
# Entrypoint
# ============================================================================

if __name__ == "__main__":
    if _store is not None:
        # Load every tenant under API_TENANTS_PREFIX from SSM so workload
        # tokens can be dispatched right away. New tenants register through
        # /config and land in the same caches without a restart.
        _store.hydrate()
        if not _store.all():
            logger.warning(
                "No tenants found in SSM. /v1 traffic will be rejected until "
                "at least one tenant completes setup at /config."
            )
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        # Behind the ALB: trust X-Forwarded-Proto so redirects stay https.
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
