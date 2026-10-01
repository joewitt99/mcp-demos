"""OAuth Authorization Server routes for the ID-JAG (Cross-App-Access) flow.

swiss-army-mcp acts as a *Resource Authorization Server*: it advertises an
issuer + token endpoint, accepts an ID-JAG at ``/token`` via the RFC 7523
``jwt-bearer`` grant, and mints its own opaque access token. See ``idjag.py``
for the validation and token-minting logic.

Routes registered here:
  - GET  /.well-known/oauth-authorization-server   (RFC 8414 AS metadata)
  - GET  /.well-known/oauth-protected-resource     (RFC 9728 PRM, root)
  - GET  /.well-known/oauth-protected-resource/mcp (RFC 9728 PRM, path-based)
  - GET  /authorize                                (documented stub)
  - POST /token                                    (jwt-bearer / ID-JAG; client
                                                    auth required)
"""

from __future__ import annotations

import base64
import binascii
import logging
from urllib.parse import unquote, urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from idjag import (
    ID_JAG_GRANT_PROFILE,
    JWT_BEARER_GRANT,
    IdJagError,
    IdJagValidator,
    TokenStore,
)
from okta_auth import peek_jwt_claims
from scopes import ALL_SCOPES
from tenant_config import TenantStore

logger = logging.getLogger(__name__)

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _invalid_client(description: str) -> JSONResponse:
    """RFC 6749 §5.2: invalid_client is 401 and carries a challenge."""
    return JSONResponse(
        {"error": "invalid_client", "error_description": description},
        status_code=401,
        headers={**_NO_STORE, "WWW-Authenticate": 'Basic realm="token"'},
    )


def _parse_client_auth(request: Request, form) -> tuple[str, str, str] | None:
    """Extract client credentials, preferring Basic over form parameters.

    Returns (client_id, client_secret, method) or None when absent. Per RFC
    6749 §2.3.1 the Basic userid/password are form-urlencoded before base64, so
    they must be unquoted after splitting.
    """
    header = request.headers.get("authorization") or ""
    if header[:6].lower() == "basic ":
        try:
            raw = base64.b64decode(header[6:].strip(), validate=True).decode()
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        if ":" not in raw:
            return None
        cid, _, sec = raw.partition(":")
        return unquote(cid), unquote(sec), "client_secret_basic"

    cid = (form.get("client_id") or "").strip()
    sec = (form.get("client_secret") or "").strip()
    if cid and sec:
        return cid, sec, "client_secret_post"
    return None


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers=_NO_STORE,
    )


def register_oauth_routes(
    mcp,
    *,
    store: TenantStore,
    token_store: TokenStore,
    validator: IdJagValidator,
    issuer: str,
    resource_url: str,
    opaque_ttl: int,
) -> None:
    """Register the OAuth AS + protected-resource routes on the FastMCP app."""

    issuer = issuer.rstrip("/")

    @mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def as_metadata(_request: Request) -> Response:
        # NOTE: ID-JAG is non-interactive, so this AS only supports the
        # jwt-bearer grant and does not really use an authorization endpoint.
        # We still advertise one (and an empty response_types_supported) for
        # metadata completeness. RFC 8414 defines no default for an empty
        # response_types_supported, and generic MCP clients assume the
        # interactive auth-code+PKCE flow — this server targets machine clients
        # that already hold an ID-JAG.
        return JSONResponse({
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "grant_types_supported": [JWT_BEARER_GRANT],
            "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
            "response_types_supported": [],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "scopes_supported": ALL_SCOPES,
            "code_challenge_methods_supported": ["S256"],
        })

    # RFC 9728 §3.1 builds the metadata URL by inserting the *resource's path*
    # after the well-known segment, so the resource https://host/mcp is
    # described at /.well-known/oauth-protected-resource/mcp. That is the URL
    # the 401 challenge advertises in `resource_metadata`, and what MCP clients
    # fetch first (mcp/client/auth/utils.py tries path-based, then root-based).
    # Serving only the root path made every spec-compliant client 404 on
    # discovery, so register both.
    _resource_path = urlparse(resource_url).path.rstrip("/")
    _prm_paths = ["/.well-known/oauth-protected-resource"]
    if _resource_path:
        _prm_paths.append(f"/.well-known/oauth-protected-resource{_resource_path}")

    def _prm_body() -> Response:
        return JSONResponse({
            # Must match the resource identifier in the challenge, which the
            # SDK derives without a trailing slash.
            "resource": resource_url.rstrip("/"),
            "authorization_servers": [issuer],
            "scopes_supported": ALL_SCOPES,
            "bearer_methods_supported": ["header"],
        })

    for _i, _prm_path in enumerate(_prm_paths):
        # Bind the handler per iteration and give each a distinct __name__ so
        # neither registration shadows the other.
        async def protected_resource_metadata(_request: Request) -> Response:
            return _prm_body()

        protected_resource_metadata.__name__ = f"protected_resource_metadata_{_i}"
        mcp.custom_route(_prm_path, methods=["GET"])(protected_resource_metadata)

    @mcp.custom_route("/authorize", methods=["GET"])
    async def authorize(_request: Request) -> Response:
        # Present for metadata completeness only; ID-JAG is redeemed at /token.
        return _oauth_error(
            "unsupported_response_type",
            "This authorization server only supports the ID-JAG "
            "jwt-bearer grant at the token endpoint.",
        )

    @mcp.custom_route("/token", methods=["POST"])
    async def token(request: Request) -> Response:
        try:
            form = await request.form()
        except Exception:
            return _oauth_error("invalid_request", "malformed form body")

        grant_type = (form.get("grant_type") or "").strip()
        if grant_type != JWT_BEARER_GRANT:
            return _oauth_error(
                "unsupported_grant_type",
                f"only '{JWT_BEARER_GRANT}' is supported",
            )

        assertion = (form.get("assertion") or "").strip()
        if not assertion:
            return _oauth_error("invalid_request", "missing 'assertion' parameter")

        # Client authentication is mandatory. Reject a request carrying no
        # credentials before doing any signature work. Credentials are verified
        # against the tenant below, once the assertion has established which
        # tenant this is.
        creds = _parse_client_auth(request, form)
        if creds is None:
            return _invalid_client(
                "client authentication required: use HTTP Basic "
                "(client_secret_basic) or client_id/client_secret form "
                "parameters (client_secret_post)"
            )
        auth_client_id, auth_client_secret, auth_method = creds

        try:
            claims = await validator.validate(assertion)
        except IdJagError as e:
            peek = peek_jwt_claims(assertion) or {}
            logger.warning(
                "ID-JAG redemption failed (%s). Unverified claims (DIAGNOSTIC): "
                "iss=%s aud=%s sub=%s client_id=%s exp=%s",
                e.oauth_error, peek.get("iss"), peek.get("aud"),
                peek.get("sub"), peek.get("client_id"), peek.get("exp"),
            )
            return _oauth_error(e.oauth_error, e.description)

        # The assertion is authentic, so claims.tenant_domain is trustworthy and
        # names the tenant whose registered secret must match.
        tenant = store.get(claims.tenant_domain)
        if tenant is None or not tenant.verify_client(auth_client_id, auth_client_secret):
            logger.warning(
                "Client auth failed at /token (method=%s) for client_id=%r "
                "tenant=%s", auth_method, auth_client_id, claims.tenant_domain,
            )
            return _invalid_client("client authentication failed")

        # Bind the credential to the assertion: a registered client may only
        # redeem an ID-JAG that was issued to itself. Without this check any
        # authenticated client could replay another client's assertion.
        if auth_client_id != claims.client_id:
            logger.warning(
                "Client/assertion mismatch at /token: authenticated as %r but "
                "assertion client_id=%r (tenant=%s)",
                auth_client_id, claims.client_id, claims.tenant_domain,
            )
            return _oauth_error(
                "invalid_grant",
                "assertion was not issued to the authenticated client",
            )

        # Optional down-scoping: a requested 'scope' may only narrow, not widen.
        granted = list(claims.scopes)
        requested = (form.get("scope") or "").split()
        if requested:
            granted = [s for s in granted if s in requested]

        access_token = token_store.mint(
            sub=claims.sub,
            client_id=claims.client_id,
            scopes=granted,
            tenant_domain=claims.tenant_domain,
            tenant_issuer=claims.tenant_issuer,
            expires_in=opaque_ttl,
            extra_claims={"idjag_jti": claims.raw_claims.get("jti")},
        )
        logger.info(
            "Minted opaque access token for sub=%s tenant=%s scopes=%s",
            claims.sub, claims.tenant_domain, granted,
        )

        # Per the ID-JAG draft, do NOT return a refresh token.
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": opaque_ttl,
                "scope": " ".join(granted),
            },
            headers=_NO_STORE,
        )
