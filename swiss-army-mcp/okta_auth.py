"""Okta access-token verification for the FastMCP server.

Validates the incoming `Authorization: Bearer <jwt>` header against an Okta
custom authorization server using JWKS-based signature verification, plus
issuer/audience/expiration checks. When OKTA_CLIENT_ID is set, the token's
`cid` claim must match as well — restricting access to a specific Okta app.

Configuration (all via environment variables):

    OKTA_ISSUER         REQUIRED.  Full issuer URL of the custom auth server,
                                   e.g. https://dev-123456.okta.com/oauth2/default
    OKTA_AUDIENCE       REQUIRED.  Expected `aud` claim, e.g. api://default
    OKTA_CLIENT_ID      Optional.  If set, the token's `cid` claim must match.
    OKTA_JWKS_URI       Optional.  Defaults to {OKTA_ISSUER}/v1/keys
    OKTA_REQUIRED_SCOPES  Optional. Comma-separated scopes the token must have.
    OKTA_DOMAIN         Optional.  Informational, e.g. dev-123456.okta.com
    MCP_BASE_URL        Optional.  Public URL of this MCP server (RFC 8707).
    MCP_AUTH_DISABLED   Optional.  Set to 'true' to disable auth for local dev.
"""

from __future__ import annotations

import base64
import json
import logging
import os

from fastmcp.server.auth.providers.jwt import AccessToken, JWTVerifier

logger = logging.getLogger(__name__)


def _peek_jwt_claims(token: str) -> dict | None:
    """Decode a JWT's payload WITHOUT verifying its signature.

    Diagnostic-only — used to surface why a token was rejected (e.g. wrong
    audience, expired, wrong issuer). Never trust these claims for auth.
    """
    try:
        _, payload_b64, _ = token.split(".", 2)
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None


class OktaJWTVerifier(JWTVerifier):
    """JWTVerifier with an additional Okta-specific `cid` claim check.

    Okta access tokens identify the calling app via the `cid` claim (not the
    standard OAuth `client_id`). The base verifier already validates the
    signature, issuer, audience, and expiration; this subclass adds an
    optional equality check on `cid` so the server can be locked to one app.
    """

    def __init__(self, *, expected_client_id: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self._expected_client_id = expected_client_id

    async def verify_token(self, token: str) -> AccessToken | None:
        access = await super().verify_token(token)
        if access is None:
            peek = _peek_jwt_claims(token)
            if peek is None:
                logger.warning("Token rejected and is not a parseable JWT.")
            else:
                logger.warning(
                    "Token rejected. Unverified claims (DIAGNOSTIC ONLY): "
                    "iss=%s aud=%s cid=%s azp=%s exp=%s scp=%s sub=%s. "
                    "Server expects iss=%s aud=%s cid=%s.",
                    peek.get("iss"), peek.get("aud"),
                    peek.get("cid"), peek.get("azp"),
                    peek.get("exp"), peek.get("scp"), peek.get("sub"),
                    self.issuer, self.audience,
                    self._expected_client_id or "<any>",
                )
            return None
        if self._expected_client_id:
            cid = access.claims.get("cid") or access.claims.get("client_id")
            if cid != self._expected_client_id:
                logger.warning(
                    "Rejecting token: cid claim %r does not match OKTA_CLIENT_ID",
                    cid,
                )
                return None
            # Surface cid as the canonical client_id on the AccessToken.
            access.client_id = str(cid)
        logger.info(
            "Token verified. Claims: %s",
            json.dumps(access.claims, default=str, sort_keys=True),
        )
        return access


def build_okta_auth() -> OktaJWTVerifier | None:
    """Construct an Okta JWT verifier from environment variables.

    Returns None if MCP_AUTH_DISABLED=true (useful for local development).
    Raises RuntimeError if required env vars are missing.
    """
    if os.environ.get("MCP_AUTH_DISABLED", "").lower() == "true":
        logger.warning("MCP_AUTH_DISABLED=true — Okta auth is OFF. Do not use in prod.")
        return None

    issuer = os.environ.get("OKTA_ISSUER")
    audience = os.environ.get("OKTA_AUDIENCE")
    missing = [k for k, v in {"OKTA_ISSUER": issuer, "OKTA_AUDIENCE": audience}.items() if not v]
    if missing:
        raise RuntimeError(
            f"Missing required Okta env vars: {', '.join(missing)}. "
            "Set MCP_AUTH_DISABLED=true to disable auth for local development."
        )

    jwks_uri = os.environ.get("OKTA_JWKS_URI") or f"{issuer.rstrip('/')}/v1/keys"
    client_id = os.environ.get("OKTA_CLIENT_ID") or None
    base_url = os.environ.get("MCP_BASE_URL") or None

    scopes_raw = os.environ.get("OKTA_REQUIRED_SCOPES", "").strip()
    required_scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()] or None

    logger.info(
        "Okta auth enabled (issuer=%s, audience=%s, client_id=%s, scopes=%s)",
        issuer, audience, client_id or "<any>", required_scopes or "<none>",
    )

    return OktaJWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience,
        required_scopes=required_scopes,
        base_url=base_url,
        expected_client_id=client_id,
    )
