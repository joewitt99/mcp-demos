"""Okta JWT verification for the multi-tenant swiss-army-mcp.

The single deployed instance serves many customers. Each request's bearer
token is dispatched to the right verifier by inspecting its (unverified)
``iss`` claim:

  - Workload tokens (`/mcp/*`)  — `iss` is the customer's custom auth server.
    Looked up against ``TenantStore.find_by_workload_issuer(iss)``.
  - Admin tokens (`/config/workload` POST) — `iss` is the customer's org
    auth server (their tenant URL). Looked up against
    ``TenantStore.get(domain)`` via the host portion of `iss`.

For each tenant we lazily build and cache a per-tenant ``OktaJWTVerifier``
holding the right JWKS URI, expected issuer/audience, and ``cid`` allow-list.

Configuration (environment variables):
    MCP_BASE_URL          Optional. Public URL of this MCP server.
    MCP_AUTH_DISABLED     Optional. Set to 'true' to disable auth for local dev.
"""

from __future__ import annotations

import base64
import json
import logging
from urllib.parse import urlparse

from fastmcp.server.auth.providers.jwt import (
    AccessToken,
    JWTVerifier,
    TokenVerifier,
)

from tenant_config import Tenant, TenantStore

logger = logging.getLogger(__name__)


def peek_jwt_claims(token: str) -> dict | None:
    """Decode a JWT payload WITHOUT verifying its signature.

    Diagnostic-only — never trust these claims for auth decisions.
    """
    try:
        _, payload_b64, _ = token.split(".", 2)
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None


class OktaJWTVerifier(JWTVerifier):
    """JWTVerifier with an additional Okta-specific `cid` claim allow-list."""

    def __init__(self, *, expected_client_ids: list[str] | None = None, **kwargs):
        super().__init__(**kwargs)
        self._expected_client_ids = expected_client_ids

    async def verify_token(self, token: str) -> AccessToken | None:
        access = await super().verify_token(token)
        if access is None:
            peek = peek_jwt_claims(token)
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
                    self._expected_client_ids or "<any>",
                )
            return None
        if self._expected_client_ids:
            cid = access.claims.get("cid") or access.claims.get("client_id")
            if cid not in self._expected_client_ids:
                logger.warning(
                    "Rejecting token: cid claim %r is not in allow-list %s",
                    cid, self._expected_client_ids,
                )
                return None
            access.client_id = str(cid)
        return access


def build_workload_verifier(tenant: Tenant, base_url: str | None) -> OktaJWTVerifier:
    if not tenant.custom_issuer or not tenant.audience:
        raise ValueError(f"Tenant {tenant.okta_domain} has no workload config yet")
    return OktaJWTVerifier(
        jwks_uri=f"{tenant.custom_issuer.rstrip('/')}/v1/keys",
        issuer=tenant.custom_issuer,
        audience=tenant.audience,
        base_url=base_url,
        expected_client_ids=tenant.workload_client_ids or None,
    )


def build_admin_verifier(tenant: Tenant) -> OktaJWTVerifier:
    """Verifier for an admin SPA token issued by the tenant's org auth server."""
    issuer = tenant.org_issuer
    return OktaJWTVerifier(
        jwks_uri=f"{issuer.rstrip('/')}/oauth2/v1/keys",
        issuer=issuer,
        audience=issuer,
        expected_client_ids=[tenant.admin_client_id],
    )


class MultiTenantOktaVerifier(TokenVerifier):
    """FastMCP auth provider for workload tokens across many tenants.

    Looks up the tenant by the token's (unverified) ``iss`` claim, then
    delegates to a per-tenant ``OktaJWTVerifier`` that performs the real
    signature + claims verification.
    """

    def __init__(self, *, store: TenantStore, base_url: str | None = None):
        super().__init__(base_url=base_url)
        self._store = store
        self._base_url = base_url
        self._verifiers: dict[str, OktaJWTVerifier] = {}  # by custom_issuer
        # FastMCP metadata endpoints expect these to exist.
        self.issuer = None
        self.audience = None

    def invalidate(self, custom_issuer: str | None) -> None:
        """Drop any cached verifier for ``custom_issuer`` so the next request
        rebuilds it from the (possibly updated) tenant config."""
        if custom_issuer and custom_issuer in self._verifiers:
            del self._verifiers[custom_issuer]

    async def verify_token(self, token: str) -> AccessToken | None:
        peek = peek_jwt_claims(token)
        if not peek:
            logger.warning("Workload token rejected: not a parseable JWT")
            return None
        iss = peek.get("iss")
        if not iss:
            logger.warning("Workload token rejected: no iss claim")
            return None
        tenant = self._store.find_by_workload_issuer(iss)
        if tenant is None:
            logger.warning(
                "Workload token rejected: no tenant matches iss=%s. "
                "Configured tenants: %s",
                iss, [t.custom_issuer for t in self._store.all() if t.custom_issuer],
            )
            return None
        verifier = self._verifiers.get(iss)
        if verifier is None:
            verifier = build_workload_verifier(tenant, self._base_url)
            self._verifiers[iss] = verifier
        return await verifier.verify_token(token)


def domain_from_issuer(iss: str) -> str | None:
    """Extract the Okta domain from an issuer URL.

    For org auth servers `iss` looks like ``https://<tenant>.okta.com``, so
    the domain is the URL host. For custom auth servers it's the same.
    """
    try:
        host = urlparse(iss).netloc
        return host.lower() or None
    except Exception:
        return None
