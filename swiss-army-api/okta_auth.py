"""Okta access-token verification for the multi-tenant swiss-army-api.

The single deployed instance serves many customers. Each request's bearer
token is dispatched to the right verifier by inspecting its (unverified)
``iss`` claim — the same scheme as ``swiss-army-mcp/okta_auth.py``:

  - Workload tokens (``/v1/*``)  — ``iss`` is the customer's custom auth
    server. Looked up against ``TenantStore.find_by_workload_issuer(iss)``.
  - Admin tokens (``/config/*``) — ``iss`` is the customer's org auth server
    (their tenant URL). Looked up against ``TenantStore.get(domain)`` via the
    host portion of ``iss``.

For each tenant we lazily build and cache an ``OktaJWTVerifier`` holding the
right JWKS URI, expected issuer/audience, and ``cid`` allow-list. The JWKS-URI
convention, ``cid`` allow-list and diagnostic logging are carried over from
swiss-army-mcp; the signature check uses PyJWT rather than FastMCP.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import jwt

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


def okta_jwks_uri(issuer: str) -> str:
    """Derive the Okta JWKS URI for an issuer.

    Custom authorization servers have an ``/oauth2/<ausId>`` path and serve keys
    at ``{issuer}/v1/keys``. A bare org auth server (``https://<domain>``) serves
    keys at ``{issuer}/oauth2/v1/keys``.
    """
    trimmed = issuer.rstrip("/")
    if "/oauth2/" in trimmed:
        return f"{trimmed}/v1/keys"
    return f"{trimmed}/oauth2/v1/keys"


@dataclass
class AccessToken:
    """The verified parts of an Okta access token the API cares about."""

    claims: dict
    scopes: list[str] = field(default_factory=list)
    client_id: str | None = None
    subject: str | None = None


class OktaJWTVerifier:
    """Verify Okta access tokens: signature (JWKS), ``iss``, ``aud``, ``exp``,
    and an optional ``cid`` allow-list."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        expected_client_ids: list[str] | None = None,
        jwks_uri: str | None = None,
    ):
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self._expected_client_ids = expected_client_ids or None
        self.jwks_uri = jwks_uri or okta_jwks_uri(self.issuer)
        # PyJWKClient caches the key set and refetches on an unknown `kid`,
        # so Okta key rotation is picked up without a restart.
        self._jwks = jwt.PyJWKClient(self.jwks_uri, cache_keys=True)

    def verify_token(self, token: str) -> AccessToken | None:
        """Return the verified token, or None if it must be rejected.

        Synchronous (PyJWKClient does blocking HTTP); FastAPI runs sync
        dependencies in its threadpool.
        """
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iss", "aud"]},
            )
        except Exception as e:
            peek = peek_jwt_claims(token)
            if peek is None:
                logger.warning("Token rejected (%s) and is not a parseable JWT.", e)
            else:
                logger.warning(
                    "Token rejected (%s). Unverified claims (DIAGNOSTIC ONLY): "
                    "iss=%s aud=%s cid=%s exp=%s scp=%s sub=%s. "
                    "Server expects iss=%s aud=%s cid=%s.",
                    e,
                    peek.get("iss"), peek.get("aud"), peek.get("cid"),
                    peek.get("exp"), peek.get("scp"), peek.get("sub"),
                    self.issuer, self.audience,
                    self._expected_client_ids or "<any>",
                )
            return None

        cid = claims.get("cid") or claims.get("client_id")
        if self._expected_client_ids and cid not in self._expected_client_ids:
            logger.warning(
                "Rejecting token: cid claim %r is not in allow-list %s",
                cid, self._expected_client_ids,
            )
            return None

        # Okta puts scopes in `scp` as a list; RFC 9068 tokens use a
        # space-delimited `scope` string. Accept either.
        scp = claims.get("scp")
        if isinstance(scp, str):
            scopes = scp.split()
        elif isinstance(scp, list):
            scopes = [str(s) for s in scp]
        else:
            scopes = (claims.get("scope") or "").split()

        return AccessToken(
            claims=claims,
            scopes=scopes,
            client_id=str(cid) if cid else None,
            subject=claims.get("sub"),
        )


def build_workload_verifier(tenant: Tenant) -> OktaJWTVerifier:
    if not tenant.custom_issuer or not tenant.audience:
        raise ValueError(f"Tenant {tenant.okta_domain} has no workload config yet")
    return OktaJWTVerifier(
        issuer=tenant.custom_issuer,
        audience=tenant.audience,
        expected_client_ids=tenant.workload_client_ids or None,
    )


def build_admin_verifier(tenant: Tenant) -> OktaJWTVerifier:
    """Verifier for an admin SPA token issued by the tenant's org auth server."""
    issuer = tenant.org_issuer
    return OktaJWTVerifier(
        issuer=issuer,
        audience=issuer,
        expected_client_ids=[tenant.admin_client_id],
    )


class MultiTenantOktaVerifier:
    """Verify workload tokens across many tenants.

    Looks up the tenant by the token's (unverified) ``iss`` claim, then
    delegates to a per-tenant ``OktaJWTVerifier`` that performs the real
    signature + claims verification.
    """

    def __init__(self, *, store: TenantStore):
        self._store = store
        self._verifiers: dict[str, OktaJWTVerifier] = {}  # by custom_issuer

    def invalidate(self, custom_issuer: str | None) -> None:
        """Drop any cached verifier for ``custom_issuer`` so the next request
        rebuilds it from the (possibly updated) tenant config."""
        if custom_issuer:
            self._verifiers.pop(custom_issuer, None)

    def verify_token(self, token: str) -> tuple[Tenant, AccessToken] | None:
        """Return the tenant and verified token, or None to reject."""
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
            verifier = build_workload_verifier(tenant)
            self._verifiers[iss] = verifier
        access = verifier.verify_token(token)
        return None if access is None else (tenant, access)


def domain_from_issuer(iss: str) -> str | None:
    """Extract the Okta domain (URL host) from an issuer URL."""
    try:
        host = urlparse(iss).netloc
        return host.lower() or None
    except Exception:
        return None
