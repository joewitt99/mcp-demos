"""ID-JAG (Identity Assertion JWT Authorization Grant) support.

This module lets swiss-army-mcp act as a *Resource Authorization Server* in the
Okta Cross-App-Access / ID-JAG flow
(``draft-ietf-oauth-identity-assertion-authz-grant``):

  1. A requesting app obtains an ID-JAG from the customer's Okta org (the IdP)
     via RFC 8693 token exchange, with ``aud`` set to *this server's* issuer.
  2. The requesting app POSTs the ID-JAG to our ``/token`` endpoint using the
     RFC 7523 ``urn:ietf:params:oauth:grant-type:jwt-bearer`` grant.
  3. We validate the ID-JAG and mint our own **opaque** access token, which is
     then presented as a bearer token on ``/mcp/*``.

We are only ever the Resource AS (step 2/3). We never mint ID-JAGs — Okta does.
"Assume the user from the ID-JAG" means the ID-JAG ``sub`` claim *is* the
identity; there is no interactive login.

Design notes / demo simplifications:
  - The opaque-token store is process-local (in-memory), matching the single
    task (``DESIRED_COUNT=1``) deployment assumption used by ``TenantStore``.
    Tokens are lost on restart.
  - Client authentication at the token endpoint (private_key_jwt per Okta) is
    not required; we validate the ID-JAG ``client_id`` claim against the
    tenant's ``workload_client_ids`` allow-list when one is configured.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field

from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.utilities.auth import decode_jwt_header

from okta_auth import build_issuer_verifier, peek_jwt_claims
from tenant_config import TenantStore

logger = logging.getLogger(__name__)

# --- Spec constants (draft-ietf-oauth-identity-assertion-authz-grant) --------
ID_JAG_TYP = "oauth-id-jag+jwt"
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG_GRANT_PROFILE = "urn:ietf:params:oauth:grant-profile:id-jag"


class IdJagError(Exception):
    """A validation failure to surface as an OAuth token-endpoint error.

    ``oauth_error`` is the RFC 6749 error code (e.g. ``invalid_grant``,
    ``invalid_request``) the ``/token`` handler returns to the client.
    """

    def __init__(self, oauth_error: str, description: str):
        super().__init__(description)
        self.oauth_error = oauth_error
        self.description = description


@dataclass
class IdJagClaims:
    """The validated, trusted claims extracted from an ID-JAG."""

    sub: str
    client_id: str
    scopes: list[str]
    tenant_domain: str
    tenant_issuer: str
    exp: int | None
    raw_claims: dict = field(default_factory=dict)


# ----------------------------------------------------------------------------
# Opaque access-token store
# ----------------------------------------------------------------------------

@dataclass
class _TokenRecord:
    sub: str
    client_id: str
    scopes: list[str]
    tenant_domain: str
    tenant_issuer: str
    expires_at: int  # absolute Unix seconds
    extra_claims: dict = field(default_factory=dict)


class TokenStore:
    """In-memory store of minted opaque access tokens.

    Process-local by design (single-task deployment). Not durable across
    restarts — acceptable for a demo. Swap this class for an SSM/DynamoDB-backed
    implementation to gain durability or multi-task support.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, _TokenRecord] = {}

    def mint(
        self,
        *,
        sub: str,
        client_id: str,
        scopes: list[str],
        tenant_domain: str,
        tenant_issuer: str,
        expires_in: int,
        extra_claims: dict | None = None,
    ) -> str:
        token = secrets.token_urlsafe(32)
        record = _TokenRecord(
            sub=sub,
            client_id=client_id,
            scopes=list(scopes),
            tenant_domain=tenant_domain,
            tenant_issuer=tenant_issuer,
            expires_at=int(time.time()) + int(expires_in),
            extra_claims=dict(extra_claims or {}),
        )
        with self._lock:
            self._records[token] = record
        return token

    def lookup(self, token: str) -> _TokenRecord | None:
        now = int(time.time())
        with self._lock:
            record = self._records.get(token)
            if record is None:
                return None
            if record.expires_at <= now:
                # Lazily evict expired tokens.
                del self._records[token]
                return None
            return record


# ----------------------------------------------------------------------------
# ID-JAG validation
# ----------------------------------------------------------------------------

class IdJagValidator:
    """Validate an inbound ID-JAG assertion per the draft spec.

    Steps (draft-ietf-oauth-identity-assertion-authz-grant):
      1. Header ``typ`` MUST be ``oauth-id-jag+jwt``.
      2. Signature verifies against the IdP's JWKS (derived from ``iss``).
      3. ``iss`` maps to a known/trusted tenant.
      4. ``aud`` equals our issuer identifier (enforced by the verifier).
      5. ``exp`` not passed (enforced by the verifier).
      6. ``client_id`` is permitted for the tenant.
      7. ``jti`` has not been seen before (replay protection).
    """

    def __init__(
        self,
        *,
        store: TenantStore,
        expected_audience: str,
        base_url: str | None = None,
    ) -> None:
        self._store = store
        self._expected_audience = expected_audience
        self._base_url = base_url
        self._verifiers: dict[str, object] = {}  # by issuer
        self._seen_jti: dict[str, int] = {}  # jti -> exp (for eviction)
        self._lock = threading.Lock()

    def invalidate(self, issuer: str | None) -> None:
        """Drop any cached verifier for ``issuer`` (e.g. after a config change)."""
        if issuer:
            with self._lock:
                self._verifiers.pop(issuer, None)

    def _check_replay(self, jti: str | None, exp: int | None) -> None:
        if not jti:
            # jti is REQUIRED by the spec; a missing one can't be replay-checked.
            raise IdJagError("invalid_grant", "ID-JAG is missing the required 'jti' claim")
        now = int(time.time())
        with self._lock:
            # Evict expired jti entries opportunistically.
            for old in [j for j, e in self._seen_jti.items() if e <= now]:
                del self._seen_jti[old]
            if jti in self._seen_jti:
                raise IdJagError("invalid_grant", "ID-JAG has already been redeemed (jti replay)")
            self._seen_jti[jti] = int(exp) if exp else now + 300

    async def validate(self, assertion: str) -> IdJagClaims:
        # 1. Header typ.
        try:
            header = decode_jwt_header(assertion)
        except Exception:
            raise IdJagError("invalid_grant", "assertion is not a parseable JWT")
        if header.get("typ") != ID_JAG_TYP:
            raise IdJagError(
                "invalid_grant",
                f"assertion 'typ' header must be '{ID_JAG_TYP}'",
            )

        # 3. Resolve the tenant from the (unverified) iss claim.
        peek = peek_jwt_claims(assertion) or {}
        iss = peek.get("iss")
        if not iss:
            raise IdJagError("invalid_grant", "assertion has no 'iss' claim")
        tenant = self._store.resolve_tenant_by_issuer(iss)
        if tenant is None:
            logger.warning("ID-JAG rejected: no tenant matches iss=%s", iss)
            raise IdJagError("invalid_grant", "assertion issuer is not a known tenant")

        # 2/4/5. Verify signature, iss, aud (== our issuer) and exp.
        with self._lock:
            verifier = self._verifiers.get(iss)
            if verifier is None:
                verifier = build_issuer_verifier(
                    iss, self._expected_audience, base_url=self._base_url
                )
                self._verifiers[iss] = verifier
        access = await verifier.verify_token(assertion)  # type: ignore[attr-defined]
        if access is None:
            raise IdJagError(
                "invalid_grant",
                "ID-JAG signature/issuer/audience/expiry validation failed",
            )
        claims = access.claims or {}

        # 7. Replay protection (only after the signature is trusted).
        self._check_replay(claims.get("jti"), claims.get("exp"))

        # 6. client_id must be permitted for this tenant.
        client_id = claims.get("client_id") or access.client_id or ""
        if tenant.workload_client_ids and client_id not in tenant.workload_client_ids:
            logger.warning(
                "ID-JAG rejected: client_id %r not in tenant allow-list %s",
                client_id, tenant.workload_client_ids,
            )
            raise IdJagError("invalid_grant", "assertion client_id is not permitted")

        sub = claims.get("sub")
        if not sub:
            raise IdJagError("invalid_grant", "assertion has no 'sub' claim")

        tenant_issuer = tenant.custom_issuer or tenant.org_issuer
        return IdJagClaims(
            sub=str(sub),
            client_id=str(client_id),
            scopes=list(access.scopes or []),
            tenant_domain=tenant.okta_domain,
            tenant_issuer=tenant_issuer,
            exp=claims.get("exp"),
            raw_claims=claims,
        )


# ----------------------------------------------------------------------------
# Opaque-token verifier (accepts our minted tokens on /mcp/*)
# ----------------------------------------------------------------------------

class OpaqueTokenVerifier(TokenVerifier):
    """Verify opaque access tokens we minted from ID-JAGs via local lookup.

    Returns ``None`` on a miss so a composing ``MultiAuth`` falls through to the
    Okta JWT verifier for the direct access-token path.
    """

    def __init__(
        self,
        *,
        store: TokenStore,
        resource_url: str | None = None,
        base_url: str | None = None,
        resource_base_url: str | None = None,
    ) -> None:
        super().__init__(base_url=base_url, resource_base_url=resource_base_url)
        self._store = store
        self._resource_url = resource_url

    async def verify_token(self, token: str) -> AccessToken | None:
        record = self._store.lookup(token)
        if record is None:
            return None
        return AccessToken(
            token=token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=record.expires_at,
            resource=self._resource_url,
            claims={
                "iss": record.tenant_issuer,
                "sub": record.sub,
                "tenant_domain": record.tenant_domain,
                "idjag": True,
                **record.extra_claims,
            },
        )
