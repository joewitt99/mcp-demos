"""Multi-tenant config persistence for swiss-army-mcp.

A single deployed instance serves many customers. Each customer is identified
by their Okta org domain (e.g. ``your-tenant.oktapreview.com``) and self-
onboards via the ``/config`` UI. Their settings are persisted to AWS SSM
Parameter Store at ``/swiss-army-mcp/tenants/<domain>``.

Configuration:
    MCP_TENANTS_PREFIX     Prefix in SSM under which per-tenant JSON blobs
                           live. Defaults to ``/swiss-army-mcp/tenants/``.
    AWS_REGION             Standard AWS region env var.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resource server credentials
#
# Okta's resource server connector has two access methods. Cross App Access
# (XAA) asks only for Resource URL / Issuer URL / Audience and sends no client
# credentials. Brokered Consent asks for a Client ID, Client secret and
# scopes, which the resource server must supply.
#
# So we generate a credential — with no input, since the admin has nothing to
# give us at that point — and client authentication at /token is OPTIONAL:
# enforced when a request presents credentials, and skippable for pure XAA
# unless the tenant sets require_client_auth.
#
# Only a salted SHA-256 hash is persisted. The tenant blob is a plain SSM
# String, so anything with ssm:GetParameter on the prefix can read it; a hash
# keeps a leaked parameter from yielding a usable secret. Plain SHA-256 is
# adequate for 256 bits of os.urandom, which is not a human-chosen password.
# ---------------------------------------------------------------------------

_SECRET_SCHEME = "sha256"
RESOURCE_CLIENT_PREFIX = "samcp_"


def generate_client_id() -> str:
    return RESOURCE_CLIENT_PREFIX + secrets.token_urlsafe(16)


def generate_client_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_client_secret(secret: str, *, salt: bytes | None = None) -> str:
    salt = salt if salt is not None else secrets.token_bytes(16)
    return f"{_SECRET_SCHEME}${salt.hex()}${hashlib.sha256(salt + secret.encode()).hexdigest()}"


def verify_client_secret(secret: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$", 2)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    if scheme != _SECRET_SCHEME:
        return False
    expected = hashlib.sha256(salt + secret.encode()).hexdigest()
    return hmac.compare_digest(expected, digest_hex)


@dataclass
class Tenant:
    """One customer's runtime configuration."""

    okta_domain: str
    admin_client_id: str
    custom_issuer: str | None = None
    audience: str | None = None
    # Mode 1 (direct Okta access tokens on /mcp): Okta apps whose tokens are
    # accepted, matched against the `cid` claim.
    workload_client_ids: list[str] = field(default_factory=list)
    # Mode 2 (ID-JAG redeemed at /token): Okta apps permitted to redeem an
    # assertion, matched against the ID-JAG's `client_id` claim. Separate from
    # workload_client_ids on purpose — the two modes share nothing but scopes,
    # so neither list may widen the other. Empty means allow any client_id.
    idjag_client_ids: list[str] = field(default_factory=list)
    # Credential this server issues for Okta's Brokered Consent fields.
    # {"client_id", "secret" (hash), "created", "rotated"}. Generated with no
    # input — the admin has nothing to supply when registering us.
    resource_client: dict = field(default_factory=dict)
    # When true, /token rejects a request that presents no credentials. Off by
    # default so pure XAA (which sends none) keeps working.
    require_client_auth: bool = False
    enforce_scopes: bool = False
    # Okta authorization-server URL that mints ID-JAG assertions (Cross-App
    # Access) for this customer. Often the same as ``custom_issuer``, but kept
    # separate so a tenant can mint ID-JAGs from a dedicated auth server. When
    # set, ID-JAGs whose ``iss`` matches this value are dispatched to this
    # tenant. See ``idjag.py``.
    idjag_issuer: str | None = None

    def issue_resource_credentials(self) -> tuple[str, str]:
        """Generate (or rotate) this tenant's resource-server credential.

        Takes no arguments: Okta has not given the admin anything to supply at
        registration time. Keeps the existing client_id across a rotation so
        the value already pasted into Okta stays valid. Returns the plaintext
        secret for one-time display; only its hash is stored.
        """
        rotating = bool(self.resource_client.get("client_id"))
        client_id = self.resource_client.get("client_id") or generate_client_id()
        secret = generate_client_secret()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.resource_client = {
            "client_id": client_id,
            "secret": hash_client_secret(secret),
            "created": self.resource_client.get("created") or now,
        }
        if rotating:
            self.resource_client["rotated"] = now
        return client_id, secret

    def verify_resource_client(self, client_id: str, secret: str) -> bool:
        """Constant-time check of presented credentials."""
        rc = self.resource_client
        if not rc or not client_id or not secret:
            return False
        if not hmac.compare_digest(client_id, rc.get("client_id") or ""):
            return False
        return verify_client_secret(secret, rc.get("secret") or "")

    @property
    def resource_client_id(self) -> str | None:
        """The client_id, safe to redisplay. The secret is never recoverable."""
        return self.resource_client.get("client_id") or None

    @property
    def has_workload_config(self) -> bool:
        return bool(self.custom_issuer and self.audience)

    @property
    def org_issuer(self) -> str:
        """Okta org auth server URL — tenant root."""
        return f"https://{self.okta_domain}"

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "Tenant":
        d = json.loads(raw)
        return cls(
            okta_domain=d["okta_domain"],
            admin_client_id=d["admin_client_id"],
            custom_issuer=d.get("custom_issuer") or None,
            audience=d.get("audience") or None,
            workload_client_ids=list(d.get("workload_client_ids") or []),
            idjag_client_ids=list(d.get("idjag_client_ids") or []),
            resource_client=dict(d.get("resource_client") or {}),
            require_client_auth=bool(d.get("require_client_auth", False)),
            enforce_scopes=bool(d.get("enforce_scopes", False)),
            idjag_issuer=d.get("idjag_issuer") or None,
        )


class TenantStore:
    """Read/write per-tenant config from SSM Parameter Store.

    Caches everything in memory after the initial ``hydrate()`` call. The
    deployed server is single-task (DESIRED_COUNT=1), so cross-process cache
    invalidation isn't required.
    """

    def __init__(self, prefix: str | None = None, region: str | None = None):
        raw = prefix or os.environ.get("MCP_TENANTS_PREFIX") or "/swiss-army-mcp/tenants/"
        if not raw.endswith("/"):
            raw += "/"
        self.prefix = raw
        self.region = region or os.environ.get("AWS_REGION") or "us-east-1"
        self._ssm = boto3.client("ssm", region_name=self.region)
        self._lock = threading.Lock()
        self._by_domain: dict[str, Tenant] = {}
        self._by_workload_issuer: dict[str, Tenant] = {}
        self._by_idjag_issuer: dict[str, Tenant] = {}

    # ------------------------------------------------------------------
    # Hydration / lookup
    # ------------------------------------------------------------------

    def hydrate(self) -> None:
        """Fetch every tenant under the prefix and populate the caches."""
        paginator = self._ssm.get_paginator("get_parameters_by_path")
        loaded: list[Tenant] = []
        for page in paginator.paginate(Path=self.prefix, Recursive=False):
            for p in page.get("Parameters", []):
                try:
                    loaded.append(Tenant.from_json(p["Value"]))
                except Exception:
                    logger.exception("Skipping malformed tenant param %s", p.get("Name"))
        with self._lock:
            self._by_domain = {t.okta_domain: t for t in loaded}
            self._by_workload_issuer = {
                t.custom_issuer: t for t in loaded if t.custom_issuer
            }
            self._by_idjag_issuer = {
                t.idjag_issuer: t for t in loaded if t.idjag_issuer
            }
        logger.info(
            "Hydrated %d tenant(s) from %s; %d have workload config",
            len(loaded), self.prefix, len(self._by_workload_issuer),
        )

    def get(self, domain: str) -> Tenant | None:
        with self._lock:
            return self._by_domain.get(domain.lower())

    def find_by_workload_issuer(self, issuer: str) -> Tenant | None:
        with self._lock:
            return self._by_workload_issuer.get(issuer)

    def find_by_idjag_issuer(self, issuer: str) -> Tenant | None:
        with self._lock:
            return self._by_idjag_issuer.get(issuer)

    def resolve_tenant_by_issuer(self, issuer: str) -> Tenant | None:
        """Find the tenant an ID-JAG ``iss`` belongs to.

        An ID-JAG's issuer may be the tenant's dedicated ``idjag_issuer``, its
        workload ``custom_issuer``, or its org auth server (``org_issuer``).
        Try each, matching ``org_issuer`` by URL host so a bare org issuer
        (``https://<domain>``) resolves regardless of trailing path.
        """
        if not issuer:
            return None
        with self._lock:
            hit = self._by_idjag_issuer.get(issuer) or self._by_workload_issuer.get(issuer)
            if hit is not None:
                return hit
            host = urlparse(issuer).netloc.lower()
            for t in self._by_domain.values():
                if urlparse(t.org_issuer).netloc.lower() == host:
                    return t
        return None

    def all(self) -> list[Tenant]:
        with self._lock:
            return list(self._by_domain.values())

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def save(self, tenant: Tenant) -> None:
        """Persist a tenant to SSM and update the in-memory caches."""
        param_name = self.prefix + tenant.okta_domain.lower()
        self._ssm.put_parameter(
            Name=param_name,
            Value=tenant.to_json(),
            Type="String",
            Overwrite=True,
        )
        with self._lock:
            # If updating an existing entry, evict the old issuer index entries
            # first (either issuer may have changed).
            old = self._by_domain.get(tenant.okta_domain.lower())
            if old and old.custom_issuer and old.custom_issuer in self._by_workload_issuer:
                if self._by_workload_issuer.get(old.custom_issuer) is old:
                    del self._by_workload_issuer[old.custom_issuer]
            if old and old.idjag_issuer and old.idjag_issuer in self._by_idjag_issuer:
                if self._by_idjag_issuer.get(old.idjag_issuer) is old:
                    del self._by_idjag_issuer[old.idjag_issuer]
            self._by_domain[tenant.okta_domain.lower()] = tenant
            if tenant.custom_issuer:
                self._by_workload_issuer[tenant.custom_issuer] = tenant
            if tenant.idjag_issuer:
                self._by_idjag_issuer[tenant.idjag_issuer] = tenant
        logger.info(
            "Saved tenant %s (workload_config=%s, enforce_scopes=%s)",
            tenant.okta_domain, tenant.has_workload_config, tenant.enforce_scopes,
        )
