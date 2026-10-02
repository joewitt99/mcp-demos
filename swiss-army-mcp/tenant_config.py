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
# Client registry
#
# swiss-army-mcp is an authorization server in its own right (RFC 8414
# metadata, /token, it mints access tokens), so it keeps its own client
# registry rather than borrowing Okta's identifiers. Registering a workload
# issues a NEW client_id of ours plus a secret, and records which Okta
# client_id that credential speaks for.
#
# Two reasons this matters beyond tidiness:
#   * Our client_id is globally unique, so /token can authenticate the caller
#     *before* touching the assertion — RFC 6749 §5.2 order. Keying on Okta's
#     client_id forced us to validate the assertion first just to learn which
#     tenant's secret to check.
#   * The same Okta app registered in two orgs is distinguishable here, and
#     revoking our credential never touches anything in Okta.
#
# Secrets are shown to the admin exactly once and persisted only as a salted
# SHA-256 hash: the tenant blob is a plain SSM ``String`` (see
# TenantStore.save), so anything with ssm:GetParameter on the prefix can read
# it, and a hash keeps a leaked parameter from yielding usable credentials.
# Plain SHA-256 is adequate because the secret is 256 bits of os.urandom, not
# a human-chosen password.
# ---------------------------------------------------------------------------

_SECRET_SCHEME = "sha256"
CLIENT_ID_PREFIX = "samcp_"


def generate_client_id() -> str:
    """A client_id in our own namespace, unique across all tenants."""
    return CLIENT_ID_PREFIX + secrets.token_urlsafe(16)


def generate_client_secret() -> str:
    """A fresh 256-bit client secret, URL-safe. Shown once, never stored."""
    return secrets.token_urlsafe(32)


def hash_client_secret(secret: str, *, salt: bytes | None = None) -> str:
    """Encode as ``sha256$<salt_hex>$<digest_hex>``."""
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.sha256(salt + secret.encode()).hexdigest()
    return f"{_SECRET_SCHEME}${salt.hex()}${digest}"


def verify_client_secret(secret: str, stored: str) -> bool:
    """Constant-time check of ``secret`` against a stored hash."""
    try:
        scheme, salt_hex, digest_hex = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != _SECRET_SCHEME:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
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
    workload_client_ids: list[str] = field(default_factory=list)
    # Our client_id -> {"secret": <salted hash>, "okta_client_id": str,
    # "created": iso8601}. Credentials we issued; the key is in our namespace,
    # not Okta's. A workload with no entry here cannot redeem an ID-JAG, since
    # /token requires client authentication for every tenant.
    clients: dict[str, dict] = field(default_factory=dict)
    enforce_scopes: bool = False
    # Okta authorization-server URL that mints ID-JAG assertions (Cross-App
    # Access) for this customer. Often the same as ``custom_issuer``, but kept
    # separate so a tenant can mint ID-JAGs from a dedicated auth server. When
    # set, ID-JAGs whose ``iss`` matches this value are dispatched to this
    # tenant. See ``idjag.py``.
    idjag_issuer: str | None = None

    def register_client(self, okta_client_id: str) -> tuple[str, str]:
        """Issue a new (client_id, secret) pair for an Okta workload app.

        Returns our generated client_id and the plaintext secret. The secret is
        only ever returned here — storage keeps a salted hash.
        """
        client_id = generate_client_id()
        secret = generate_client_secret()
        self.clients[client_id] = {
            "secret": hash_client_secret(secret),
            "okta_client_id": okta_client_id,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        # Deliberately does NOT touch workload_client_ids. That list is the
        # allow-list for the DIRECT Okta-token flow on /mcp (see
        # okta_auth.build_workload_verifier), so appending here would let
        # registering an XAA credential silently widen direct access. The two
        # flows stay disjoint: `clients` governs ID-JAG redemption only.
        return client_id, secret

    def rotate_client_secret(self, client_id: str) -> str | None:
        """Replace one client's secret, keeping its client_id and mapping."""
        rec = self.clients.get(client_id)
        if rec is None:
            return None
        secret = generate_client_secret()
        rec["secret"] = hash_client_secret(secret)
        rec["rotated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return secret

    def revoke_client(self, client_id: str) -> bool:
        """Delete a credential. The Okta app is untouched."""
        return self.clients.pop(client_id, None) is not None

    def authenticate_client(self, client_id: str, secret: str) -> dict | None:
        """Return the client record when the secret matches, else None."""
        if not client_id or not secret:
            return None
        rec = self.clients.get(client_id)
        if not rec:
            return None
        if not verify_client_secret(secret, rec.get("secret") or ""):
            return None
        return rec

    @property
    def idjag_client_ids(self) -> list[str]:
        """Okta apps permitted to redeem ID-JAGs, from our client registry.

        Separate from workload_client_ids, which gates the direct Okta-token
        flow on /mcp. Falls back to that list only when no credential has been
        issued yet, so a tenant configured before the registry existed keeps
        working.
        """
        from_registry = [
            rec.get("okta_client_id") for rec in self.clients.values()
            if rec.get("okta_client_id")
        ]
        return from_registry or list(self.workload_client_ids)

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
            clients=dict(d.get("clients") or {}),
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
        # Our client_id -> owning tenant. Globally unique because we generate
        # the ids, which lets /token authenticate before reading the assertion.
        self._by_client_id: dict[str, Tenant] = {}

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
            self._by_client_id = {
                cid: t for t in loaded for cid in t.clients
            }
        logger.info(
            "Hydrated %d tenant(s) from %s; %d have workload config, "
            "%d registered client(s)",
            len(loaded), self.prefix, len(self._by_workload_issuer),
            len(self._by_client_id),
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

    def find_client(self, client_id: str) -> tuple[Tenant, dict] | None:
        """Resolve one of our client_ids to its tenant and record."""
        with self._lock:
            tenant = self._by_client_id.get(client_id)
        if tenant is None:
            return None
        rec = tenant.clients.get(client_id)
        if rec is None:
            return None
        return tenant, rec

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
            if old:
                # Drop every client_id the previous revision owned, so revoked
                # credentials stop resolving immediately.
                for cid in list(self._by_client_id):
                    if self._by_client_id.get(cid) is old:
                        del self._by_client_id[cid]
            self._by_domain[tenant.okta_domain.lower()] = tenant
            for cid in tenant.clients:
                self._by_client_id[cid] = tenant
            if tenant.custom_issuer:
                self._by_workload_issuer[tenant.custom_issuer] = tenant
            if tenant.idjag_issuer:
                self._by_idjag_issuer[tenant.idjag_issuer] = tenant
        logger.info(
            "Saved tenant %s (workload_config=%s, enforce_scopes=%s)",
            tenant.okta_domain, tenant.has_workload_config, tenant.enforce_scopes,
        )
