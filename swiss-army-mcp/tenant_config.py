"""Multi-tenant config persistence for swiss-army-mcp.

A single deployed instance serves many customers. Each customer is identified
by their Okta org domain (e.g. ``joe-wf-oie-demos.oktapreview.com``) and self-
onboards via the ``/config`` UI. Their settings are persisted to AWS SSM
Parameter Store at ``/swiss-army-mcp/tenants/<domain>``.

Configuration:
    MCP_TENANTS_PREFIX     Prefix in SSM under which per-tenant JSON blobs
                           live. Defaults to ``/swiss-army-mcp/tenants/``.
    AWS_REGION             Standard AWS region env var.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class Tenant:
    """One customer's runtime configuration."""

    okta_domain: str
    admin_client_id: str
    custom_issuer: str | None = None
    audience: str | None = None
    workload_client_ids: list[str] = field(default_factory=list)
    enforce_scopes: bool = False

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
            enforce_scopes=bool(d.get("enforce_scopes", False)),
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
            # If updating an existing entry, evict the old workload-issuer
            # index entry first (the issuer may have changed).
            old = self._by_domain.get(tenant.okta_domain.lower())
            if old and old.custom_issuer and old.custom_issuer in self._by_workload_issuer:
                if self._by_workload_issuer.get(old.custom_issuer) is old:
                    del self._by_workload_issuer[old.custom_issuer]
            self._by_domain[tenant.okta_domain.lower()] = tenant
            if tenant.custom_issuer:
                self._by_workload_issuer[tenant.custom_issuer] = tenant
        logger.info(
            "Saved tenant %s (workload_config=%s, enforce_scopes=%s)",
            tenant.okta_domain, tenant.has_workload_config, tenant.enforce_scopes,
        )
