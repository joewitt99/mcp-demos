"""ASGI-level check of the /config/clients credential endpoints.

These back the credential UI on the /config page: issue, list, rotate, revoke.
Admin resolution is stubbed — the PKCE login itself is out of scope here.
"""
import asyncio
import json
import os
import sys
import types

b = types.ModuleType("boto3"); b.client = lambda *a, **k: types.SimpleNamespace()
sys.modules["boto3"] = b
bc = types.ModuleType("botocore"); e = types.ModuleType("botocore.exceptions")
class CE(Exception): pass
e.ClientError = CE; bc.exceptions = e
sys.modules["botocore"] = bc; sys.modules["botocore.exceptions"] = e

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import config_routes
from fastmcp import FastMCP
from tenant_config import Tenant, TenantStore

BASE = "https://swiss.example.com"


def make_store(tenant):
    s = TenantStore.__new__(TenantStore)
    import threading
    s._lock = threading.Lock()
    s._by_domain = {tenant.okta_domain: tenant}
    s._by_workload_issuer = {}
    s._by_idjag_issuer = {}
    s._by_client_id = {cid: tenant for cid in tenant.clients}
    s.saved = []

    def save(t):
        s.saved.append(t.to_json())
        s._by_domain[t.okta_domain] = t
        for cid in list(s._by_client_id):
            if s._by_client_id[cid] is t:
                del s._by_client_id[cid]
        for cid in t.clients:
            s._by_client_id[cid] = t

    s.save = save
    return s


async def main():
    t = Tenant(okta_domain="acme.okta.com", admin_client_id="0oaAdmin",
               custom_issuer=f"{BASE}/aus", audience="api://default",
               workload_client_ids=["direct-app"])
    store = make_store(t)

    # stub admin resolution: any token resolves to our tenant, "" is anonymous
    async def fake_resolve(token, _store):
        return t if token else None
    config_routes._resolve_admin = fake_resolve

    mcp = FastMCP(name="t")
    config_routes.register_config_routes(
        mcp, store=store,
        workload_verifier=types.SimpleNamespace(invalidate=lambda *a: None),
        public_base_url=BASE, issuer=BASE, idjag_validator=None,
    )
    app = mcp.http_app()

    results = []
    def ck(n, c): results.append((n, c)); print(f"[{'PASS' if c else 'FAIL'}] {n}")

    AUTH = {"Authorization": "Bearer admin-token"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        async with app.router.lifespan_context(app):
            # the page itself carries the UI
            r = await client.get("/config")
            ck("page serves", r.status_code == 200)
            ck("page has credential UI",
               "cred-section" in r.text and "issue-btn" in r.text
               and "new_okta_client_id" in r.text)

            # unauthenticated access is refused on every credential route
            for method, path in [("GET", "/config/clients"),
                                 ("POST", "/config/clients"),
                                 ("POST", "/config/clients/rotate"),
                                 ("POST", "/config/clients/revoke")]:
                r = await client.request(method, path, json={})
                ck(f"{method} {path} needs admin", r.status_code == 401)

            # empty to start
            r = await client.get("/config/clients", headers=AUTH)
            ck("list starts empty", r.status_code == 200 and r.json()["clients"] == [])

            # issue
            r = await client.post("/config/clients", headers=AUTH,
                                  json={"okta_client_id": "0oaWorkload"})
            ck("issue 200", r.status_code == 200)
            d = r.json()
            cid, secret = d["client_id"], d["client_secret"]
            ck("client_id is ours", cid.startswith("samcp_"))
            ck("maps to okta app", d["okta_client_id"] == "0oaWorkload")
            ck("returns token endpoint", d["token_endpoint"] == f"{BASE}/token")
            ck("no-store on secret response",
               r.headers.get("cache-control") == "no-store")
            ck("secret authenticates", t.authenticate_client(cid, secret) is not None)
            ck("persisted to store", any(cid in blob for blob in store.saved))
            ck("plaintext never persisted",
               all(secret not in blob for blob in store.saved))

            # missing field
            r = await client.post("/config/clients", headers=AUTH, json={})
            ck("issue needs okta_client_id", r.status_code == 400)

            # list now shows it, without the secret
            r = await client.get("/config/clients", headers=AUTH)
            lst = r.json()["clients"]
            ck("list shows credential", len(lst) == 1 and lst[0]["client_id"] == cid)
            ck("list omits secrets", "secret" not in json.dumps(lst))
            ck("list shows okta mapping", lst[0]["okta_client_id"] == "0oaWorkload")

            # issuing must not widen the DIRECT-flow allow-list
            ck("direct allow-list untouched", t.workload_client_ids == ["direct-app"])
            ck("xaa allow-list is registry-derived",
               t.idjag_client_ids == ["0oaWorkload"])

            # rotate
            r = await client.post("/config/clients/rotate", headers=AUTH,
                                  json={"client_id": cid})
            ck("rotate 200", r.status_code == 200)
            new_secret = r.json()["client_secret"]
            ck("rotate keeps client_id", r.json()["client_id"] == cid)
            ck("rotate changes secret", new_secret != secret)
            ck("old secret dead", t.authenticate_client(cid, secret) is None)
            ck("new secret works", t.authenticate_client(cid, new_secret) is not None)

            r = await client.post("/config/clients/rotate", headers=AUTH,
                                  json={"client_id": "samcp_nope"})
            ck("rotate unknown -> 404", r.status_code == 404)

            # revoke
            r = await client.post("/config/clients/revoke", headers=AUTH,
                                  json={"client_id": cid})
            ck("revoke 200", r.status_code == 200)
            ck("revoked secret dead", t.authenticate_client(cid, new_secret) is None)
            ck("store index dropped it", store.find_client(cid) is None)
            r = await client.get("/config/clients", headers=AUTH)
            ck("list empty after revoke", r.json()["clients"] == [])
            ck("revoke left direct flow alone", t.workload_client_ids == ["direct-app"])

            r = await client.post("/config/clients/revoke", headers=AUTH,
                                  json={"client_id": cid})
            ck("revoke twice -> 404", r.status_code == 404)

    nf = sum(1 for _, c in results if not c)
    print(f"\n{len(results)-nf}/{len(results)} passed")
    sys.exit(1 if nf else 0)


asyncio.run(main())
