"""ASGI-level check of the OAuth routes + /token redemption end to end."""
import asyncio
import base64
import json
import sys
import time
import types

b = types.ModuleType("boto3"); b.client = lambda *a, **k: types.SimpleNamespace()
sys.modules["boto3"] = b
bc = types.ModuleType("botocore"); e = types.ModuleType("botocore.exceptions")
class CE(Exception): pass
e.ClientError = CE; bc.exceptions = e
sys.modules["botocore"] = bc; sys.modules["botocore.exceptions"] = e

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import idjag
from fastmcp import FastMCP
from oauth_routes import register_oauth_routes
from tenant_config import Tenant, TenantStore

ISSUER = "https://swiss.example.com"
IDP = "https://acme.okta.com/oauth2/aus123"


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

def make_jag(**claims):
    return f'{b64({"alg":"RS256","typ":"oauth-id-jag+jwt","kid":"k1"})}.{b64(claims)}.sig'


class FakeVerifier:
    def __init__(self, aud): self.aud = aud
    async def verify_token(self, token):
        _, p, _ = token.split("."); p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        if c.get("aud") != self.aud or c.get("exp", 0) <= time.time():
            return None
        sc = c.get("scope", "")
        return types.SimpleNamespace(claims=c, scopes=sc.split() if sc else [],
                                     client_id=c.get("client_id"))


async def main():
    store = TenantStore.__new__(TenantStore)
    import threading
    store._lock = threading.Lock()
    store._by_domain = {}; store._by_workload_issuer = {}; store._by_idjag_issuer = {}
    t = Tenant(okta_domain="acme.okta.com", admin_client_id="0oaAdmin",
               custom_issuer=IDP, audience="api://default",
               workload_client_ids=["client-abc"], idjag_issuer=IDP)
    store._by_domain[t.okta_domain] = t
    store._by_client_id = {}
    store._by_workload_issuer[IDP] = t; store._by_idjag_issuer[IDP] = t

    # /token requires client authentication. We issue our OWN client_id and
    # bind it to the Okta app ("client-abc") that will present ID-JAGs.
    CID, CLIENT_SECRET = t.register_client("client-abc")
    BASIC = "Basic " + base64.b64encode(f"{CID}:{CLIENT_SECRET}".encode()).decode()
    store._by_client_id[CID] = t

    token_store = idjag.TokenStore()
    validator = idjag.IdJagValidator(store=store, expected_audience=ISSUER)
    validator._verifiers[IDP] = FakeVerifier(ISSUER)

    mcp = FastMCP(name="t")
    register_oauth_routes(mcp, store=store, token_store=token_store, validator=validator,
                          issuer=ISSUER, resource_url=f"{ISSUER}/mcp/", opaque_ttl=3600)
    app = mcp.http_app()

    results = []
    def ck(n, c): results.append((n, c)); print(f"[{'PASS' if c else 'FAIL'}] {n}")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        async with app.router.lifespan_context(app):
            r = await client.get("/.well-known/oauth-authorization-server")
            m = r.json()
            ck("AS metadata 200", r.status_code == 200)
            ck("AS issuer", m["issuer"] == ISSUER)
            ck("AS grant types", m["grant_types_supported"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"])
            ck("AS id-jag profile", "urn:ietf:params:oauth:grant-profile:id-jag" in m["authorization_grant_profiles_supported"])

            r = await client.get("/.well-known/oauth-protected-resource")
            p = r.json()
            ck("PRM 200", r.status_code == 200)
            ck("PRM resource", p["resource"] == f"{ISSUER}/mcp")
            ck("PRM auth servers", p["authorization_servers"] == [ISSUER])

            r = await client.get("/authorize")
            ck("authorize stub 400", r.status_code == 400 and r.json()["error"] == "unsupported_response_type")

            now = int(time.time())
            jag = make_jag(iss=IDP, sub="U123", aud=ISSUER, client_id="client-abc",
                           jti="jr1", exp=now + 300, iat=now, scope="swiss-army-mcp:text")
            r = await client.post("/token", headers={"Authorization": BASIC}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jag})
            tok = r.json()
            ck("token 200 (client_secret_basic)", r.status_code == 200)
            ck("token opaque + bearer", tok["token_type"] == "Bearer" and len(tok["access_token"]) > 20)
            ck("no refresh token", "refresh_token" not in tok)
            ck("scope echoed", tok["scope"] == "swiss-army-mcp:text")
            ck("no-store header", r.headers.get("cache-control") == "no-store")

            # minted token resolves in the store
            ck("minted token usable", token_store.lookup(tok["access_token"]) is not None)

            # bad grant type
            r = await client.post("/token", data={"grant_type": "authorization_code", "assertion": "x"})
            ck("bad grant -> unsupported_grant_type", r.json()["error"] == "unsupported_grant_type")

            # missing assertion
            # RFC 9728 §3.1: the PRM lives at the well-known prefix + the
            # resource's path. This is the URL the 401 challenge advertises and
            # the first one MCP clients fetch, so it must resolve — serving only
            # the root path 404'd every spec-compliant client's discovery.
            r = await client.get("/.well-known/oauth-protected-resource/mcp")
            ck("PRM path-based 200", r.status_code == 200)
            ck("PRM path-based resource", r.json()["resource"] == f"{ISSUER}/mcp")

            r = await client.get("/.well-known/oauth-protected-resource")
            ck("PRM root 200", r.status_code == 200)
            ck("PRM root resource no trailing slash", r.json()["resource"] == f"{ISSUER}/mcp")
            ck("PRM root authz server", r.json()["authorization_servers"] == [ISSUER])

            r = await client.post("/token", headers={"Authorization": BASIC},
                                  data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer"})
            ck("missing assertion -> invalid_request", r.json()["error"] == "invalid_request")

            # bad aud -> invalid_grant
            jag2 = make_jag(iss=IDP, sub="U1", aud="https://wrong", client_id="client-abc",
                            jti="jr2", exp=now + 300, iat=now)
            r = await client.post("/token", headers={"Authorization": BASIC}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jag2})
            ck("bad aud -> invalid_grant 400", r.status_code == 400 and r.json()["error"] == "invalid_grant")

            # ---- client authentication at /token ----
            def jag_for(cid, jti):
                return make_jag(iss=IDP, sub="U123", aud=ISSUER, client_id=cid,
                                jti=jti, exp=now + 300, iat=now,
                                scope="swiss-army-mcp:text")

            # no credentials at all -> 401 invalid_client + challenge
            r = await client.post("/token", data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-abc", "ca1")})
            ck("no creds -> 401 invalid_client",
               r.status_code == 401 and r.json()["error"] == "invalid_client")
            ck("no creds -> WWW-Authenticate",
               r.headers.get("www-authenticate", "").startswith("Basic "))

            # wrong secret -> 401 invalid_client
            bad = "Basic " + base64.b64encode(f"{CID}:wrong".encode()).decode()
            r = await client.post("/token", headers={"Authorization": bad}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-abc", "ca2")})
            ck("wrong secret -> 401 invalid_client",
               r.status_code == 401 and r.json()["error"] == "invalid_client")

            # unknown client_id -> 401 invalid_client
            unk = "Basic " + base64.b64encode(f"samcp_nope:{CLIENT_SECRET}".encode()).decode()
            r = await client.post("/token", headers={"Authorization": unk}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-abc", "ca3")})
            ck("unknown client -> 401 invalid_client",
               r.status_code == 401 and r.json()["error"] == "invalid_client")

            # client_secret_post works too
            r = await client.post("/token", data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-abc", "ca4"),
                "client_id": CID, "client_secret": CLIENT_SECRET})
            ck("client_secret_post -> 200", r.status_code == 200)

            # THE binding check: authenticate as client-abc, present an
            # assertion issued to a different registered client.
            CID2, other_secret = t.register_client("client-xyz")
            store._by_client_id[CID2] = t
            r = await client.post("/token", headers={"Authorization": BASIC}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-xyz", "ca5")})
            ck("cross-client replay -> invalid_grant",
               r.status_code == 400 and r.json()["error"] == "invalid_grant")

            # the rightful client can redeem its own assertion
            own = "Basic " + base64.b64encode(f"{CID2}:{other_secret}".encode()).decode()
            r = await client.post("/token", headers={"Authorization": own}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-xyz", "ca6")})
            ck("rightful client -> 200", r.status_code == 200)

            # rotation invalidates the old secret
            t.rotate_client_secret(CID)
            r = await client.post("/token", headers={"Authorization": BASIC}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-abc", "ca7")})
            ck("rotated secret invalidates old",
               r.status_code == 401 and r.json()["error"] == "invalid_client")

            # our client_id is in OUR namespace, not Okta's
            ck("client_id is ours", CID.startswith("samcp_") and CID != "client-abc")

            # auth runs before the grant: bad creds + unparseable assertion
            # must yield invalid_client, not invalid_grant
            r = await client.post("/token",
                headers={"Authorization": "Basic " + base64.b64encode(b"samcp_x:y").decode()},
                data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                      "assertion": "not.a.jwt"})
            ck("auth precedes grant processing",
               r.status_code == 401 and r.json()["error"] == "invalid_client")

            # Cross-tenant: two customers can legitimately register the same
            # Okta client_id value. A credential issued by tenant B must not
            # redeem an assertion that resolved to tenant A.
            IDP_B = "https://beta.okta.com/oauth2/ausB"
            tb = Tenant(okta_domain="beta.okta.com", admin_client_id="0oaB",
                        custom_issuer=IDP_B, audience="api://default",
                        workload_client_ids=["client-abc"], idjag_issuer=IDP_B)
            CID_B, SEC_B = tb.register_client("client-abc")
            store._by_domain[tb.okta_domain] = tb
            store._by_idjag_issuer[IDP_B] = tb
            store._by_client_id[CID_B] = tb
            basic_b = "Basic " + base64.b64encode(f"{CID_B}:{SEC_B}".encode()).decode()
            # assertion below is issued by tenant A's IdP (IDP), naming the
            # same okta client_id, so only the tenant check can stop it
            r = await client.post("/token", headers={"Authorization": basic_b}, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": jag_for("client-abc", "ct1")})
            ck("cross-tenant redemption blocked",
               r.status_code == 400 and r.json()["error"] == "invalid_grant")

            # ---- the two flows must stay disjoint ----
            # workload_client_ids gates the DIRECT Okta-token flow on /mcp.
            # Registering an XAA credential must not widen it, or issuing an
            # ID-JAG credential would silently grant direct /mcp access.
            td = Tenant(okta_domain="d.okta.com", admin_client_id="0oaD",
                        custom_issuer=IDP, audience="api://default",
                        workload_client_ids=["direct-only-app"])
            before = list(td.workload_client_ids)
            xcid, _ = td.register_client("xaa-only-app")
            ck("register does not widen direct flow",
               td.workload_client_ids == before)
            ck("xaa app absent from direct allow-list",
               "xaa-only-app" not in td.workload_client_ids)
            ck("xaa allow-list comes from the registry",
               td.idjag_client_ids == ["xaa-only-app"])
            ck("direct-only app cannot redeem ID-JAGs",
               "direct-only-app" not in td.idjag_client_ids)
            # revoking the credential empties the XAA list without touching
            # the direct one
            td.revoke_client(xcid)
            ck("revoke leaves direct flow intact",
               td.workload_client_ids == before)
            # and with no credentials issued, the legacy list is the fallback
            ck("empty registry falls back to legacy list",
               td.idjag_client_ids == ["direct-only-app"])

            # metadata advertises the real auth methods
            m2 = (await client.get("/.well-known/oauth-authorization-server")).json()
            ck("metadata advertises client auth",
               m2["token_endpoint_auth_methods_supported"] ==
               ["client_secret_basic", "client_secret_post"])

    nf = sum(1 for _, c in results if not c)
    print(f"\n{len(results)-nf}/{len(results)} passed")
    sys.exit(1 if nf else 0)


asyncio.run(main())
