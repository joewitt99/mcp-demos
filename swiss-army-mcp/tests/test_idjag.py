"""Network-free verification of the ID-JAG core logic.

Run directly: ``python tests/test_idjag.py`` (exit code 0 = all pass).

Stubs boto3 (a deploy-only dependency) and injects a fake signature verifier so
we can exercise IdJagValidator / TokenStore / OpaqueTokenVerifier and the tenant
issuer resolution without hitting Okta or SSM.
"""
import asyncio
import base64
import json
import os
import sys
import time
import types

# --- stub boto3 / botocore so tenant_config imports without the deploy dep ---
if "boto3" not in sys.modules:
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda *a, **k: types.SimpleNamespace()
    sys.modules["boto3"] = boto3
    botocore = types.ModuleType("botocore")
    exc = types.ModuleType("botocore.exceptions")
    class ClientError(Exception):
        pass
    exc.ClientError = ClientError
    botocore.exceptions = exc
    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = exc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import idjag  # noqa: E402
from tenant_config import Tenant, TenantStore  # noqa: E402

PASS, FAIL = "PASS", "FAIL"
results = []
def check(name, cond):
    results.append((name, cond))
    print(f"[{PASS if cond else FAIL}] {name}")


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

def make_jag(typ="oauth-id-jag+jwt", **claims):
    header = {"alg": "RS256", "typ": typ, "kid": "k1"}
    return f"{b64(header)}.{b64(claims)}.sig"


class FakeVerifier:
    """Mimics OktaJWTVerifier: checks aud + exp, returns AccessToken-like."""
    def __init__(self, audience):
        self.audience = audience
    async def verify_token(self, token):
        _, payload_b64, _ = token.split(".")
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        if claims.get("aud") != self.audience:
            return None
        if claims.get("exp", 0) <= time.time():
            return None
        scope = claims.get("scope", "")
        return types.SimpleNamespace(
            claims=claims,
            scopes=scope.split() if scope else [],
            client_id=claims.get("client_id"),
        )


ISSUER = "https://swiss.example.com"
IDP = "https://acme.okta.com/oauth2/aus123"


def make_store():
    store = TenantStore.__new__(TenantStore)  # bypass __init__/boto3
    import threading
    store._lock = threading.Lock()
    store._by_domain = {}
    store._by_workload_issuer = {}
    store._by_idjag_issuer = {}
    t = Tenant(
        okta_domain="acme.okta.com",
        admin_client_id="0oaAdmin",
        custom_issuer=IDP,
        audience="api://default",
        workload_client_ids=["client-abc"],
        enforce_scopes=True,
        idjag_issuer=IDP,
    )
    store._by_domain[t.okta_domain] = t
    store._by_workload_issuer[t.custom_issuer] = t
    store._by_idjag_issuer[t.idjag_issuer] = t
    return store, t


async def main():
    store, tenant = make_store()

    # tenant resolution
    check("resolve by idjag_issuer", store.resolve_tenant_by_issuer(IDP) is tenant)
    check("resolve by org host", store.resolve_tenant_by_issuer("https://acme.okta.com") is tenant)
    check("resolve unknown -> None", store.resolve_tenant_by_issuer("https://evil.com") is None)

    def fresh_validator():
        v = idjag.IdJagValidator(store=store, expected_audience=ISSUER)
        v._verifiers[IDP] = FakeVerifier(ISSUER)  # inject; skip network JWKS
        return v

    now = int(time.time())
    good = dict(iss=IDP, sub="U123", aud=ISSUER, client_id="client-abc",
               jti="j1", exp=now + 300, iat=now, scope="swiss-army-mcp:text swiss-army-mcp:math")

    # happy path
    v = fresh_validator()
    claims = await v.validate(make_jag(**good))
    check("valid ID-JAG accepted", claims.sub == "U123" and claims.tenant_domain == "acme.okta.com")
    check("scopes extracted", claims.scopes == ["swiss-army-mcp:text", "swiss-army-mcp:math"])

    # wrong typ
    v = fresh_validator()
    try:
        await v.validate(make_jag(typ="JWT", **good))
        check("wrong typ rejected", False)
    except idjag.IdJagError as e:
        check("wrong typ rejected", e.oauth_error == "invalid_grant")

    # wrong aud
    v = fresh_validator()
    bad_aud = {**good, "aud": "https://other.example.com", "jti": "j2"}
    try:
        await v.validate(make_jag(**bad_aud))
        check("wrong aud rejected", False)
    except idjag.IdJagError as e:
        check("wrong aud rejected", e.oauth_error == "invalid_grant")

    # expired
    v = fresh_validator()
    expired = {**good, "exp": now - 10, "jti": "j3"}
    try:
        await v.validate(make_jag(**expired))
        check("expired rejected", False)
    except idjag.IdJagError:
        check("expired rejected", True)

    # unknown issuer
    v = fresh_validator()
    unknown = {**good, "iss": "https://evil.com", "jti": "j4"}
    try:
        await v.validate(make_jag(**unknown))
        check("unknown issuer rejected", False)
    except idjag.IdJagError:
        check("unknown issuer rejected", True)

    # client_id not allowed
    v = fresh_validator()
    badcid = {**good, "client_id": "not-allowed", "jti": "j5"}
    try:
        await v.validate(make_jag(**badcid))
        check("bad client_id rejected", False)
    except idjag.IdJagError:
        check("bad client_id rejected", True)

    # replay: same jti twice
    v = fresh_validator()
    await v.validate(make_jag(**good))
    try:
        await v.validate(make_jag(**good))
        check("jti replay rejected", False)
    except idjag.IdJagError as e:
        check("jti replay rejected", "replay" in e.description.lower())

    # TokenStore mint/lookup/expiry
    ts = idjag.TokenStore()
    tok = ts.mint(sub="U123", client_id="client-abc", scopes=["swiss-army-mcp:text"],
                  tenant_domain="acme.okta.com", tenant_issuer=IDP, expires_in=60)
    rec = ts.lookup(tok)
    check("token mint+lookup", rec is not None and rec.sub == "U123")
    check("unknown token -> None", ts.lookup("nope") is None)
    expired_tok = ts.mint(sub="U9", client_id="c", scopes=[], tenant_domain="acme.okta.com",
                          tenant_issuer=IDP, expires_in=-1)
    check("expired token -> None", ts.lookup(expired_tok) is None)

    # OpaqueTokenVerifier
    ov = idjag.OpaqueTokenVerifier(store=ts, resource_url=f"{ISSUER}/mcp/")
    at = await ov.verify_token(tok)
    check("opaque verify hit", at is not None and at.claims["tenant_domain"] == "acme.okta.com"
          and at.claims["iss"] == IDP and at.claims["idjag"] is True)
    check("opaque verify miss -> None", await ov.verify_token("nope") is None)

    print()
    n_fail = sum(1 for _, ok in results if not ok)
    print(f"{len(results) - n_fail}/{len(results)} passed")
    sys.exit(1 if n_fail else 0)


asyncio.run(main())
