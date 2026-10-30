"""End-to-end check of /config onboarding, multi-tenant token routing, the REST
surface, and per-tenant scope enforcement.

Uses an in-memory stand-in for SSM and signs tokens with throwaway RSA keys
(selected by `kid`), so no AWS account, network or Okta org is needed. Run
with ``python tests/test_api.py`` (or pytest).
"""
import os
import sys
import time
import types

os.environ.update(API_BASE_URL="https://api.example.com")
os.environ.pop("API_AUTH_DISABLED", None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeSSM:
    def __init__(self):
        self.params = {}

    def put_parameter(self, Name, Value, **_):
        self.params[Name] = Value

    def get_paginator(self, _op):
        params = self.params
        return types.SimpleNamespace(paginate=lambda **_: [
            {"Parameters": [{"Name": k, "Value": v} for k, v in params.items()]}
        ])


import boto3
SSM = FakeSSM()
boto3.client = lambda *a, **k: SSM

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app as api

KEYS = {kid: rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for kid in ("org", "acme", "globex", "rogue")}
jwt.PyJWKClient.get_signing_key_from_jwt = lambda _self, t: types.SimpleNamespace(
    key=KEYS[jwt.get_unverified_header(t)["kid"]].public_key()
)
client = TestClient(api.app)

DOMAIN = "acme.okta.com"
ADMIN_CID = "0oaAdminSpa"
ACME_ISS = "https://acme.okta.com/oauth2/aus123"
ACME_AUD = "api://swiss-army-api"
GLOBEX_ISS = "https://globex.okta.com/oauth2/ausG"


def sign(kid, **claims):
    claims.setdefault("exp", int(time.time()) + 300)
    return jwt.encode(claims, KEYS[kid], algorithm="RS256", headers={"kid": kid})


def admin_token(**o):
    return sign("org", **{"iss": f"https://{DOMAIN}", "aud": f"https://{DOMAIN}",
                          "cid": ADMIN_CID, **o})


def acme_token(**o):
    return sign("acme", **{"iss": ACME_ISS, "aud": ACME_AUD, "cid": "0oaWorkload",
                           "scp": ["swiss-army-api:text", "swiss-army-api:datetime"], **o})


def auth(t):
    return {"Authorization": f"Bearer {t}"}


def test_openapi_contract():
    spec = client.get("/openapi.json").json()
    ops = {op["operationId"]: op for p in spec["paths"].values() for op in p.values()}
    assert len(ops) == 25, sorted(ops)  # /config routes must not leak in
    assert spec["servers"] == [{"url": "https://api.example.com"}]
    assert ops["text_uppercase"]["security"] == [{"OktaBearer": ["swiss-army-api:text"]}]
    assert "requestBody" not in ops["rand_uuid"]
    assert ops["rand_password"]["requestBody"].get("required") is not True


def test_unknown_tenant_rejected():
    r = client.post("/v1/text/uppercase", json={"text": "hi"}, headers=auth(acme_token()))
    assert r.status_code == 401


def test_onboarding():
    page = client.get("/config").text
    assert "https://api.example.com/config/callback" in page
    assert "https://api.example.com/openapi.json" in page
    assert client.get("/config/lookup", params={"domain": DOMAIN}).json()["exists"] is False

    body = {"okta_domain": DOMAIN, "admin_client_id": ADMIN_CID}
    # Wrong client_id in the token → nothing written.
    r = client.post("/config/finalize", json=body, headers=auth(admin_token(cid="0oaOther")))
    assert r.status_code == 401 and not SSM.params
    r = client.post("/config/finalize", json=body, headers=auth(admin_token()))
    assert r.status_code == 200, r.text
    assert "/swiss-army-api/tenants/acme.okta.com" in SSM.params
    assert client.get("/config/lookup", params={"domain": DOMAIN}).json()["admin_client_id"] == ADMIN_CID

    assert client.get("/config/workload", headers=auth(admin_token())).status_code == 204
    assert client.get("/config/workload", headers=auth(acme_token())).status_code == 401
    r = client.post("/config/workload", headers=auth(admin_token()), json={
        "custom_issuer": ACME_ISS + "/", "audience": ACME_AUD,
        "workload_client_ids": "0oaWorkload", "enforce_scopes": False,
    })
    assert r.status_code == 200, r.text
    cfg = client.get("/config/workload", headers=auth(admin_token())).json()
    assert cfg["custom_issuer"] == ACME_ISS and cfg["workload_client_ids"] == ["0oaWorkload"]


def test_workload_calls():
    r = client.post("/v1/text/uppercase", json={"text": "hi"}, headers=auth(acme_token()))
    assert r.status_code == 200 and r.json() == {"result": "HI"}
    r = client.get("/v1/datetime/current-iso", headers=auth(acme_token()))
    assert r.status_code == 200 and r.json()["result"].endswith("+00:00")
    # Scopes are not enforced yet: a token without math scope still works.
    r = client.post("/v1/math/add", json={"a": 1, "b": 2}, headers=auth(acme_token()))
    assert r.json() == {"result": 3.0}
    r = client.post("/v1/random/password", headers=auth(acme_token()))
    assert r.status_code == 200 and len(r.json()["result"]) == 16


def test_rejections():
    r = client.post("/v1/text/uppercase", json={"text": "hi"})
    assert r.status_code == 401
    assert 'resource_metadata="https://api.example.com/' in r.headers["www-authenticate"]
    for bad in (
        # acme's kid, signed with someone else's key
        jwt.encode({"iss": ACME_ISS, "aud": ACME_AUD, "cid": "0oaWorkload",
                    "exp": int(time.time()) + 300},
                   KEYS["rogue"], algorithm="RS256", headers={"kid": "acme"}),
        acme_token(aud="api://other"),
        acme_token(exp=int(time.time()) - 10),
        acme_token(cid="0oaSomeoneElse"),
        admin_token(),  # org token isn't a workload token
    ):
        r = client.post("/v1/text/uppercase", json={"text": "hi"}, headers=auth(bad))
        assert r.status_code == 401, r.text


def test_scope_enforcement_toggles_live():
    client.post("/config/workload", headers=auth(admin_token()), json={
        "custom_issuer": ACME_ISS, "audience": ACME_AUD,
        "workload_client_ids": ["0oaWorkload"], "enforce_scopes": True,
    })
    r = client.post("/v1/math/add", json={"a": 1, "b": 2}, headers=auth(acme_token()))
    assert r.status_code == 403
    assert 'scope="swiss-army-api:math"' in r.headers["www-authenticate"]
    r = client.post("/v1/math/add", json={"a": 1, "b": 2},
                    headers=auth(acme_token(scp=["swiss-army-api:*"])))
    assert r.status_code == 200


def test_issuer_cannot_be_claimed_twice():
    # A second tenant must not hijack acme's issuer routing.
    other = "globex.okta.com"
    t = lambda: sign("org", iss=f"https://{other}", aud=f"https://{other}", cid="0oaG")
    client.post("/config/finalize", json={"okta_domain": other, "admin_client_id": "0oaG"},
                headers=auth(t()))
    r = client.post("/config/workload", headers=auth(t()),
                    json={"custom_issuer": ACME_ISS, "audience": "x"})
    assert r.status_code == 409
    r = client.post("/config/workload", headers=auth(t()),
                    json={"custom_issuer": GLOBEX_ISS, "audience": "api://g"})
    assert r.status_code == 200
    r = client.get("/v1/fun/joke", headers=auth(sign("globex", iss=GLOBEX_ISS, aud="api://g")))
    assert r.status_code == 200


def test_rebrand_refused_and_hydrate_roundtrip():
    r = client.post("/config/finalize", json={"okta_domain": DOMAIN, "admin_client_id": "0oaNew"},
                    headers=auth(admin_token(cid="0oaNew")))
    assert r.status_code == 409
    fresh = api.TenantStore()
    fresh.hydrate()
    assert {t.okta_domain for t in fresh.all()} == {DOMAIN, "globex.okta.com"}
    assert fresh.find_by_workload_issuer(ACME_ISS).enforce_scopes is True


def test_tool_errors_are_400():
    t = acme_token(scp=["swiss-army-api:*"])
    r = client.post("/v1/math/divide", json={"a": 1, "b": 0}, headers=auth(t))
    assert r.status_code == 400 and "Division by zero" in r.json()["detail"]
    r = client.post("/v1/data/regex-match", json={"pattern": "(", "text": "x"}, headers=auth(t))
    assert r.status_code == 400
    r = client.post("/v1/math/add", json={"a": "nope"}, headers=auth(t))
    assert r.status_code == 422


def test_health_and_prm_are_public():
    assert client.get("/healthz").text == "ok"
    prm = client.get("/.well-known/oauth-protected-resource").json()
    assert "swiss-army-api:*" in prm["scopes_supported"]
    assert "authorization_servers" not in prm


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
