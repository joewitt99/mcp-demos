# swiss-army-api

A REST/OpenAPI companion to [`swiss-army-mcp`](../swiss-army-mcp): **25 of its
100 tools**, exposed as plain HTTP operations and protected by **Okta access
tokens from a custom authorization server**. Built to be imported into the
Bridge's OpenAPI→MCP support, so the bridged tools show up with the same names
(`text_uppercase`, `math_add`, ...) as on swiss-army-mcp.

- **Contract:** `GET /openapi.json` (OpenAPI 3.1, unauthenticated). Swagger UI at `/docs`.
- **Auth:** `Authorization: Bearer <okta-access-token>` on every `/v1/*` call.
  Multi-tenant like swiss-army-mcp — customers self-onboard at `/config`;
  per-tenant settings persist to AWS SSM.
- **Image:** `joewitt99/swiss-army-api` (build and push it yourself — see below).

## How it maps to swiss-army-mcp

| | swiss-army-mcp | swiss-army-api |
| --- | --- | --- |
| Tools | 100 MCP tools | 25 REST operations, `operationId` = MCP tool name |
| Tool code | `server.py` | `tools.py` (copied verbatim) |
| Okta verification | `okta_auth.py` (FastMCP `JWTVerifier`) | `okta_auth.py` (PyJWT; same `iss` routing, JWKS-URI rule, `cid` allow-list, diagnostics) |
| Tenancy | `/config` + `tenant_config.py` (SSM) | Same flow and store, minus the ID-JAG / XAA fields |
| Scopes | `swiss-army-mcp:<category>` | `swiss-army-api:<category>`, advertised per operation in OpenAPI |
| Auth modes | Okta JWTs + ID-JAG → opaque token | Okta JWTs only (the Bridge presents them directly) |
| Deploy | `deploy/terraform` | `deploy/terraform` (same module minus ALB stickiness) |

## The 25 operations

Tools with arguments are `POST` with a JSON body whose fields are the tool's
arguments; tools without arguments are `GET`. Every response is
`{"result": <value>}`. Bad input → `400`, schema mismatch → `422`.

| Category (scope) | Operations |
| --- | --- |
| Text (`swiss-army-api:text`) | `POST /v1/text/uppercase`, `/word-count`, `/slugify` |
| Math (`swiss-army-api:math`) | `POST /v1/math/add`, `/divide`, `/factorial` |
| Encoding (`swiss-army-api:encoding`) | `POST /v1/encoding/base64`, `/base64-decode`, `/url` |
| Hashing (`swiss-army-api:hashing`) | `POST /v1/hashing/sha256`, `/password-strength` |
| Date/Time (`swiss-army-api:datetime`) | `GET /v1/datetime/current-iso`, `POST /days-between`, `/add-days` |
| Random (`swiss-army-api:random`) | `GET /v1/random/uuid`, `POST /password` (body optional) |
| Color (`swiss-army-api:color`) | `POST /v1/color/hex-to-rgb`, `/contrast-ratio` |
| Units (`swiss-army-api:units`) | `POST /v1/units/celsius-to-fahrenheit`, `/miles-to-km` |
| Data (`swiss-army-api:data`) | `POST /v1/data/json-validate`, `/regex-match`, `/base-convert` |
| Fun (`swiss-army-api:fun`) | `GET /v1/fun/joke`, `POST /rock-paper-scissors` |

`swiss-army-api:*` grants every category.

## How it works

One shared deployment serves many customers. Onboarding is the same flow as
swiss-army-mcp's `/config`:

1. The page shows the redirect URI (`https://<host>/config/callback`) to
   register on the customer's admin Okta SPA.
2. They enter their Okta domain. If it's already registered they go straight
   to login; otherwise they enter their admin SPA `client_id`.
3. PKCE login against their Okta org auth server. **No SSM write happens
   before a successful login**, and a domain can't be re-registered under a
   different admin `client_id`.
4. They fill in their **custom authorization server** (issuer, audience,
   optional workload client IDs) and optionally enable scope enforcement.
   Saved at `/swiss-army-api/tenants/<their-domain>`.

Tokens hitting `/v1/*` are routed to the right tenant by their `iss` claim,
then checked for signature (JWKS at `{issuer}/v1/keys`), `aud`, `exp`, and —
if workload client IDs are set — `cid`. Unknown issuers get `401`. An issuer
can belong to only one tenant. Changes in `/config` apply on the next call.

The `/config` routes are excluded from `/openapi.json`, so the Bridge only
imports the 25 tools.

### Okta setup per customer

1. **Applications → Create App Integration → OIDC, SPA** for the admin login.
   Add the `/config/callback` redirect URI shown on the page.
2. **Security → API → Authorization Servers**: create (or reuse) a custom
   authorization server. Its issuer and audience go into `/config`.
3. **Scopes** tab (only if enabling enforcement): add the ten
   `swiss-army-api:<category>` scopes and `swiss-army-api:*`.
4. **Access Policies**: grant tokens to the client the Bridge uses.

## Configuration

Container env vars only; tenants configure themselves at `/config`.

| Variable | Required | Description |
| --- | --- | --- |
| `API_BASE_URL` | yes | Public URL. Builds the `/config/callback` redirect URI and the OpenAPI `servers` entry, so the Bridge calls the right host. |
| `API_TENANTS_PREFIX` | no | SSM prefix for per-tenant configs (default `/swiss-army-api/tenants/`). |
| `AWS_REGION` | no | Region for the SSM client (default `us-east-1`). |
| `API_AUTH_DISABLED` | no | `true` bypasses Okta and disables `/config`. **Local demos only.** |
| `HOST` / `PORT` / `LOG_LEVEL` | no | Defaults `0.0.0.0` / `8000` / `INFO`. |

Per-tenant runtime config (set via `/config`): **okta_domain**,
**admin_client_id**, **custom_issuer**, **audience**, **workload_client_ids**,
**enforce_scopes**.

Also served, unauthenticated: `/healthz` (ALB probe) and
`/.well-known/oauth-protected-resource` (RFC 9728: supported scopes; no
`authorization_servers`, since listing every tenant's would disclose them).
`401`s carry a `WWW-Authenticate` header pointing at it; `403`s name the
missing scope.

## Running

```bash
# From source, no auth
pip install -r requirements.txt
API_AUTH_DISABLED=true python app.py
curl -s -X POST localhost:8000/v1/math/add -H 'content-type: application/json' -d '{"a":2,"b":3}'
# => {"result":5.0}

# Tests (no AWS, network or Okta needed)
pip install httpx && python tests/test_api.py
```

With auth, once the tenant is set up at `/config`, get a token from its custom
auth server and call the API:

```bash
TOKEN=$(curl -s -X POST "$CUSTOM_ISSUER/v1/token" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials -d 'scope=swiss-army-api:*' | jq -r .access_token)
curl -s https://<your-host>/v1/fun/joke -H "Authorization: Bearer $TOKEN"
```

## Building the image

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t joewitt99/swiss-army-api:1.0.0 -t joewitt99/swiss-army-api:latest --push .
```

## Deploying to ECS

Use `deploy/terraform/` — see its README. Same shape as swiss-army-mcp's
module (ALB + Fargate + Route 53, SSM tenant store, optional demo VPC). Then
send customers to the `config_url` output and point the Bridge at
`openapi_url`.

## License

MIT.
