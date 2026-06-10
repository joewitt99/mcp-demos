# swiss-army-mcp

A demo [Model Context Protocol](https://modelcontextprotocol.io) server exposing **100 tools across 10 categories** — text, math, encoding, hashing, date/time, random, color, units, data, and fun. Useful for exercising MCP clients against a non-trivial tool surface, including paginated `tools/list` and Okta-backed OAuth.

- **Transport:** Streamable HTTP (stateful — issues `Mcp-Session-Id` on `initialize`)
- **Auth:** Okta JWT, multi-tenant — customers self-onboard at `/config`. Per-tenant settings persist to AWS SSM.
- **Image:** [`joewitt99/swiss-army-mcp`](https://hub.docker.com/r/joewitt99/swiss-army-mcp) — `linux/amd64`, `linux/arm64`

## How it works

One shared deployment serves many customers. Each customer self-onboards
through a public `/config` page (clearly banner'd as a demo environment):

1. The page displays the redirect URI to register on their admin Okta SPA.
2. They enter their Okta domain (e.g. `joe-wf-oie-demos.oktapreview.com`)
   and click **Next**.
3. If the domain is already registered, they're sent straight to login.
   Otherwise they enter their admin SPA `client_id` and click
   **Continue to Login**.
4. PKCE round-trip against the customer's Okta org auth server.
5. On successful login the server verifies the token against the proposed
   `client_id` and writes the tenant to SSM. **No SSM write happens before
   a successful login** — anyone can attempt onboarding but only verified
   token holders can claim a domain.
6. The customer fills in their **custom authorization server** (issuer,
   audience, workload client IDs) and optionally enables scope enforcement.
   Saved at `/swiss-army-mcp/tenants/<their-domain>`.

Workload tokens hitting `/mcp/*` are routed to the right tenant's verifier by
inspecting the JWT's `iss` claim. Unknown issuers are rejected.

## Quick start (local — no auth)

```bash
docker run --rm -p 8000:8000 \
  -e MCP_AUTH_DISABLED=true \
  joewitt99/swiss-army-mcp:latest
```

The server is reachable at `http://localhost:8000/mcp/`. The `/config` UI is
disabled in this mode.

## Deploying

Use the Terraform module in `deploy/terraform/`. It runs from an EC2 with an
IAM instance profile (no AWS keys), pulls the public image (no build/push),
and provisions ALB + Fargate + Route 53. The task role gets `ssm:GetParameter`,
`PutParameter`, and `GetParametersByPath` on the tenants prefix. See
`deploy/terraform/README.md` for the apply/destroy workflow.

After deploy, point each customer at `https://<your-host>/config`.

## Configuration

All configuration is via environment variables (just on the container; tenants
configure themselves via `/config`).

| Variable | Required | Description |
| --- | --- | --- |
| `MCP_BASE_URL` | yes | Public URL of this server. Used to build the `/config/callback` redirect URI. |
| `MCP_TENANTS_PREFIX` | no | SSM prefix for per-tenant configs (default `/swiss-army-mcp/tenants/`). |
| `AWS_REGION` | no | Region for the SSM client (default `us-east-1`). |
| `MCP_AUTH_DISABLED` | no | Set to `true` to bypass Okta entirely. **Local demos only.** |
| `MCP_LIST_PAGE_SIZE` | no | Page size for `tools/list` etc. (default `30`). |
| `HOST` | no | Bind address (default `0.0.0.0`). |
| `PORT` | no | Listen port (default `8000`). |
| `LOG_LEVEL` | no | Python logging level (default `INFO`). |

Per-tenant runtime config (set via `/config`): **okta_domain**,
**admin_client_id**, **custom_issuer**, **audience**, **workload_client_ids**,
**enforce_scopes**.

## The 100 tools

Tools are namespaced by category prefix. `tools/list` is paginated — clients must follow `nextCursor` to retrieve the full inventory.

| Category | Prefix | Examples |
| --- | --- | --- |
| Text | `text_` | `text_uppercase`, `text_slugify`, `text_truncate` |
| Math | `math_` | `math_add`, `math_factorial`, `math_gcd` |
| Encoding | `encode_` | `encode_base64`, `encode_url`, `encode_rot13` |
| Hashing | `hash_` | `hash_sha256`, `hash_hmac_sha256`, `hash_password_strength` |
| Date/Time | `time_` | `time_current_iso`, `time_days_between`, `time_unix_timestamp` |
| Random | `rand_` | `rand_uuid`, `rand_password`, `rand_dice` |
| Color | `color_` | `color_hex_to_rgb`, `color_blend`, `color_contrast_ratio` |
| Units | `unit_` | `unit_celsius_to_fahrenheit`, `unit_miles_to_km` |
| Data | `data_` | `data_json_pretty`, `data_csv_to_json`, `data_regex_match` |
| Fun | `fun_` | `fun_joke`, `fun_rock_paper_scissors`, `fun_pig_latin` |

10 tools per category × 10 categories = 100.

## Per-category scopes

When a tenant ticks **Enforce per-category scopes** in `/config`, each tool
call from that tenant's workload tokens requires the matching scope. Tools the
caller is not authorized for are also filtered out of `tools/list`.

| Category | Required scope |
| --- | --- |
| Text | `swiss-army-mcp:text` |
| Math | `swiss-army-mcp:math` |
| Encoding | `swiss-army-mcp:encoding` |
| Hashing | `swiss-army-mcp:hashing` |
| Date/Time | `swiss-army-mcp:datetime` |
| Random | `swiss-army-mcp:random` |
| Color | `swiss-army-mcp:color` |
| Units | `swiss-army-mcp:units` |
| Data | `swiss-army-mcp:data` |
| Fun | `swiss-army-mcp:fun` |
| (any) | `swiss-army-mcp:*` (wildcard) |

Each customer defines these scopes in their Okta custom auth server's
**Scopes** tab and adds them to their workload application's allowed scopes
before flipping the toggle on. The toggle is read on every call, so changes
via `/config` take effect without a restart.

## Wiring up a client

### Claude Desktop / Claude.ai

Add an HTTP MCP server pointing at `http://localhost:8000/mcp/` (or your deployed URL). Supply a bearer token if Okta auth is enabled.

### `curl` smoke test

```bash
# Initialize a session (no-auth mode)
curl -i -X POST http://localhost:8000/mcp/ \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

Capture the `Mcp-Session-Id` response header and send it as a request header on subsequent calls.

## Running from source

```bash
pip install -r requirements.txt
MCP_AUTH_DISABLED=true python server.py
```

## Image tags

- `latest` — tracks the most recent release. Convenient for trying it out, but **pin to a version tag in any persistent demo setup** so a future image rebuild doesn't surprise you.
- `X.Y.Z` — immutable semver release.

## License

MIT.
