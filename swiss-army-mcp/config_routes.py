"""Self-service tenant onboarding routes.

Flow:

  1. GET /config                       — render the SPA
  2. SPA: user enters Okta domain, clicks Next
  3. SPA: GET /config/lookup?domain=…
     - exists → skip ahead to PKCE using the stored admin client_id
     - new    → ask for admin client_id, then PKCE
  4. SPA redirects to Okta /oauth2/v1/authorize for PKCE
  5. GET /config/callback              — same SPA page
  6. SPA: exchanges code for access token
  7. SPA: POST /config/finalize        — server verifies the token against
     the proposed (or stored) admin_client_id, THEN writes/confirms the SSM
     entry. No SSM write happens before this point.
  8. SPA: GET/POST /config/workload    — fill in custom auth server details
"""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from okta_auth import (
    MultiTenantOktaVerifier,
    OktaJWTVerifier,
    build_admin_verifier,
    domain_from_issuer,
    peek_jwt_claims,
)
from scopes import TOOL_PREFIX_TO_SCOPE, WILDCARD_SCOPE
from tenant_config import Tenant, TenantStore

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------------

def _html(redirect_uri: str) -> str:
    scope_rows = "\n          ".join(
        f"<tr><td><code>{prefix}*</code></td><td><code>{scope}</code></td></tr>"
        for prefix, scope in TOOL_PREFIX_TO_SCOPE.items()
    )
    wildcard_scope = WILDCARD_SCOPE
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>swiss-army-mcp — configure</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 640px;
           margin: 0 auto; padding: 0 1.5rem 4rem; color: #1a1a1a; }}
    .demo-banner {{ background: #fff3cd; color: #6b4f00; border-bottom: 2px solid #f0c948;
                    padding: 0.75rem 1rem; text-align: center; font-weight: 600;
                    font-size: 0.9rem; margin: 0 -1.5rem 2rem; letter-spacing: 0.02em; }}
    h1 {{ font-size: 1.5rem; margin: 2.5rem 0 0.5rem; }}
    .subtle {{ color: #666; font-size: 0.9rem; margin-bottom: 2rem; }}
    label {{ display: block; margin: 1rem 0 0.25rem; font-weight: 500; font-size: 0.9rem; }}
    input {{ width: 100%; padding: 0.6rem 0.75rem; font: inherit;
             border: 1px solid #d0d0d0; border-radius: 6px; box-sizing: border-box; }}
    .hint {{ color: #777; font-size: 0.8rem; margin-top: 0.25rem; }}
    button {{ margin-top: 1.5rem; padding: 0.6rem 1.2rem; font: inherit;
              background: #0a66c2; color: white; border: none; border-radius: 6px;
              cursor: pointer; }}
    button.secondary {{ background: #555; }}
    button[disabled] {{ background: #999; cursor: not-allowed; }}
    .msg {{ margin-top: 1rem; padding: 0.75rem 1rem; border-radius: 6px; font-size: 0.9rem; }}
    .err {{ background: #fde7e7; color: #8a1f1f; }}
    .ok  {{ background: #e3f3e6; color: #1b5e25; }}
    .hidden {{ display: none; }}
    code {{ background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85em; }}
    .callout {{ background: #f6f8fa; border: 1px solid #d8dee4; padding: 0.75rem 1rem;
                border-radius: 6px; margin: 1rem 0; font-size: 0.9rem; }}
    .callout code {{ user-select: all; }}
    .redirect-box {{ display: flex; gap: 0.5rem; align-items: center; }}
    .redirect-box code {{ flex: 1; padding: 0.5rem 0.75rem; word-break: break-all; }}
    .copy-btn {{ margin: 0; padding: 0.4rem 0.8rem; font-size: 0.85em; }}
    details.scope-ref {{ margin: 0.5rem 0 0; font-size: 0.85rem; }}
    details.scope-ref summary {{ cursor: pointer; color: #0a66c2; user-select: none; }}
    details.scope-ref summary:hover {{ text-decoration: underline; }}
    details.scope-ref p {{ color: #555; margin: 0.6rem 0 0.4rem; }}
    details.scope-ref table {{ width: 100%; border-collapse: collapse; margin-top: 0.25rem; }}
    details.scope-ref th, details.scope-ref td {{ padding: 0.3rem 0.5rem; text-align: left; border-bottom: 1px solid #eee; }}
    details.scope-ref th {{ font-weight: 600; color: #444; background: #fafafa; }}
  </style>
</head>
<body>
  <div class="demo-banner">⚠ DEMO ENVIRONMENT — for demonstration use only. Do not configure with production credentials or data.</div>

  <h1>swiss-army-mcp configuration</h1>
  <div class="subtle">
    Self-service setup. Enter your Okta domain to begin.
  </div>

  <!-- Step 1: domain entry -->
  <form id="domain-form" class="hidden">
    <div class="callout">
      <div style="margin-bottom: 0.5rem;">Before you continue:  you need to add this redirect uri to your Bridge demo Admin UI application in Okta.</div>
      <div class="redirect-box">
        <code id="redirect-uri-display"></code>
        <button type="button" class="copy-btn secondary" id="copy-btn">Copy</button>
      </div>
    </div>

    <label for="domain">Okta domain</label>
    <input id="domain" type="text" required
           placeholder="your-tenant.okta.com" autocomplete="off">
    <div class="hint">No <code>https://</code>, no paths. Example:
      <code>your-tenant.oktapreview.com</code>.</div>

    <button id="next-btn" type="submit">Next</button>
    <div id="domain-msg" class="msg hidden"></div>
  </form>

  <!-- Step 2: client_id entry (new tenants only) -->
  <form id="client-form" class="hidden">
    <div class="callout">
      Domain <code id="client-domain-label"></code> is not yet registered.
      Enter your admin SPA <code>client_id</code> to bootstrap setup. The
      MCP server only persists this value after you successfully log in.
    </div>
    <label for="admin_client_id">Admin SPA client ID</label>
    <input id="admin_client_id" type="text" required placeholder="0oa..." autocomplete="off">
    <button id="login-btn" type="submit">Continue to Login</button>
    <button id="back-btn" class="secondary" type="button">Back</button>
    <div id="client-msg" class="msg hidden"></div>
  </form>

  <!-- Loading / in-flight indicator -->
  <div id="loading" class="hidden">Working…</div>

  <!-- Step 3: workload configuration -->
  <form id="workload-form" class="hidden">
    <div class="callout">Logged in as tenant <code id="logged-in-domain"></code>.</div>

    <label for="custom_issuer">Custom authorization server issuer</label>
    <input id="custom_issuer" type="url" required
           placeholder="https://your-tenant.okta.com/oauth2/aus...">
    <div class="hint">Full Okta custom auth server URL (not the org URL).</div>

    <label for="audience">Audience</label>
    <input id="audience" type="text" required placeholder="api://default">

    <label for="clients">Workload client IDs (comma-separated)</label>
    <input id="clients" type="text" placeholder="0oaXXXX...,0oaYYYY...">
    <div class="hint">Leave empty to allow any client ID. Matches <code>cid</code> claim.</div>

    <label style="display: flex; align-items: center; gap: 0.5rem; margin-top: 1.25rem;">
      <input id="enforce" type="checkbox" style="width: auto;">
      Restrict tool access by scope
    </label>
    <div class="hint" style="margin-top: 0.4rem;">
      <strong>Off (default):</strong> any valid token can call every tool.
      <strong>On:</strong> each tool requires a specific scope in the token's
      <code>scp</code> claim — calls without it are denied at invocation time.
      <code>tools/list</code> still returns every tool either way so the LLM
      can attempt unauthorized calls and observe the rejection.
    </div>
    <details class="scope-ref">
      <summary>Show scope reference</summary>
      <p>Define these scopes on your Okta custom authorization server and
         grant them to your workload client. The wildcard
         <code>{wildcard_scope}</code> covers every category.</p>
      <table>
        <thead><tr><th>Tool prefix</th><th>Required scope</th></tr></thead>
        <tbody>
          {scope_rows}
          <tr><td><code>(any)</code></td><td><code>{wildcard_scope}</code></td></tr>
        </tbody>
      </table>
    </details>

    <button id="save-btn" type="submit">Save configuration</button>
    <button id="signout-btn" class="secondary" type="button">Sign out</button>
    <div id="workload-msg" class="msg hidden"></div>
  </form>

<script>
const REDIRECT_URI = {redirect_uri!r};
const SS = sessionStorage;

function b64url(buf) {{
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}}
async function sha256(s) {{
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
}}
function randStr() {{
  const bytes = new Uint8Array(48);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}}
function show(id) {{ document.getElementById(id).classList.remove('hidden'); }}
function hide(id) {{ document.getElementById(id).classList.add('hidden'); }}
function only(id) {{
  for (const x of ['domain-form', 'client-form', 'loading', 'workload-form']) hide(x);
  show(id);
}}
function msg(id, text, kind) {{
  const m = document.getElementById(id);
  m.textContent = text;
  m.className = 'msg ' + kind;
}}

async function lookup(domain) {{
  const r = await fetch('/config/lookup?domain=' + encodeURIComponent(domain));
  if (!r.ok) throw new Error('lookup failed');
  return r.json();
}}

async function startPkce(domain, clientId) {{
  const verifier = randStr();
  const challenge = b64url(await sha256(verifier));
  const state = randStr();
  SS.setItem('pkce_verifier', verifier);
  SS.setItem('pkce_state', state);
  SS.setItem('domain', domain);
  SS.setItem('admin_client_id', clientId);
  const params = new URLSearchParams({{
    client_id: clientId,
    response_type: 'code',
    scope: 'openid',
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  }});
  window.location.href = 'https://' + domain + '/oauth2/v1/authorize?' + params.toString();
}}

async function finishLogin(code, state) {{
  if (state !== SS.getItem('pkce_state')) throw new Error('state mismatch');
  const domain = SS.getItem('domain');
  const clientId = SS.getItem('admin_client_id');
  if (!domain || !clientId) throw new Error('no pending login in this tab');
  const body = new URLSearchParams({{
    grant_type: 'authorization_code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code,
    code_verifier: SS.getItem('pkce_verifier'),
  }});
  const r = await fetch('https://' + domain + '/oauth2/v1/token', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
    body,
  }});
  if (!r.ok) throw new Error('token exchange failed: ' + await r.text());
  const tok = await r.json();
  SS.setItem('access_token', tok.access_token);
  SS.removeItem('pkce_verifier');
  SS.removeItem('pkce_state');
  window.history.replaceState({{}}, '', '/config');

  // Server-side: verify the token, and (if new) write the tenant to SSM.
  const fin = await fetch('/config/finalize', {{
    method: 'POST',
    headers: {{
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + tok.access_token,
    }},
    body: JSON.stringify({{ okta_domain: domain, admin_client_id: clientId }}),
  }});
  if (!fin.ok) throw new Error('finalize failed: ' + await fin.text());
}}

async function loadWorkload() {{
  const token = SS.getItem('access_token');
  const r = await fetch('/config/workload', {{
    headers: {{ Authorization: 'Bearer ' + token }},
  }});
  if (r.status === 401) {{ SS.removeItem('access_token'); throw new Error('401'); }}
  if (r.status === 204) return null;
  if (!r.ok) throw new Error('load failed: ' + await r.text());
  return r.json();
}}

async function saveWorkload(ev) {{
  ev.preventDefault();
  const btn = document.getElementById('save-btn');
  btn.disabled = true;
  msg('workload-msg', 'Saving…', 'ok');
  const body = {{
    custom_issuer: document.getElementById('custom_issuer').value.trim(),
    audience: document.getElementById('audience').value.trim(),
    workload_client_ids: document.getElementById('clients').value
      .split(',').map(s => s.trim()).filter(Boolean),
    enforce_scopes: document.getElementById('enforce').checked,
  }};
  try {{
    const r = await fetch('/config/workload', {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + SS.getItem('access_token'),
      }},
      body: JSON.stringify(body),
    }});
    if (!r.ok) throw new Error(await r.text());
    msg('workload-msg', 'Saved. Workload verifier reloaded.', 'ok');
  }} catch (e) {{
    msg('workload-msg', 'Save failed: ' + e.message, 'err');
  }} finally {{
    btn.disabled = false;
  }}
}}

function signOut() {{
  SS.clear();
  window.location.href = '/config';
}}

async function showWorkload() {{
  only('workload-form');
  document.getElementById('logged-in-domain').textContent = SS.getItem('domain');
  try {{
    const cfg = await loadWorkload();
    if (cfg) {{
      document.getElementById('custom_issuer').value = cfg.custom_issuer || '';
      document.getElementById('audience').value = cfg.audience || '';
      document.getElementById('clients').value = (cfg.workload_client_ids || []).join(',');
      document.getElementById('enforce').checked = !!cfg.enforce_scopes;
    }}
  }} catch (e) {{
    SS.clear();
    only('domain-form');
    msg('domain-msg', 'Session expired. Start over.', 'err');
  }}
}}

async function onDomainSubmit(ev) {{
  ev.preventDefault();
  const btn = document.getElementById('next-btn');
  btn.disabled = true;
  const domain = document.getElementById('domain').value.trim().toLowerCase();
  if (!domain) {{
    msg('domain-msg', 'Enter your Okta domain.', 'err');
    btn.disabled = false; return;
  }}
  try {{
    const r = await lookup(domain);
    if (r.exists) {{
      only('loading');
      await startPkce(domain, r.admin_client_id);  // navigates away
    }} else {{
      SS.setItem('pending_domain', domain);
      document.getElementById('client-domain-label').textContent = domain;
      only('client-form');
    }}
  }} catch (e) {{
    msg('domain-msg', 'Lookup failed: ' + e.message, 'err');
  }} finally {{
    btn.disabled = false;
  }}
}}

async function onClientSubmit(ev) {{
  ev.preventDefault();
  const btn = document.getElementById('login-btn');
  btn.disabled = true;
  const domain = SS.getItem('pending_domain');
  const clientId = document.getElementById('admin_client_id').value.trim();
  if (!domain || !clientId) {{
    msg('client-msg', 'client_id is required.', 'err');
    btn.disabled = false; return;
  }}
  only('loading');
  await startPkce(domain, clientId);  // navigates away
}}

function onBack() {{
  SS.removeItem('pending_domain');
  only('domain-form');
}}

async function main() {{
  document.getElementById('redirect-uri-display').textContent = REDIRECT_URI;
  document.getElementById('copy-btn').onclick = () => {{
    navigator.clipboard.writeText(REDIRECT_URI);
    document.getElementById('copy-btn').textContent = 'Copied';
    setTimeout(() => document.getElementById('copy-btn').textContent = 'Copy', 1500);
  }};
  document.getElementById('domain-form').onsubmit = onDomainSubmit;
  document.getElementById('client-form').onsubmit = onClientSubmit;
  document.getElementById('back-btn').onclick = onBack;
  document.getElementById('workload-form').onsubmit = saveWorkload;
  document.getElementById('signout-btn').onclick = signOut;

  const url = new URL(window.location.href);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (code) {{
    only('loading');
    try {{
      await finishLogin(code, state);
      await showWorkload();
      return;
    }} catch (e) {{
      SS.clear();
      only('domain-form');
      msg('domain-msg', 'Login failed: ' + e.message, 'err');
      return;
    }}
  }}
  if (SS.getItem('access_token')) {{
    await showWorkload();
  }} else {{
    only('domain-form');
  }}
}}
main();
</script>
</body>
</html>"""


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return None
    return auth[7:].strip()


def _redirect_uri(request: Request, public_base_url: str | None) -> str:
    if public_base_url:
        return public_base_url.rstrip("/") + "/config/callback"
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.url.netloc
    return f"{scheme}://{host}/config/callback"


# ----------------------------------------------------------------------------
# Route registration
# ----------------------------------------------------------------------------

def register_config_routes(
    mcp,
    *,
    store: TenantStore,
    workload_verifier: MultiTenantOktaVerifier,
    public_base_url: str | None,
) -> None:
    """Register /config* routes on the FastMCP HTTP app."""

    @mcp.custom_route("/config", methods=["GET"])
    async def config_page(request: Request) -> Response:
        return HTMLResponse(_html(_redirect_uri(request, public_base_url)))

    @mcp.custom_route("/config/callback", methods=["GET"])
    async def config_callback(request: Request) -> Response:
        return HTMLResponse(_html(_redirect_uri(request, public_base_url)))

    @mcp.custom_route("/config/lookup", methods=["GET"])
    async def config_lookup(request: Request) -> Response:
        domain = (request.query_params.get("domain") or "").strip().lower()
        if not domain:
            return JSONResponse({"error": "missing domain"}, status_code=400)
        t = store.get(domain)
        if t is None:
            return JSONResponse({"exists": False, "domain": domain})
        return JSONResponse({
            "exists": True,
            "domain": t.okta_domain,
            "admin_client_id": t.admin_client_id,
            "has_workload_config": t.has_workload_config,
        })

    @mcp.custom_route("/config/finalize", methods=["POST"])
    async def config_finalize(request: Request) -> Response:
        """Verify the freshly-acquired admin token; on success, create or
        confirm the tenant's SSM entry. Only path that writes admin_client_id
        to SSM — no pre-login writes exist."""
        token = _bearer_token(request)
        if not token:
            return JSONResponse({"error": "missing bearer token"}, status_code=401)
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        domain = (payload.get("okta_domain") or "").strip().lower()
        client_id = (payload.get("admin_client_id") or "").strip()
        if not domain or not client_id:
            return JSONResponse(
                {"error": "okta_domain and admin_client_id required"},
                status_code=400,
            )

        # Sanity: token's iss must match the claimed domain (org auth server).
        peek = peek_jwt_claims(token)
        token_iss_domain = domain_from_issuer(peek.get("iss") or "") if peek else None
        if token_iss_domain != domain:
            return JSONResponse(
                {"error": f"token iss does not match domain {domain}"},
                status_code=401,
            )

        # Verify the bearer against the *proposed* admin_client_id.
        candidate = Tenant(okta_domain=domain, admin_client_id=client_id)
        try:
            verifier: OktaJWTVerifier = build_admin_verifier(candidate)
        except Exception as e:
            return JSONResponse({"error": f"verifier build failed: {e}"}, status_code=400)
        access = await verifier.verify_token(token)
        if access is None:
            return JSONResponse({"error": "token verification failed"}, status_code=401)

        # If a tenant already exists for this domain, the admin_client_id
        # in SSM is the source of truth — refuse to silently rebrand.
        existing = store.get(domain)
        if existing and existing.admin_client_id != client_id:
            return JSONResponse(
                {"error": "domain already registered with a different admin_client_id"},
                status_code=409,
            )

        if existing is None:
            try:
                store.save(candidate)
            except Exception as e:
                logger.exception("SSM save failed")
                return JSONResponse({"error": f"persist failed: {e}"}, status_code=500)
            logger.info("Bootstrapped new tenant %s", domain)

        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/config/workload", methods=["GET"])
    async def workload_get(request: Request) -> Response:
        token = _bearer_token(request)
        tenant = await _resolve_admin(token, store)
        if tenant is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not tenant.has_workload_config:
            return Response(status_code=204)
        return JSONResponse({
            "custom_issuer": tenant.custom_issuer,
            "audience": tenant.audience,
            "workload_client_ids": tenant.workload_client_ids,
            "enforce_scopes": tenant.enforce_scopes,
        })

    @mcp.custom_route("/config/workload", methods=["POST"])
    async def workload_post(request: Request) -> Response:
        token = _bearer_token(request)
        tenant = await _resolve_admin(token, store)
        if tenant is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        custom_issuer = (payload.get("custom_issuer") or "").strip()
        audience = (payload.get("audience") or "").strip()
        client_ids_raw = payload.get("workload_client_ids") or []
        if isinstance(client_ids_raw, str):
            client_ids_raw = [c.strip() for c in client_ids_raw.split(",")]
        client_ids = [c for c in client_ids_raw if c]
        if not custom_issuer or not audience:
            return JSONResponse(
                {"error": "custom_issuer and audience are required"}, status_code=400,
            )
        if not custom_issuer.startswith("https://"):
            return JSONResponse(
                {"error": "custom_issuer must be an https URL"}, status_code=400,
            )

        workload_verifier.invalidate(tenant.custom_issuer)
        updated = Tenant(
            okta_domain=tenant.okta_domain,
            admin_client_id=tenant.admin_client_id,
            custom_issuer=custom_issuer,
            audience=audience,
            workload_client_ids=client_ids,
            enforce_scopes=bool(payload.get("enforce_scopes", False)),
        )
        try:
            store.save(updated)
        except Exception as e:
            logger.exception("SSM save failed")
            return JSONResponse({"error": f"persist failed: {e}"}, status_code=500)
        workload_verifier.invalidate(custom_issuer)
        return JSONResponse({"status": "ok"})


async def _resolve_admin(token: str | None, store: TenantStore) -> Tenant | None:
    """Verify an admin bearer token and return the tenant it belongs to."""
    if not token:
        return None
    peek = peek_jwt_claims(token)
    if not peek:
        return None
    domain = domain_from_issuer(peek.get("iss") or "")
    if not domain:
        return None
    tenant = store.get(domain)
    if tenant is None:
        return None
    try:
        verifier = build_admin_verifier(tenant)
    except Exception:
        logger.exception("Failed to build admin verifier for %s", domain)
        return None
    access = await verifier.verify_token(token)
    if access is None:
        return None
    return tenant
