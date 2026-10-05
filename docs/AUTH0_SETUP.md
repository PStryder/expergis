# Expergis: Google sign-in through Auth0

The source implementation is ready for isolated testing. Real Auth0 login,
ChatGPT linking, HTTPS delivery and the locked-PC test are **pending setup**.
This source implementation creates no tenant, application, credentials, grants,
tunnel or service. An operator-run synthetic tunnel metadata test does not
verify the production OAuth or event-delivery flow.

Google authenticates Peter to Auth0. Auth0 issues a separate access token for
the Expergis API. Expergis verifies that token locally using Auth0's public
signing keys. Google ID/access tokens and tokens for ChatGPT or another API are
not accepted as substitutes. Expergis never receives a Google password or OAuth
client secret. [Auth0 token validation](https://auth0.com/docs/secure/tokens/access-tokens/validate-access-tokens)

## What Peter needs to supply at setup

* Sign in to the chosen Auth0 tenant and Google developer account in the browser.
* Choose the Auth0 issuer domain and exact canonical HTTPS resource identifier.
  For a tunnel, copy the resource observed in ChatGPT discovery; do not infer it
  from the local MCP URL or tunnel transport URL. It is also the API audience.
* Approve the dedicated Expergis API, OAuth client and Google login connection.
  Record the client ID and Peter's verified Auth0 user ID (`sub`), not his email.
* Select one existing private local data directory and one harmless demo folder.
* Separately approve the transport, runtime transition from any legacy watcher,
  ChatGPT connection and a `demo-file` subscription in the intended dot.

These are setup decisions, not missing source dependencies. Do not paste tokens,
passwords or secrets into chat or put them in Git. The issuer, resource, client
ID and subject are configuration identifiers; treat the local policy as private.

## Provider setup, after approval

1. In the chosen Auth0 tenant, register an Expergis API with the exact canonical
   HTTPS resource identifier, RS256 signing and a single permission `expergis`.
   Auth0 does not fetch this identifier; it need not be publicly reachable.
   Preserve every character, including the absence/presence of a trailing slash.
   Auth0 API identifiers cannot be edited after creation.
   [Register APIs](https://auth0.com/docs/get-started/auth0-overview/set-up-apis)
   Use short access-token lifetimes (for example one hour). Do not select the
   Auth0 Management API or enable unrelated downstream API grants.
   [Auth0 APIs](https://auth0.com/docs/get-started/apis)
2. Under tenant Settings > Advanced, enable **Resource Parameter Compatibility
   Profile** and **Include Issuer in Authorization Responses**. These allow the
   MCP resource parameter to select this API and protect OAuth response issuer
   handling. Review these tenant-wide choices during setup if other apps exist.
   [Auth0 compatibility profile](https://auth0.com/ai/docs/mcp/guides/resource-param-compatibility-profile)
3. Create a dedicated predefined OAuth client for this Expergis connection using
   Auth0's manual registration flow. Configure authorization code with S256 PKCE,
   the token endpoint authentication method supported by the ChatGPT connection,
   and only the exact redirect URI displayed by the client setup. Copy its ID
   into `client_ids`. Any client secret belongs only in the provider/client setup,
   never Expergis. Enable only the Expergis API grant. Refresh-token access is a
   separate approval if continuous access requires it. The verifier also accepts
   an explicitly allowlisted CIMD client ID if that registration method is chosen;
   it does not register clients itself or enable open dynamic registration.
   [Auth0 manual registration](https://auth0.com/ai/docs/mcp/guides/registering-your-mcp-client-application/manual-client-registration),
   [CIMD alternative](https://auth0.com/ai/docs/mcp/guides/registering-your-mcp-client-application/manual-cimd-registration)
4. Configure Google as the login connection for this client. Google OAuth setup
   uses the Auth0 domain as origin and `https://YOUR_AUTH0_DOMAIN/login/callback`
   as redirect URI. Enter Google's credentials directly in Auth0's social
   connection settings; select only basic login/profile permissions needed for
   authentication. Follow the provider guide to test the connection. Use Peter's
   resulting Auth0 user ID for the owner allowlist; do not infer it from email.
   [Auth0 Google setup](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/google)
5. Before linking, check the issuer's public discovery document advertises
   S256, the configured client authentication method and correct endpoints.
   Confirm a token obtained for the Expergis resource has that audience and
   `expergis` scope. Inspect locally without logging or sharing the token.
   [OpenAI authentication contract](https://developers.openai.com/plugins/build/auth)

The Google login redirect and ChatGPT's OAuth redirect are different and must
not be interchanged. Issuer metadata and login pages are hosted by Auth0;
Expergis only serves protected-resource metadata. Secure MCP Tunnel transports
MCP traffic but does not replace end-user OAuth or automatically tunnel the
authorization server. [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)

## Local configuration (not yet deployed)

Start with the event configuration in [MCP_EVENTS.md](MCP_EVENTS.md). Add this
top-level object to a separate private `expergis-auth.local.json`; replace all
placeholders after provider setup. Keep the live stdio configuration unchanged.

```json
"auth0": {
  "issuer": "https://YOUR_TENANT.auth0.com/",
  "resource": "https://YOUR_EXPERGIS_HOST/mcp",
  "client_ids": ["YOUR_DEDICATED_CLIENT_ID"],
  "policy_file": "C:/Users/YOU/AppData/Local/Expergis/expergis-policy.local.json"
}
```

The issuer must be its exact lowercase HTTPS origin with trailing `/`. Custom
Auth0 domains are supported. The HTTPS resource may have a path other than
`/mcp`; the configured string must survive URL parsing without normalization.
It is matched exactly against JWT `aud`, never fetched or used to locate JWKS.
No query, credentials, fragment, nonstandard port or local IP is accepted for
issuer/resource. JWKS fetching remains pinned to the issuer with public-address
DNS checks, no redirects and no token-supplied key URLs. At most four explicitly
selected clients are allowed.

### Tunnel discovery versus token audience

For an explicitly approved loopback HTTP tunnel deployment, optionally add
`"tunnel_local_resource": "http://127.0.0.1:PORT/mcp"` to `auth0`, replacing PORT
with the actual approved local listener port (1–65535). This is the only accepted
form: no other host, scheme, path, credentials or query. It does not start a
listener or configure the tunnel. Omit it for the existing direct-HTTPS behavior.

Keep `auth0.resource` set to the exact **rewritten resource observed by ChatGPT**.
The local metadata route stays `/.well-known/oauth-protected-resource/mcp`;
its resource and the `/mcp` authentication challenge advertise the configured
loopback URL. The tunnel rewrites these discovery values upstream. Expergis
does not add a tunnel prefix, derive a gateway URL, or advertise that gateway
as a local route. Both the JWT verifier and SDK authentication retain the
canonical audience; a token for the loopback URL or another tunnel is rejected.
[Tunnel discovery rewriting](https://github.com/openai/tunnel-client/blob/v0.0.15/docs/configuration.md#oauth-protected-mcp-notes)

The observed gateway resource is an opaque identifier, not an issuer or an
endpoint to browse. Its stability is only established for the observed tunnel
and environment; recheck discovery if either changes. An observation in the
synthetic connection form does not verify an Auth0 grant, token propagation,
production metadata rewriting, event callback, or locked-PC dot receipt. These
remain pending an authorized end-to-end test. The tunnel's discovery-origin
allowlist must contain only the approved local server and actual Auth0 issuer;
this implementation does not change that configuration.

Create the policy in the existing private directory, initially disabled:

```json
{
  "owner": "google-oauth2|VERIFIED_AUTH0_USER_ID",
  "enabled": false,
  "watcher_ids": ["demo-file"],
  "tokens_valid_after": 0
}
```

Set `mcp_events.owner` to exactly the same verified subject. Choose concrete
`allowed_roots` and `allowed_process_names` in the event config; policy watcher
IDs do not authorize arbitrary paths or processes. The bounded MVP policy
permits up to 32 IDs containing letters, digits, underscores and hyphens.
Enable the policy only during the approved live setup.

In a **separate** Python 3.11 environment, install `.[events]`; this pins MCP
2.3.0 and adds PyJWT with cryptography. Do not update the live venv.

```powershell
.\.venv-events\Scripts\python -m pip install -e ".[events]" pytest pytest-asyncio
.\.venv-events\Scripts\python -m expergis.auth0 C:\PRIVATE\expergis-auth.local.json
.\.venv-events\Scripts\python -m pytest tests -q -p no:cacheprovider
```

The preflight validates auth fields and policy only. It prints no configuration
values, starts no watchers/listeners, creates no database and makes no network
requests. It does not verify provider grants, issuer availability or filesystem
permissions. An approved deployment wrapper loads the JSON and calls:

```python
from expergis.auth0 import create_auth0_app, read_json
app = create_auth0_app(read_json(private_config_path))
```

This returns the ASGI application without binding a port. Its runtime lifespan
starts the configured watchers, so do not start it until the single-runtime
transition is approved. No listener/service launcher is installed by this work.
For the usual direct `/mcp` resource or explicit tunnel local binding, the SDK
publishes `/.well-known/oauth-protected-resource/mcp` and a matching HTTP 401
`WWW-Authenticate` challenge. Other direct resource paths use the SDK
resource-path metadata route. Successful modern `tools/list` responses
declare OAuth `securitySchemes`; all four tools and event methods remain protected.

## Revocation and operational limits

Atomically replace the policy file to avoid partial reads (write a temporary
file in the same private directory, then replace). Missing, malformed, oversized
or disabled policies deny access. Setting `enabled` false denies new requests
and queued deliveries; removing a watcher ID revokes that watcher. The worker
removes revoked subscriptions when it encounters their queued work. An already
in-flight request/delivery can finish. Monitoring itself continues until stopped;
revocation prevents access/delivery, not local observation.

`tokens_valid_after` is a Unix-seconds cutoff: tokens issued at or before it are
rejected. It does not cancel already established subscriptions; use `enabled`
false, watcher removal or unsubscribe for that. There is no Auth0 Management API
poller: blocking a user or revoking refresh tokens at Auth0 alone does not
immediately invalidate issued JWTs or subscriptions. Apply the local policy too.

JWKS keys are cached for five minutes, with one refresh attempt per 30 seconds
on unknown keys or failure. New rotated keys can wait up to that cooldown.
Expired caches fail closed if discovery fails; previously cached keys can remain
usable until their five-minute expiry. The issuer fetch uses verified TLS,
public-address DNS validation, no redirects/proxies/cookies, a five-second timeout
and 64 KiB response cap. JWTs are capped at 16 KiB; only RS256 is accepted.
No bearer token, private context or remote error body is logged by this adapter.
[Auth0 JWKS guidance](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)

Synthetic tests cover signed tokens, altered issuer/audience/client/owner/scopes,
expiry and future dates, algorithm confusion, invalid signatures, token-supplied
key URLs, bounded discovery, rotation/failure/cache behavior, local revocation,
queued delivery denial, protected metadata and HTTP challenges. They cannot prove
the future tenant/client configuration or real ChatGPT interoperability.

After authorized setup, use the one-file locked-PC test in
[MCP_EVENTS.md](MCP_EVENTS.md#first-harmless-real-event-in-this-dot-pending).
The PC must stay awake and online; queued observations can replay subject to
subscription expiry and retention. Actual dot receipt remains a separate check
from a successful webhook acknowledgement.
