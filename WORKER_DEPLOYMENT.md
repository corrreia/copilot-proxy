# Cloudflare Worker deployment

The Worker edition runs the proxy, dashboard, authentication, encrypted storage, and real-time activity feed entirely on Cloudflare:

- **Cloudflare Access** signs the operator into the dashboard. The Worker uses trusted native `ctx.access` when available and automatically verifies the signed Access assertion as a compatibility fallback.
- **GitHub's device authorization flow** connects the GitHub account with the Copilot subscription. No GitHub client secret is required.
- One SQLite-backed **Durable Object**, named `singleton`, stores encrypted GitHub/Copilot tokens, hashed private API keys, settings, OAuth state, and recent request metadata.
- The same Durable Object serializes Copilot token refresh and delivers dashboard events over hibernating WebSockets. The UI does not poll for activity.
- **Workers Static Assets** serves the console only after native Access identity or a cryptographically verified Access assertion confirms authentication.

There is no D1 or KV dependency. This is intentionally a single-operator application with one Durable Object instance and no persisted Cloudflare Access identity.

> This uses GitHub Copilot's API with your subscription. Deploy it for an account you control and follow GitHub's applicable terms. Do not expose a bypassed dashboard or share generated API keys.

## Prerequisites

- Node.js 20 or newer
- A Cloudflare account with Workers, Durable Objects, and Zero Trust Access enabled
- A hostname on Cloudflare (recommended) or the deployed `workers.dev` hostname
- A GitHub account with an active Copilot subscription

Authenticate Wrangler and install dependencies:

```bash
npx wrangler login
npm install
```

## 1. Deploy once to obtain a hostname

```bash
npm run deploy
```

Wrangler prints a `*.workers.dev` URL. You may instead add a Worker custom domain in `wrangler.jsonc` or in **Workers & Pages → copilot-proxy → Settings → Domains & Routes**.

The `new_sqlite_classes` migration in `wrangler.jsonc` provisions the SQLite-backed Durable Object namespace. The singleton object's schema initializes automatically on first use.

Until Access is configured, the dashboard returns `401 Access required` while `/v1/*` continues to use private API-key authentication.

## 2. Put Cloudflare Access in front of the UI

1. Open **Workers & Pages → your Worker → Access**.
2. Choose **Protect this Worker behind Access** and protect **All traffic**.
3. Add an **Allow** policy for the one operator allowed to use the console.
4. Select your preferred identity provider. Cloudflare's **One-time PIN** provider provides a Cloudflare-hosted email sign-in flow; any configured Access identity provider also works.
5. In **Zero Trust → Access controls → Applications**, create a second, more-specific self-hosted application for `your-worker-host/v1/*` with a **Bypass / Everyone** policy. This makes the OpenAI wire endpoint reachable while the Worker still requires a generated private API key.
6. Optionally create the same bypass for `your-worker-host/health` if external uptime checks need it.

Do **not** bypass `/api/*`, `/app.js`, `/styles.css`, or the dashboard root. The Worker does not save the Access subject or email. There is no configured team domain or audience tag: if native `ctx.access` is unavailable, the Worker extracts the issuer from the signed assertion, restricts it to `https://*.cloudflareaccess.com`, verifies the RS256 signature against that issuer's JWKS, and requires a non-empty audience claim. Renaming or recreating the Access application therefore does not require a Worker configuration change.

The API aliases without `/v1` are retained for compatibility, but a catch-all Access application protects them. Use `/v1` as the public client base URL.

## 3. Add the encryption secret

Generate a fresh 32-byte AES key and write it directly to the Worker secret prompt:

```bash
openssl rand -base64 32 | npx wrangler secret put TOKEN_ENCRYPTION_KEY
```

Never put this value in `wrangler.jsonc`, source control, logs, or a client. Back it up in a password manager: losing it makes the encrypted GitHub tokens unreadable. Rotating it requires reconnecting GitHub.

## 4. Deploy the configured Worker

```bash
npm run check
npm run deploy
```

Visit the Worker hostname. Cloudflare Access prompts you to sign in, then the console walks through GitHub device authorization.

## 5. Connect GitHub and create a key

1. Choose **Connect GitHub**.
2. Open GitHub and enter the displayed one-time code.
3. After the account is connected, choose **Create API key**.
4. Copy the `cpp_…` key immediately. Only its SHA-256 digest is stored, so it cannot be displayed again.

The proxy defaults to an individual Copilot account, matching the original project's default behavior. The account-type control is only needed for Copilot Business or Enterprise because those plans use different upstream API hosts.

The GitHub OAuth device code and provider tokens are encrypted with AES-256-GCM before Durable Object storage. Disconnecting GitHub deletes local token ciphertext; revoke the OAuth grant in GitHub settings as well if you need provider-side revocation.

## Storage model

All persistent application data lives in the private SQLite database attached to the one `singleton` Durable Object:

| Data | Storage |
|---|---|
| Raw generated `cpp_…` key | Shown once; never stored |
| API-key SHA-256 digest and metadata | Durable Object SQLite |
| GitHub device-flow state | AES-256-GCM encrypted in Durable Object SQLite |
| GitHub and Copilot tokens | AES-256-GCM encrypted in Durable Object SQLite |
| Settings and recent request metrics | Durable Object SQLite |
| Master encryption key | Cloudflare Worker Secret |
| Active WebSockets and hot Copilot token | Singleton Durable Object runtime |

Because every API request uses the same object, key revocation is strongly consistent. The application intentionally does not support cross-user partitioning or global administration.

## OpenAI-compatible usage

Set the base URL to the value shown in the console and use the generated key as a Bearer token:

```bash
curl https://copilot.example.com/v1/chat/completions \
  -H "Authorization: Bearer cpp_REPLACE_ME" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5-mini",
    "messages": [{"role": "user", "content": "Say hello"}],
    "stream": true
  }'
```

OpenAI SDK:

```python
from openai import OpenAI

client = OpenAI(
    api_key="cpp_REPLACE_ME",
    base_url="https://copilot.example.com/v1",
)

response = client.chat.completions.create(
    model="gpt-5-mini",
    messages=[{"role": "user", "content": "Say hello"}],
)
print(response.choices[0].message.content)
```

### Worker endpoint coverage

| Endpoint | Method | Upstream behavior |
|---|---:|---|
| `/v1/models` | GET | Copilot models passthrough |
| `/v1/chat/completions` | POST | OpenAI Chat Completions passthrough, including SSE |
| `/v1/responses` | POST | OpenAI Responses passthrough, including SSE |
| `/v1/embeddings` | POST | Embeddings passthrough |
| `/v1/messages` | POST | Native Anthropic Messages passthrough |
| `/health` | GET | Worker health response |

Request and response bodies are streamed. The Worker does not buffer large completions or SSE streams. It inspects the model only for small requests with an explicit `Content-Length` and limits declared request bodies to 100 MB.

## Local development

```bash
cp .dev.vars.example .dev.vars
# Replace TOKEN_ENCRYPTION_KEY with: openssl rand -base64 32
npm run dev
```

`LOCAL_DEV_EMAIL` is honored only when the request hostname is `localhost` or `127.0.0.1`; it cannot bypass Access on a deployed hostname. Local Durable Object SQLite state is managed automatically by Wrangler.

## Operations

```bash
npm run check                 # generated types, TypeScript, tests, deployment dry run
npx wrangler tail             # structured Worker logs
npx wrangler versions list    # list deployable/rollback versions
```

The console loads its initial state once. For each live connection it obtains a one-time, 60-second socket ticket from the Access-protected `/api/socket-ticket` endpoint, then opens the hibernating Durable Object WebSocket at `/v1/dashboard/events`. The ticket is sent as a WebSocket subprotocol, consumed on first use, and allows the connection through the `/v1/*` Access exception without exposing activity publicly. Reconnects obtain a fresh ticket and use exponential backoff; the dashboard never polls for activity.
