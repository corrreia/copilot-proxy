# Copilot Proxy

A single-operator Cloudflare Worker that exposes a GitHub Copilot subscription through OpenAI-compatible API endpoints.

## Architecture

- **Cloudflare Access** protects the web console. The Worker uses native trusted `ctx.access` when available and automatically verifies the signed Access assertion as a compatibility fallback—without configured team-domain or audience values.
- **GitHub device authorization** connects the GitHub account that owns the Copilot subscription.
- Exactly one SQLite-backed **Durable Object** (`USER_HUB` / `singleton`) stores encrypted provider credentials, hashed API keys, settings, OAuth state, metrics, and hibernating WebSockets.
- `/v1/*` bypasses Cloudflare Access but requires a generated `cpp_…` private key.
- Request and response bodies stream through the Worker, including SSE.
- The dashboard receives activity over WebSockets and does not poll. Each connection uses a one-time, 60-second ticket issued through the Access-protected dashboard API, so the WebSocket can traverse the `/v1/*` Access exception without becoming public.
- The console lists the complete live GitHub Copilot model catalog with provider, endpoint support, context limits, copyable model IDs, and ready-to-fill environment snippets.

D1 and KV are not required. Cloudflare Access identity is validated for each dashboard request but is never persisted.

## Supported endpoints

| Endpoint | Method | Description |
|---|---:|---|
| `/v1/models` | GET | Copilot model list |
| `/v1/chat/completions` | POST | OpenAI Chat Completions |
| `/v1/responses` | POST | OpenAI Responses API |
| `/v1/embeddings` | POST | OpenAI-compatible embeddings |
| `/v1/messages` | POST | Native Anthropic Messages passthrough |
| `/health` | GET | Health response |

## Development

```bash
npm install
cp .dev.vars.example .dev.vars
# Put a fresh value from `openssl rand -base64 32` in .dev.vars
npm run dev
```

Validation:

```bash
npm run check
```

## Deployment

See [WORKER_DEPLOYMENT.md](WORKER_DEPLOYMENT.md) for Cloudflare Access policy layout, Worker secret configuration, and client examples.

No GitHub personal access token or Copilot token is configured at deployment time. After deployment, sign into the console through Cloudflare Access and complete GitHub's device flow. Provider tokens are encrypted with AES-256-GCM before Durable Object storage. Generated API keys are displayed once and only their SHA-256 digests are retained.

## License

MIT
