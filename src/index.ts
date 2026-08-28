import { AccessError, requireAccessUser, requireSameOrigin, type AccessUser } from "./access";
import { encryptSecret } from "./crypto";
import {
  copilotBaseUrl,
  copilotHeaders,
  fetchCopilotToken,
  fetchCopilotUsage,
  fetchGitHubUser,
  pollDeviceCode,
  requestDeviceCode,
} from "./github";
import {
  DASHBOARD_SOCKET_PROTOCOL_PREFIX,
  SINGLETON_HUB_NAME,
  UserHub,
  type AccountType,
  type CopilotCredential,
  type RequestMetric,
} from "./user-hub";

export { UserHub };

const PROXY_ROUTES = new Map<string, { upstream: string; methods: readonly string[] }>([
  ["/models", { upstream: "/models", methods: ["GET"] }],
  ["/v1/models", { upstream: "/models", methods: ["GET"] }],
  ["/chat/completions", { upstream: "/chat/completions", methods: ["POST"] }],
  ["/v1/chat/completions", { upstream: "/chat/completions", methods: ["POST"] }],
  ["/responses", { upstream: "/responses", methods: ["POST"] }],
  ["/v1/responses", { upstream: "/responses", methods: ["POST"] }],
  ["/embeddings", { upstream: "/embeddings", methods: ["POST"] }],
  ["/v1/embeddings", { upstream: "/embeddings", methods: ["POST"] }],
  ["/v1/messages", { upstream: "/v1/messages", methods: ["POST"] }],
]);

export default {
  async fetch(request: Request, env: Cloudflare.Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/health") {
        return json({ status: "ok", service: "copilot-proxy" });
      }

      if (url.pathname === "/v1/dashboard/events") {
        return await handleDashboardSocket(request, env);
      }

      const proxyRoute = PROXY_ROUTES.get(url.pathname);
      if (proxyRoute) {
        if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders() });
        if (!proxyRoute.methods.includes(request.method)) {
          return openAIError("Method not allowed", 405, { Allow: proxyRoute.methods.join(", ") });
        }
        return await proxyToCopilot(request, env, ctx, proxyRoute.upstream);
      }

      const user = await requireAccessUser(request, env, ctx.access);
      if (url.pathname.startsWith("/api/")) {
        return await handleDashboardApi(request, env, user, url);
      }
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json({ error: "Method not allowed" }, 405);
      }
      const asset = await env.ASSETS.fetch(request);
      const headers = new Headers(asset.headers);
      headers.set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
      headers.set("Referrer-Policy", "no-referrer");
      headers.set("X-Content-Type-Options", "nosniff");
      headers.set("X-Frame-Options", "DENY");
      headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
      return new Response(asset.body, { status: asset.status, statusText: asset.statusText, headers });
    } catch (error) {
      return handleError(error, url.pathname);
    }
  },
} satisfies ExportedHandler<Cloudflare.Env>;

async function handleDashboardApi(
  request: Request,
  env: Cloudflare.Env,
  user: AccessUser,
  url: URL,
): Promise<Response> {
  const hub = singletonHub(env);

  if (url.pathname === "/api/dashboard" && request.method === "GET") {
    const dashboard = await hub.getDashboard();
    return json({
      user: { email: user.email, name: user.name },
      ...dashboard,
      endpoint: `${url.origin}/v1`,
    });
  }

  if (url.pathname === "/api/events" && request.method === "GET") {
    requireSameOrigin(request);
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return json({ error: "Expected a WebSocket upgrade" }, 426);
    }
    return hub.fetch(request);
  }

  if (url.pathname === "/api/socket-ticket" && request.method === "POST") {
    requireSameOrigin(request);
    return json(await hub.issueSocketTicket());
  }

  if (url.pathname === "/api/usage" && request.method === "GET") {
    const githubToken = await hub.getGitHubToken();
    if (!githubToken) return json({ error: "Connect GitHub to view usage" }, 409);
    return json({ usage: await fetchCopilotUsage(env, githubToken) });
  }

  if (url.pathname === "/api/models" && request.method === "GET") {
    let credential: CopilotCredential;
    try {
      credential = await hub.getDashboardCredential();
    } catch (error) {
      return json({ error: errorMessage(error) }, 409);
    }
    const response = await fetch(`${copilotBaseUrl(credential.accountType)}/models`, {
      headers: copilotHeaders(env, credential.token, request),
    });
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) await hub.invalidateToken();
      return json({ error: `Unable to load GitHub Copilot models (${response.status})` }, 502);
    }
    const models: unknown = await response.json();
    return json(models);
  }

  if (url.pathname === "/api/github/device" && request.method === "POST") {
    requireSameOrigin(request);
    const device = await requestDeviceCode(env);
    const encrypted = await encryptSecret(device.device_code, env.TOKEN_ENCRYPTION_KEY);
    const sessionId = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const interval = Math.max(device.interval || 5, 5);
    await hub.saveDeviceSession({
      id: sessionId,
      deviceCode: encrypted,
      userCode: device.user_code,
      verificationUri: device.verification_uri,
      intervalSeconds: interval,
      expiresAt: now + device.expires_in,
    });
    return json({
      sessionId,
      userCode: device.user_code,
      verificationUri: device.verification_uri,
      expiresAt: new Date((now + device.expires_in) * 1000).toISOString(),
      interval,
    }, 201);
  }

  if (url.pathname === "/api/github/device/poll" && request.method === "POST") {
    requireSameOrigin(request);
    try {
      const body = await readJsonObject(request);
      const sessionId = stringField(body, "sessionId", 100);
      const claim = await hub.claimDevicePoll(sessionId);
      if (claim.state === "missing") return json({ error: "Device authorization session not found" }, 404);
      if (claim.state === "expired") {
        return json({ state: "expired", error: "The GitHub device code expired. Start again." }, 410);
      }
      if (claim.state === "rate_limited") {
        return json({ state: "pending", retryAfter: claim.retryAfter }, 429, {
          "Retry-After": String(claim.retryAfter),
        });
      }

      const result = await pollDeviceCode(env, claim.deviceCode);
      if (result.state === "pending") return json({ state: "pending", retryAfter: claim.intervalSeconds });
      if (result.state === "slow_down") {
        const interval = await hub.slowDownDeviceSession(sessionId);
        if (interval === null) return json({ error: "Device authorization session not found" }, 404);
        return json({ state: "pending", retryAfter: interval });
      }
      if (result.state === "expired" || result.state === "denied") {
        await hub.deleteDeviceSession(sessionId);
        return json({ state: result.state, error: result.message }, result.state === "expired" ? 410 : 403);
      }

      const [githubUser, copilotToken] = await Promise.all([
        fetchGitHubUser(env, result.accessToken),
        fetchCopilotToken(env, result.accessToken),
      ]);
      const [githubEncrypted, copilotEncrypted] = await Promise.all([
        encryptSecret(result.accessToken, env.TOKEN_ENCRYPTION_KEY),
        encryptSecret(copilotToken.token, env.TOKEN_ENCRYPTION_KEY),
      ]);
      await hub.saveConnectedCredentials(
        sessionId,
        githubUser.login,
        githubEncrypted,
        copilotEncrypted,
        copilotToken.expires_at,
      );
      return json({ state: "complete", login: githubUser.login });
    } catch (error) {
      const reason = errorMessage(error);
      console.error(JSON.stringify({ event: "github_connection_failed", reason }));
      return json({ state: "error", error: `GitHub connection failed: ${reason}` }, 502);
    }
  }

  if (url.pathname === "/api/github" && request.method === "DELETE") {
    requireSameOrigin(request);
    await hub.disconnectCredentials();
    return new Response(null, { status: 204 });
  }

  if (url.pathname === "/api/keys" && request.method === "POST") {
    requireSameOrigin(request);
    const body = await readJsonObject(request);
    const name = stringField(body, "name", 64).trim();
    if (name.length < 2) throw new AccessError("Key name must contain at least 2 characters", 400);
    try {
      const created = await hub.createApiKey(name);
      return json(created, 201);
    } catch (error) {
      if (errorMessage(error).includes("Connect GitHub")) return json({ error: errorMessage(error) }, 409);
      throw error;
    }
  }

  const keyMatch = url.pathname.match(/^\/api\/keys\/([0-9a-f-]{36})$/i);
  if (keyMatch && request.method === "DELETE") {
    requireSameOrigin(request);
    const keyId = keyMatch[1];
    if (!keyId) return json({ error: "Invalid API key ID" }, 400);
    const revoked = await hub.revokeApiKey(keyId);
    return revoked ? new Response(null, { status: 204 }) : json({ error: "API key not found" }, 404);
  }

  if (url.pathname === "/api/settings" && request.method === "PUT") {
    requireSameOrigin(request);
    const body = await readJsonObject(request);
    const accountType = stringField(body, "accountType", 20);
    if (!isAccountType(accountType)) {
      return json({ error: "Account type must be individual, business, or enterprise" }, 400);
    }
    await hub.setAccountType(accountType);
    return json({ accountType });
  }

  return json({ error: "Not found" }, 404);
}

async function handleDashboardSocket(request: Request, env: Cloudflare.Env): Promise<Response> {
  requireSameOrigin(request);
  if (request.method !== "GET" || request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return json({ error: "Expected a WebSocket upgrade" }, 426);
  }
  const protocol = dashboardSocketProtocol(request);
  if (!protocol) return json({ error: "Missing dashboard socket ticket" }, 401);
  const token = protocol.slice(DASHBOARD_SOCKET_PROTOCOL_PREFIX.length);
  if (!token || !(await singletonHub(env).consumeSocketTicket(token))) {
    return json({ error: "Invalid or expired dashboard socket ticket" }, 401);
  }
  return singletonHub(env).fetch(request);
}

async function proxyToCopilot(
  request: Request,
  env: Cloudflare.Env,
  ctx: ExecutionContext,
  upstreamPath: string,
): Promise<Response> {
  const secret = apiSecret(request);
  if (!secret) return openAIError("Missing API key", 401, { "WWW-Authenticate": "Bearer" });

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 100 * 1024 * 1024) return openAIError("Request body exceeds 100 MB", 413);

  const started = Date.now();
  const modelPromise = readModelHint(request);
  const hub = singletonHub(env);
  let authentication;
  try {
    authentication = await hub.authenticateAndGetCredential(secret);
  } catch (error) {
    return openAIError(errorMessage(error), 409);
  }
  if (!authentication) return openAIError("Invalid or revoked API key", 401, { "WWW-Authenticate": "Bearer" });

  let upstream: Response;
  try {
    upstream = await fetch(`${copilotBaseUrl(authentication.credential.accountType)}${upstreamPath}`, {
      method: request.method,
      headers: copilotHeaders(env, authentication.credential.token, request),
      body: request.method === "GET" || request.method === "HEAD" ? null : request.body,
      redirect: "manual",
    });
  } catch (error) {
    return openAIError(`Copilot upstream request failed: ${errorMessage(error)}`, 502);
  }

  if (upstream.status === 401 || upstream.status === 403) {
    ctx.waitUntil(hub.invalidateToken());
  }
  const metric: RequestMetric = {
    id: crypto.randomUUID(),
    endpoint: upstreamPath,
    model: await modelPromise,
    status: upstream.status,
    latencyMs: Date.now() - started,
    createdAt: new Date().toISOString(),
  };
  ctx.waitUntil(hub.recordRequest(authentication.keyId, metric).catch((error) => {
    console.error(JSON.stringify({ event: "metric_record_failed", requestId: metric.id, reason: errorMessage(error) }));
  }));

  const headers = new Headers(upstream.headers);
  for (const [name, value] of Object.entries(corsHeaders())) headers.set(name, value);
  headers.set("X-Copilot-Proxy-Worker", "1");
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers });
}

function singletonHub(env: Cloudflare.Env): DurableObjectStub<UserHub> {
  return env.USER_HUB.getByName(SINGLETON_HUB_NAME);
}

function readModelHint(request: Request): Promise<string> {
  const size = Number(request.headers.get("content-length"));
  if (!Number.isFinite(size) || size <= 0 || size > 64 * 1024) return Promise.resolve("");
  return readTextAtMost(request.clone(), 64 * 1024).then((text) => {
    const value: unknown = JSON.parse(text);
    if (typeof value === "object" && value !== null && "model" in value) {
      const model = (value as { model?: unknown }).model;
      return typeof model === "string" ? model.slice(0, 160) : "";
    }
    return "";
  }).catch(() => "");
}

function dashboardSocketProtocol(request: Request): string | null {
  const protocols = request.headers.get("sec-websocket-protocol")?.split(",").map((value) => value.trim()) ?? [];
  return protocols.find((value) => value.startsWith(DASHBOARD_SOCKET_PROTOCOL_PREFIX)) ?? null;
}

function apiSecret(request: Request): string | null {
  const xApiKey = request.headers.get("x-api-key")?.trim();
  if (xApiKey) return xApiKey;
  const authorization = request.headers.get("authorization");
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 16 * 1024) throw new AccessError("Request body is too large", 413);
  let value: unknown;
  try {
    value = JSON.parse(await readTextAtMost(request, 16 * 1024));
  } catch (error) {
    if (error instanceof AccessError) throw error;
    throw new AccessError("Expected a valid JSON object", 400);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AccessError("Expected a JSON object", 400);
  }
  return value as Record<string, unknown>;
}

async function readTextAtMost(
  request: { readonly body: ReadableStream<Uint8Array<ArrayBuffer>> | null },
  limit: number,
): Promise<string> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel("body limit exceeded");
      throw new AccessError("Request body is too large", 413);
    }
    const copy = new Uint8Array(value.byteLength);
    copy.set(value);
    chunks.push(copy);
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

function isAccountType(value: string): value is AccountType {
  return value === "individual" || value === "business" || value === "enterprise";
}

function stringField(body: Record<string, unknown>, name: string, maxLength: number): string {
  const value = body[name];
  if (typeof value !== "string" || !value.trim() || value.length > maxLength) {
    throw new AccessError(`${name} must be a non-empty string of at most ${maxLength} characters`, 400);
  }
  return value;
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, X-API-Key, Anthropic-Beta, Anthropic-Version",
    "Access-Control-Expose-Headers": "Retry-After, X-Request-Id, X-Copilot-Proxy-Worker",
  };
}

function json(
  body: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store", ...extraHeaders },
  });
}

function openAIError(message: string, status: number, extraHeaders: Record<string, string> = {}): Response {
  const response = json({ error: { message, type: status === 401 ? "authentication_error" : "api_error" } }, status, extraHeaders);
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(corsHeaders())) headers.set(name, value);
  return new Response(response.body, { status: response.status, headers });
}

function handleError(error: unknown, path: string): Response {
  if (error instanceof AccessError) return json({ error: error.message }, error.status);
  const id = crypto.randomUUID();
  console.error(JSON.stringify({ event: "request_failed", path, errorId: id, reason: errorMessage(error) }));
  return json({ error: "Internal server error", errorId: id }, 500);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}
