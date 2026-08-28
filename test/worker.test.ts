import { env } from "cloudflare:workers";
import {
  createExecutionContext,
  listDurableObjectIds,
  reset,
  runInDurableObject,
  waitOnExecutionContext,
} from "cloudflare:test";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { decryptSecret, encryptSecret, generateApiKey, sha256 } from "../src/crypto";
import { SINGLETON_HUB_NAME, UserHub } from "../src/user-hub";

let privateKey: CryptoKey;
let publicJwk: JWK;
let upstreamAuthorization = "";
let copilotTokenFailure = false;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  publicJwk = await exportJWK(pair.publicKey);
  publicJwk.kid = "test-key";
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
});

beforeEach(async () => {
  await reset();
  upstreamAuthorization = "";
  copilotTokenFailure = false;
  vi.restoreAllMocks();
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === "https://test.cloudflareaccess.com/cdn-cgi/access/certs") {
      return Response.json({ keys: [publicJwk] });
    }
    if (url === "https://github.com/login/device/code") {
      return Response.json({
        device_code: "device-secret",
        user_code: "ABCD-EFGH",
        verification_uri: "https://github.com/login/device",
        expires_in: 900,
        interval: 5,
      });
    }
    if (url === "https://github.com/login/oauth/access_token") {
      return Response.json({ access_token: "github-oauth-secret", token_type: "bearer", scope: "read:user" });
    }
    if (url === "https://api.github.com/user") {
      const headers = new Headers(init?.headers);
      if (headers.get("x-github-api-version") !== "2026-03-10") {
        return Response.json({ message: "Bad Request", errors: "Unsupported API version" }, { status: 400 });
      }
      return Response.json({ login: "octocat" });
    }
    if (url === "https://api.github.com/copilot_internal/v2/token") {
      if (copilotTokenFailure) return new Response("Forbidden", { status: 403 });
      return Response.json({ token: "copilot-short-lived-secret", expires_at: Math.floor(Date.now() / 1000) + 1800 });
    }
    if (url === "https://api.github.com/copilot_internal/user") {
      return Response.json({ copilot_plan: "individual", quota_snapshots: {} });
    }
    if (url === "https://api.githubcopilot.com/models") {
      const headers = new Headers(init?.headers);
      if (headers.has("x-github-api-version")) {
        return Response.json({ message: "Bad Request", error: "Unsupported GitHub API version header" }, { status: 400 });
      }
      upstreamAuthorization = headers.get("authorization") || "";
      return Response.json({ data: [{
        id: "gpt-5-mini",
        name: "GPT-5 mini",
        vendor: "OpenAI",
        supported_endpoints: ["chat_completions", "responses"],
        capabilities: { limits: { max_context_window_tokens: 128000 } },
      }] });
    }
    if (url === "https://api.githubcopilot.com/chat/completions") {
      const headers = new Headers(init?.headers);
      if (headers.has("x-github-api-version")) {
        return Response.json({ message: "Bad Request", error: "Unsupported GitHub API version header" }, { status: 400 });
      }
      upstreamAuthorization = headers.get("authorization") || "";
      return Response.json({ id: "chatcmpl_test", choices: [{ index: 0, message: { role: "assistant", content: "hello" } }] });
    }
    throw new Error(`Unexpected outbound fetch: ${url}`);
  });
});

describe("secret handling", () => {
  it("encrypts values and generates non-recoverable key material", async () => {
    const encrypted = await encryptSecret("very-secret", env.TOKEN_ENCRYPTION_KEY);
    expect(encrypted.ciphertext).not.toContain("very-secret");
    expect(await decryptSecret(encrypted, env.TOKEN_ENCRYPTION_KEY)).toBe("very-secret");

    const first = generateApiKey();
    const second = generateApiKey();
    expect(first.secret).toMatch(/^cpp_[A-Za-z0-9_-]{43}$/);
    expect(first.secret).not.toBe(second.secret);
    expect(await sha256(first.secret)).not.toContain(first.secret);
  });
});

describe("Cloudflare Access dashboard and singleton Durable Object", () => {
  it("rejects dashboard requests that did not pass through Access", async () => {
    const response = await call(new Request("https://console.example.com/api/dashboard"));
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({ error: expect.stringContaining("Cloudflare Access") });
  });

  it("accepts a signed Access assertion when native ctx.access is unavailable", async () => {
    const token = await signAccessToken();
    const response = await call(new Request("https://console.example.com/api/dashboard", {
      headers: { "Cf-Access-Jwt-Assertion": token },
    }));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ user: { email: "person@example.com" } });
  });

  it("uses a one-time ticket to upgrade the Access-bypassed activity feed", async () => {
    const ticketResponse = await callWithWorkerAccess(new Request("https://console.example.com/api/socket-ticket", {
      method: "POST",
      headers: { Origin: "https://console.example.com" },
    }));
    const ticket = await ticketResponse.json<{ token: string }>();
    const socketProtocol = `copilot-dashboard.${ticket.token}`;

    const rejected = await call(new Request("https://console.example.com/v1/dashboard/events", {
      headers: { Origin: "https://evil.example", Upgrade: "websocket", "Sec-WebSocket-Protocol": socketProtocol },
    }));
    expect(rejected.status).toBe(403);

    const response = await call(new Request("https://console.example.com/v1/dashboard/events", {
      headers: {
        Origin: "https://console.example.com",
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": socketProtocol,
      },
    }));
    expect(response.status).toBe(101);
    expect(response.headers.get("sec-websocket-protocol")).toBe(socketProtocol);
    const socket = response.webSocket;
    expect(socket).not.toBeNull();
    if (!socket) throw new Error("Missing WebSocket on upgrade response");
    socket.accept();

    const requestEvent = new Promise<{ type: string; metric: { status: number } }>((resolve) => {
      socket.addEventListener("message", (event) => {
        if (typeof event.data !== "string") return;
        const value = JSON.parse(event.data) as { type: string; metric?: { status: number } };
        if (value.type === "request" && value.metric) resolve({ type: value.type, metric: value.metric });
      });
    });
    await singletonHub().publish(JSON.stringify({ type: "request", metric: { status: 200 } }));
    await expect(requestEvent).resolves.toEqual({ type: "request", metric: { status: 200 } });
    const closed = new Promise<void>((resolve) => socket.addEventListener("close", () => resolve(), { once: true }));
    socket.close(1000, "test complete");
    await closed;

    const replay = await call(new Request("https://console.example.com/v1/dashboard/events", {
      headers: {
        Origin: "https://console.example.com",
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": socketProtocol,
      },
    }));
    expect(replay.status).toBe(401);
  });

  it("returns a useful provider error instead of a generic internal error", async () => {
    const start = await callWithWorkerAccess(accessRequest("/api/github/device", { method: "POST" }));
    const flow = await start.json<{ sessionId: string }>();
    copilotTokenFailure = true;

    const response = await callWithWorkerAccess(accessRequest("/api/github/device/poll", {
      method: "POST",
      body: JSON.stringify({ sessionId: flow.sessionId }),
    }));
    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      state: "error",
      error: "GitHub connection failed: Unable to obtain a GitHub Copilot API token (403)",
    });
  });

  it("connects GitHub, creates a private key, and proxies an OpenAI request", async () => {
    const dashboard = await callWithWorkerAccess(accessRequest("/api/dashboard"));
    expect(dashboard.status).toBe(200);
    await expect(dashboard.json()).resolves.toMatchObject({
      github: { connected: false },
      endpoint: "https://console.example.com/v1",
      user: { email: "person@example.com" },
    });

    const start = await callWithWorkerAccess(accessRequest("/api/github/device", { method: "POST" }));
    expect(start.status).toBe(201);
    const flow = await start.json<{ sessionId: string; userCode: string }>();
    expect(flow.userCode).toBe("ABCD-EFGH");

    const complete = await callWithWorkerAccess(accessRequest("/api/github/device/poll", {
      method: "POST",
      body: JSON.stringify({ sessionId: flow.sessionId }),
    }));
    expect(complete.status).toBe(200);
    await expect(complete.json()).resolves.toEqual({ state: "complete", login: "octocat" });

    const modelsResponse = await callWithWorkerAccess(accessRequest("/api/models"));
    expect(modelsResponse.status).toBe(200);
    await expect(modelsResponse.json()).resolves.toMatchObject({
      data: [{ id: "gpt-5-mini", vendor: "OpenAI", supported_endpoints: ["chat_completions", "responses"] }],
    });
    expect(upstreamAuthorization).toBe("Bearer copilot-short-lived-secret");

    await runInDurableObject(singletonHub(), async (_instance: UserHub, state) => {
      const stored = state.storage.sql.exec<{
        githubLogin: string;
        githubTokenCiphertext: string;
        copilotTokenCiphertext: string;
      }>(`
        SELECT github_login AS githubLogin, github_token_ciphertext AS githubTokenCiphertext,
          copilot_token_ciphertext AS copilotTokenCiphertext FROM credentials WHERE id = 1
      `).one();
      expect(stored.githubLogin).toBe("octocat");
      expect(stored.githubTokenCiphertext).not.toContain("github-oauth-secret");
      expect(stored.copilotTokenCiphertext).not.toContain("copilot-short-lived-secret");
    });

    const createdResponse = await callWithWorkerAccess(accessRequest("/api/keys", {
      method: "POST",
      body: JSON.stringify({ name: "Integration test" }),
    }));
    expect(createdResponse.status).toBe(201);
    const created = await createdResponse.json<{ id: string; secret: string; prefix: string }>();
    expect(created.secret).toMatch(/^cpp_/);
    await runInDurableObject(singletonHub(), async (_instance: UserHub, state) => {
      const key = state.storage.sql.exec<{ secretHash: string }>(`
        SELECT secret_hash AS secretHash FROM api_keys WHERE id = ?
      `, created.id).one();
      expect(key.secretHash).toBe(await sha256(created.secret));
      expect(key.secretHash).not.toContain(created.secret);
    });

    const payload = JSON.stringify({ model: "gpt-5-mini", messages: [{ role: "user", content: "hello" }] });
    const completion = await call(new Request("https://console.example.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${created.secret}`,
        "Content-Type": "application/json",
        "Content-Length": String(new TextEncoder().encode(payload).byteLength),
      },
      body: payload,
    }));
    expect(completion.status).toBe(200);
    expect(completion.headers.get("access-control-allow-origin")).toBe("*");
    expect(completion.headers.get("x-copilot-proxy-worker")).toBe("1");
    expect(upstreamAuthorization).toBe("Bearer copilot-short-lived-secret");
    await expect(completion.json()).resolves.toMatchObject({ id: "chatcmpl_test" });

    const refreshed = await callWithWorkerAccess(accessRequest("/api/dashboard"));
    const refreshedBody = await refreshed.json<{
      metrics: { totalRequests: number; successfulRequests: number; recent: Array<{ model: string }> };
    }>();
    expect(refreshedBody.metrics.totalRequests).toBe(1);
    expect(refreshedBody.metrics.successfulRequests).toBe(1);
    expect(refreshedBody.metrics.recent[0]?.model).toBe("gpt-5-mini");

    const revoked = await callWithWorkerAccess(accessRequest(`/api/keys/${created.id}`, { method: "DELETE" }));
    expect(revoked.status).toBe(204);
    const rejected = await call(new Request("https://console.example.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${created.secret}`, "Content-Type": "application/json" },
      body: payload,
    }));
    expect(rejected.status).toBe(401);
    await expect(rejected.json()).resolves.toMatchObject({
      error: { message: "Invalid or revoked API key" },
    });

    const objectIds = await listDurableObjectIds(env.USER_HUB);
    expect(objectIds).toHaveLength(1);
    expect(objectIds[0]?.equals(env.USER_HUB.idFromName(SINGLETON_HUB_NAME))).toBe(true);
  });
});

describe("credential lifecycle", () => {
  it("keeps all state in one DO and rejects stale token writes after disconnect", async () => {
    const hub = singletonHub();
    const [github, copilot, deviceCode] = await Promise.all([
      encryptSecret("old-github-token", env.TOKEN_ENCRYPTION_KEY),
      encryptSecret("old-copilot-token", env.TOKEN_ENCRYPTION_KEY),
      encryptSecret("device", env.TOKEN_ENCRYPTION_KEY),
    ]);
    await hub.saveDeviceSession({
      id: "old-session",
      deviceCode,
      userCode: "OLD-CODE",
      verificationUri: "https://github.com/login/device",
      intervalSeconds: 5,
      expiresAt: Math.floor(Date.now() / 1000) + 900,
    });
    await hub.saveConnectedCredentials(
      "old-session",
      "old-login",
      github,
      copilot,
      Math.floor(Date.now() / 1000) + 1800,
    );
    const key = await hub.createApiKey("Existing client");
    await expect(hub.authenticateAndGetCredential(key.secret)).resolves.toMatchObject({
      credential: { token: "old-copilot-token" },
    });

    await hub.disconnectCredentials();
    await runInDurableObject(hub, async (_instance: UserHub, state) => {
      const staleWrite = state.storage.sql.exec(`
        UPDATE credentials SET copilot_token_ciphertext = 'stale' WHERE id = 1 AND credential_version = 1
      `);
      expect(staleWrite.rowsWritten).toBe(0);
      const stored = state.storage.sql.exec<{
        githubTokenCiphertext: string | null;
        copilotTokenCiphertext: string | null;
        credentialVersion: number;
      }>(`
        SELECT github_token_ciphertext AS githubTokenCiphertext,
          copilot_token_ciphertext AS copilotTokenCiphertext,
          credential_version AS credentialVersion FROM credentials WHERE id = 1
      `).one();
      expect(stored).toEqual({
        githubTokenCiphertext: null,
        copilotTokenCiphertext: null,
        credentialVersion: 2,
      });
      expect(state.storage.sql.exec("SELECT id FROM settings").toArray()).toHaveLength(1);
    });

    const [newGithub, newCopilot, newDeviceCode] = await Promise.all([
      encryptSecret("new-github-token", env.TOKEN_ENCRYPTION_KEY),
      encryptSecret("new-copilot-token", env.TOKEN_ENCRYPTION_KEY),
      encryptSecret("new-device", env.TOKEN_ENCRYPTION_KEY),
    ]);
    await hub.saveDeviceSession({
      id: "new-session",
      deviceCode: newDeviceCode,
      userCode: "NEW-CODE",
      verificationUri: "https://github.com/login/device",
      intervalSeconds: 5,
      expiresAt: Math.floor(Date.now() / 1000) + 900,
    });
    await hub.saveConnectedCredentials(
      "new-session",
      "new-login",
      newGithub,
      newCopilot,
      Math.floor(Date.now() / 1000) + 1800,
    );
    await expect(hub.authenticateAndGetCredential(key.secret)).resolves.toMatchObject({
      credential: { token: "new-copilot-token" },
    });
  });
});

async function call(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

async function callWithWorkerAccess(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  Object.defineProperty(ctx, "access", {
    value: {
      aud: "test-access-audience",
      getIdentity: async () => ({ email: "person@example.com", name: "Test Person" }),
    } satisfies CloudflareAccessContext,
  });
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

function singletonHub(): DurableObjectStub<UserHub> {
  return env.USER_HUB.getByName(SINGLETON_HUB_NAME);
}

async function signAccessToken(): Promise<string> {
  return new SignJWT({ email: "person@example.com", name: "Test Person" })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer("https://test.cloudflareaccess.com")
    .setAudience("test-access-audience")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

function accessRequest(path: string, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers);
  if (!headers.has("Origin")) headers.set("Origin", "https://console.example.com");
  if (init.body) headers.set("Content-Type", "application/json");
  return new Request(`https://console.example.com${path}`, { ...init, headers });
}

