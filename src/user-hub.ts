import { DurableObject } from "cloudflare:workers";
import { decryptSecret, encryptSecret, generateApiKey, sha256, type EncryptedValue } from "./crypto";
import { fetchCopilotToken } from "./github";

export const SINGLETON_HUB_NAME = "singleton";
export const DASHBOARD_SOCKET_PROTOCOL_PREFIX = "copilot-dashboard.";

export type AccountType = "individual" | "business" | "enterprise";

export interface CopilotCredential {
  token: string;
  accountType: AccountType;
}

export interface ApiKeyView extends Record<string, SqlStorageValue> {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface RequestMetric extends Record<string, SqlStorageValue> {
  id: string;
  endpoint: string;
  model: string;
  status: number;
  latencyMs: number;
  createdAt: string;
}

export interface DashboardState {
  github: { connected: boolean; login: string | null };
  settings: { accountType: AccountType };
  keys: ApiKeyView[];
  metrics: { totalRequests: number; successfulRequests: number; recent: RequestMetric[] };
}

export interface DeviceSessionInput {
  id: string;
  deviceCode: EncryptedValue;
  userCode: string;
  verificationUri: string;
  intervalSeconds: number;
  expiresAt: number;
}

export type DevicePollClaim =
  | { state: "ready"; deviceCode: string; intervalSeconds: number }
  | { state: "missing" }
  | { state: "expired" }
  | { state: "rate_limited"; retryAfter: number };

interface CredentialRow extends Record<string, SqlStorageValue> {
  githubLogin: string | null;
  githubTokenCiphertext: string | null;
  githubTokenIv: string | null;
  copilotTokenCiphertext: string | null;
  copilotTokenIv: string | null;
  copilotExpiresAt: number | null;
  credentialVersion: number;
}

interface DeviceSessionRow extends Record<string, SqlStorageValue> {
  id: string;
  deviceCodeCiphertext: string;
  deviceCodeIv: string;
  intervalSeconds: number;
  lastPollAt: number;
  expiresAt: number;
}

export class UserHub extends DurableObject<Cloudflare.Env> {
  private cachedToken: { token: string; expiresAt: number; accountType: AccountType } | null = null;
  private refreshInFlight: { generation: number; promise: Promise<CopilotCredential> } | null = null;
  private credentialGeneration = 0;
  private credentialMutationsPending = 0;
  private mutationTail: Promise<void> = Promise.resolve();

  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    this.ctx.blockConcurrencyWhile(async () => {
      this.initializeSchema();
    });
  }

  getDashboard(): DashboardState {
    const credential = this.credentialRow();
    const accountType = this.accountType();
    const keys = this.ctx.storage.sql.exec<ApiKeyView>(`
      SELECT id, name, key_prefix AS prefix, created_at AS createdAt, last_used_at AS lastUsedAt
      FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC
    `).toArray();
    const totals = this.ctx.storage.sql.exec<{ totalRequests: number; successfulRequests: number }>(`
      SELECT total_requests AS totalRequests, successful_requests AS successfulRequests
      FROM stats WHERE id = 1
    `).one();
    const recent = this.ctx.storage.sql.exec<RequestMetric>(`
      SELECT id, endpoint, model, status, latency_ms AS latencyMs, created_at AS createdAt
      FROM requests ORDER BY created_at DESC LIMIT 30
    `).toArray();
    return {
      github: { connected: Boolean(credential.githubLogin), login: credential.githubLogin },
      settings: { accountType },
      keys,
      metrics: {
        totalRequests: totals.totalRequests,
        successfulRequests: totals.successfulRequests,
        recent,
      },
    };
  }

  async saveDeviceSession(input: DeviceSessionInput): Promise<void> {
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM github_device_session");
      this.ctx.storage.sql.exec(`
        INSERT INTO github_device_session (
          id, device_code_ciphertext, device_code_iv, user_code, verification_uri,
          interval_seconds, last_poll_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
      `,
      input.id,
      input.deviceCode.ciphertext,
      input.deviceCode.iv,
      input.userCode,
      input.verificationUri,
      input.intervalSeconds,
      input.expiresAt);
    });
  }

  async claimDevicePoll(sessionId: string): Promise<DevicePollClaim> {
    const session = this.first<DeviceSessionRow>(`
      SELECT id, device_code_ciphertext AS deviceCodeCiphertext, device_code_iv AS deviceCodeIv,
        interval_seconds AS intervalSeconds, last_poll_at AS lastPollAt, expires_at AS expiresAt
      FROM github_device_session WHERE id = ?
    `, sessionId);
    if (!session) return { state: "missing" };

    const now = Math.floor(Date.now() / 1000);
    if (session.expiresAt <= now) {
      this.ctx.storage.sql.exec("DELETE FROM github_device_session WHERE id = ?", sessionId);
      return { state: "expired" };
    }
    const nextPoll = session.lastPollAt + session.intervalSeconds;
    if (nextPoll > now) return { state: "rate_limited", retryAfter: nextPoll - now };

    this.ctx.storage.sql.exec(
      "UPDATE github_device_session SET last_poll_at = ? WHERE id = ?",
      now,
      sessionId,
    );
    const deviceCode = await decryptSecret(
      { ciphertext: session.deviceCodeCiphertext, iv: session.deviceCodeIv },
      this.env.TOKEN_ENCRYPTION_KEY,
    );
    return { state: "ready", deviceCode, intervalSeconds: session.intervalSeconds };
  }

  slowDownDeviceSession(sessionId: string): number | null {
    const session = this.first<{ intervalSeconds: number }>(`
      SELECT interval_seconds AS intervalSeconds FROM github_device_session WHERE id = ?
    `, sessionId);
    if (!session) return null;
    const interval = session.intervalSeconds + 5;
    this.ctx.storage.sql.exec(
      "UPDATE github_device_session SET interval_seconds = ? WHERE id = ?",
      interval,
      sessionId,
    );
    return interval;
  }

  deleteDeviceSession(sessionId: string): void {
    this.ctx.storage.sql.exec("DELETE FROM github_device_session WHERE id = ?", sessionId);
  }

  async saveConnectedCredentials(
    sessionId: string,
    githubLogin: string,
    githubToken: EncryptedValue,
    copilotToken: EncryptedValue,
    copilotExpiresAt: number,
  ): Promise<void> {
    await this.runCredentialMutation(async () => {
      this.ctx.storage.transactionSync(() => {
        const session = this.first<{ id: string }>("SELECT id FROM github_device_session WHERE id = ?", sessionId);
        if (!session) throw new Error("GitHub authorization session is no longer active");
        this.ctx.storage.sql.exec(`
          UPDATE credentials SET github_login = ?, github_token_ciphertext = ?, github_token_iv = ?,
            copilot_token_ciphertext = ?, copilot_token_iv = ?, copilot_expires_at = ?,
            credential_version = credential_version + 1, updated_at = datetime('now') WHERE id = 1
        `,
        githubLogin,
        githubToken.ciphertext,
        githubToken.iv,
        copilotToken.ciphertext,
        copilotToken.iv,
        copilotExpiresAt);
        this.ctx.storage.sql.exec("DELETE FROM github_device_session WHERE id = ?", sessionId);
      });
    });
  }

  async disconnectCredentials(): Promise<void> {
    await this.runCredentialMutation(async () => {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(`
          UPDATE credentials SET github_login = NULL, github_token_ciphertext = NULL, github_token_iv = NULL,
            copilot_token_ciphertext = NULL, copilot_token_iv = NULL, copilot_expires_at = NULL,
            credential_version = credential_version + 1, updated_at = datetime('now') WHERE id = 1
        `);
        this.ctx.storage.sql.exec("DELETE FROM github_device_session");
      });
    });
  }

  async getDashboardCredential(): Promise<CopilotCredential> {
    return this.getCopilotCredential();
  }

  async getGitHubToken(): Promise<string | null> {
    const credential = this.credentialRow();
    if (!credential.githubTokenCiphertext || !credential.githubTokenIv) return null;
    return decryptSecret(
      { ciphertext: credential.githubTokenCiphertext, iv: credential.githubTokenIv },
      this.env.TOKEN_ENCRYPTION_KEY,
    );
  }

  async issueSocketTicket(): Promise<{ token: string; expiresAt: number }> {
    const token = generateApiKey().secret;
    const tokenHash = await sha256(token);
    const expiresAt = Math.floor(Date.now() / 1000) + 60;
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM socket_tickets WHERE expires_at <= ?", Math.floor(Date.now() / 1000));
      this.ctx.storage.sql.exec(
        "INSERT INTO socket_tickets (token_hash, expires_at) VALUES (?, ?)",
        tokenHash,
        expiresAt,
      );
    });
    return { token, expiresAt };
  }

  async consumeSocketTicket(token: string): Promise<boolean> {
    const tokenHash = await sha256(token);
    const now = Math.floor(Date.now() / 1000);
    return this.ctx.storage.transactionSync(() => {
      const ticket = this.first<{ tokenHash: string }>(`
        SELECT token_hash AS tokenHash FROM socket_tickets
        WHERE token_hash = ? AND expires_at > ?
      `, tokenHash, now);
      this.ctx.storage.sql.exec("DELETE FROM socket_tickets WHERE token_hash = ? OR expires_at <= ?", tokenHash, now);
      return ticket !== null;
    });
  }

  async createApiKey(name: string): Promise<ApiKeyView & { secret: string }> {
    if (!this.credentialRow().githubLogin) throw new Error("Connect GitHub before creating an API key");
    const generated = generateApiKey();
    const id = crypto.randomUUID();
    const secretHash = await sha256(generated.secret);
    const created = this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(`
        INSERT INTO api_keys (id, name, key_prefix, secret_hash) VALUES (?, ?, ?, ?)
      `, id, name, generated.prefix, secretHash);
      return this.ctx.storage.sql.exec<{ createdAt: string }>(`
        SELECT created_at AS createdAt FROM api_keys WHERE id = ?
      `, id).one();
    });
    return {
      id,
      name,
      prefix: generated.prefix,
      secret: generated.secret,
      createdAt: created.createdAt,
      lastUsedAt: null,
    };
  }

  revokeApiKey(keyId: string): boolean {
    const result = this.ctx.storage.sql.exec(`
      UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL
    `, keyId);
    return result.rowsWritten === 1;
  }

  async authenticateAndGetCredential(secret: string): Promise<{
    keyId: string;
    credential: CopilotCredential;
  } | null> {
    const secretHash = await sha256(secret);
    const key = this.first<{ id: string }>(`
      SELECT id FROM api_keys WHERE secret_hash = ? AND revoked_at IS NULL
    `, secretHash);
    if (!key) return null;
    const credential = await this.getCopilotCredential();
    this.ctx.storage.sql.exec(
      "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ? AND revoked_at IS NULL",
      key.id,
    );
    return { keyId: key.id, credential };
  }

  async setAccountType(accountType: AccountType): Promise<void> {
    await this.runCredentialMutation(async () => {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("UPDATE settings SET account_type = ? WHERE id = 1", accountType);
        this.ctx.storage.sql.exec(`
          UPDATE credentials SET copilot_token_ciphertext = NULL, copilot_token_iv = NULL,
            copilot_expires_at = NULL, credential_version = credential_version + 1,
            updated_at = datetime('now') WHERE id = 1
        `);
      });
    });
  }

  async invalidateToken(): Promise<void> {
    await this.runCredentialMutation(async () => {
      this.ctx.storage.sql.exec(`
        UPDATE credentials SET copilot_token_ciphertext = NULL, copilot_token_iv = NULL,
          copilot_expires_at = NULL, credential_version = credential_version + 1,
          updated_at = datetime('now') WHERE id = 1
      `);
    });
  }

  recordRequest(keyId: string, metric: RequestMetric): void {
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(`
        INSERT INTO requests (id, api_key_id, endpoint, model, status, latency_ms, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      metric.id,
      keyId,
      metric.endpoint,
      metric.model,
      metric.status,
      metric.latencyMs,
      metric.createdAt);
      this.ctx.storage.sql.exec(`
        UPDATE stats SET total_requests = total_requests + 1,
          successful_requests = successful_requests + ? WHERE id = 1
      `, metric.status >= 200 && metric.status < 300 ? 1 : 0);
      this.ctx.storage.sql.exec(`
        DELETE FROM requests WHERE id NOT IN (
          SELECT id FROM requests ORDER BY created_at DESC LIMIT 200
        )
      `);
    });
    this.publish(JSON.stringify({ type: "request", metric }));
  }

  publish(event: string): void {
    for (const socket of this.ctx.getWebSockets()) {
      try {
        socket.send(event);
      } catch (error) {
        console.warn(JSON.stringify({ event: "websocket_send_failed", reason: errorMessage(error) }));
      }
    }
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected a WebSocket upgrade", { status: 426 });
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ type: "connected", at: new Date().toISOString() }));
    const headers = new Headers();
    const protocol = dashboardSocketProtocol(request);
    if (protocol) headers.set("Sec-WebSocket-Protocol", protocol);
    return new Response(null, { status: 101, webSocket: client, headers });
  }

  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): void {
    if (message === "ping") socket.send("pong");
  }

  webSocketClose(socket: WebSocket, code: number, reason: string): void {
    socket.close(code, reason);
  }

  private async getCopilotCredential(): Promise<CopilotCredential> {
    if (this.credentialMutationsPending > 0) throw new Error("Credentials are being updated; retry the request");
    const now = Math.floor(Date.now() / 1000);
    if (this.cachedToken && this.cachedToken.expiresAt > now + 120) {
      return { token: this.cachedToken.token, accountType: this.cachedToken.accountType };
    }

    const generation = this.credentialGeneration;
    if (this.refreshInFlight?.generation === generation) return this.refreshInFlight.promise;
    const promise = this.loadCopilotCredential(generation);
    this.refreshInFlight = { generation, promise };
    try {
      return await promise;
    } finally {
      if (this.refreshInFlight?.promise === promise) this.refreshInFlight = null;
    }
  }

  private async loadCopilotCredential(generation: number): Promise<CopilotCredential> {
    const now = Math.floor(Date.now() / 1000);
    const credential = this.credentialRow();
    const accountType = this.accountType();
    if (!credential.githubTokenCiphertext || !credential.githubTokenIv) {
      throw new Error("Connect a GitHub account before using this API key");
    }

    if (
      credential.copilotTokenCiphertext &&
      credential.copilotTokenIv &&
      credential.copilotExpiresAt &&
      credential.copilotExpiresAt > now + 120
    ) {
      const token = await decryptSecret(
        { ciphertext: credential.copilotTokenCiphertext, iv: credential.copilotTokenIv },
        this.env.TOKEN_ENCRYPTION_KEY,
      );
      this.assertCredentialGeneration(generation);
      this.cachedToken = { token, expiresAt: credential.copilotExpiresAt, accountType };
      return { token, accountType };
    }

    const githubToken = await decryptSecret(
      { ciphertext: credential.githubTokenCiphertext, iv: credential.githubTokenIv },
      this.env.TOKEN_ENCRYPTION_KEY,
    );
    const fresh = await fetchCopilotToken(this.env, githubToken);
    this.assertCredentialGeneration(generation);
    if (!fresh.token || !Number.isFinite(fresh.expires_at)) {
      throw new Error("GitHub returned an invalid Copilot token");
    }
    const encrypted = await encryptSecret(fresh.token, this.env.TOKEN_ENCRYPTION_KEY);
    this.assertCredentialGeneration(generation);
    const updated = this.ctx.storage.sql.exec(`
      UPDATE credentials SET copilot_token_ciphertext = ?, copilot_token_iv = ?,
        copilot_expires_at = ?, updated_at = datetime('now')
      WHERE id = 1 AND credential_version = ?
    `, encrypted.ciphertext, encrypted.iv, fresh.expires_at, credential.credentialVersion);
    this.assertCredentialGeneration(generation);
    if (updated.rowsWritten !== 1) throw new Error("Credentials changed during token refresh; retry the request");
    this.cachedToken = { token: fresh.token, expiresAt: fresh.expires_at, accountType };
    return { token: fresh.token, accountType };
  }

  private async runCredentialMutation(work: () => Promise<void>): Promise<void> {
    this.credentialMutationsPending += 1;
    this.credentialGeneration += 1;
    this.cachedToken = null;
    const operation = this.mutationTail.catch(() => undefined).then(async () => {
      if (this.refreshInFlight) {
        try {
          await this.refreshInFlight.promise;
        } catch {
          // A superseded or failed refresh must not prevent a credential mutation.
        }
      }
      await work();
    });
    this.mutationTail = operation;
    try {
      await operation;
    } finally {
      this.credentialMutationsPending -= 1;
    }
  }

  private assertCredentialGeneration(generation: number): void {
    if (this.credentialMutationsPending > 0 || this.credentialGeneration !== generation) {
      throw new Error("Credentials changed during token refresh; retry the request");
    }
  }

  private initializeSchema(): void {
    const sql = this.ctx.storage.sql;
    sql.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        account_type TEXT NOT NULL DEFAULT 'individual'
          CHECK (account_type IN ('individual', 'business', 'enterprise'))
      )
    `);
    sql.exec("INSERT OR IGNORE INTO settings (id) VALUES (1)");
    sql.exec(`
      CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        github_login TEXT,
        github_token_ciphertext TEXT,
        github_token_iv TEXT,
        copilot_token_ciphertext TEXT,
        copilot_token_iv TEXT,
        copilot_expires_at INTEGER,
        credential_version INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    sql.exec("INSERT OR IGNORE INTO credentials (id) VALUES (1)");
    sql.exec(`
      CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        total_requests INTEGER NOT NULL DEFAULT 0,
        successful_requests INTEGER NOT NULL DEFAULT 0
      )
    `);
    sql.exec("INSERT OR IGNORE INTO stats (id) VALUES (1)");
    sql.exec(`
      CREATE TABLE IF NOT EXISTS github_device_session (
        id TEXT PRIMARY KEY,
        device_code_ciphertext TEXT NOT NULL,
        device_code_iv TEXT NOT NULL,
        user_code TEXT NOT NULL,
        verification_uri TEXT NOT NULL,
        interval_seconds INTEGER NOT NULL,
        last_poll_at INTEGER NOT NULL DEFAULT 0,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS socket_tickets (
        token_hash TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        secret_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_used_at TEXT,
        revoked_at TEXT
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        api_key_id TEXT,
        endpoint TEXT NOT NULL,
        model TEXT NOT NULL DEFAULT '',
        status INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    sql.exec("CREATE INDEX IF NOT EXISTS requests_created_idx ON requests(created_at DESC)");
  }

  private credentialRow(): CredentialRow {
    return this.ctx.storage.sql.exec<CredentialRow>(`
      SELECT github_login AS githubLogin, github_token_ciphertext AS githubTokenCiphertext,
        github_token_iv AS githubTokenIv, copilot_token_ciphertext AS copilotTokenCiphertext,
        copilot_token_iv AS copilotTokenIv, copilot_expires_at AS copilotExpiresAt,
        credential_version AS credentialVersion
      FROM credentials WHERE id = 1
    `).one();
  }

  private accountType(): AccountType {
    return this.ctx.storage.sql.exec<{ accountType: AccountType }>(`
      SELECT account_type AS accountType FROM settings WHERE id = 1
    `).one().accountType;
  }

  private first<T extends Record<string, SqlStorageValue>>(query: string, ...bindings: SqlStorageValue[]): T | null {
    return this.ctx.storage.sql.exec<T>(query, ...bindings).toArray()[0] ?? null;
  }
}

function dashboardSocketProtocol(request: Request): string | null {
  const protocols = request.headers.get("sec-websocket-protocol")?.split(",").map((value) => value.trim()) ?? [];
  return protocols.find((value) => value.startsWith(DASHBOARD_SOCKET_PROTOCOL_PREFIX)) ?? null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}
