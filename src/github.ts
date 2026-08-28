export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

export type DevicePollResult =
  | { state: "pending" }
  | { state: "slow_down" }
  | { state: "complete"; accessToken: string }
  | { state: "expired"; message: string }
  | { state: "denied"; message: string };

export interface CopilotTokenResponse {
  token: string;
  expires_at: number;
  refresh_in?: number;
}

export interface GitHubUser {
  login: string;
}

export async function requestDeviceCode(env: Cloudflare.Env): Promise<DeviceCodeResponse> {
  const response = await fetch("https://github.com/login/device/code", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, scope: "read:user" }),
  });
  return parseGitHubResponse<DeviceCodeResponse>(response, "GitHub device authorization failed");
}

export async function pollDeviceCode(env: Cloudflare.Env, deviceCode: string): Promise<DevicePollResult> {
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      device_code: deviceCode,
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    }),
  });
  const body = await parseGitHubResponse<{
    access_token?: string;
    error?: string;
    error_description?: string;
  }>(response, "GitHub authorization polling failed");

  if (body.access_token) return { state: "complete", accessToken: body.access_token };
  switch (body.error) {
    case "authorization_pending":
      return { state: "pending" };
    case "slow_down":
      return { state: "slow_down" };
    case "expired_token":
      return { state: "expired", message: "The GitHub device code expired. Start again." };
    case "access_denied":
      return { state: "denied", message: "GitHub authorization was denied." };
    default:
      throw new Error(body.error_description || body.error || "GitHub returned an unexpected authorization response");
  }
}

export async function fetchCopilotToken(env: Cloudflare.Env, githubToken: string): Promise<CopilotTokenResponse> {
  const response = await fetch("https://api.github.com/copilot_internal/v2/token", {
    headers: githubHeaders(env, githubToken),
  });
  return parseGitHubResponse<CopilotTokenResponse>(response, "Unable to obtain a GitHub Copilot API token");
}

export async function fetchGitHubUser(env: Cloudflare.Env, githubToken: string): Promise<GitHubUser> {
  const response = await fetch("https://api.github.com/user", {
    headers: githubHeaders(env, githubToken),
  });
  return parseGitHubResponse<GitHubUser>(response, "Unable to read the GitHub account");
}

export async function fetchCopilotUsage(env: Cloudflare.Env, githubToken: string): Promise<unknown> {
  const response = await fetch("https://api.github.com/copilot_internal/user", {
    headers: githubHeaders(env, githubToken),
  });
  return parseGitHubResponse<unknown>(response, "Unable to read Copilot usage");
}

export function copilotBaseUrl(accountType: string): string {
  switch (accountType) {
    case "business":
      return "https://api.business.githubcopilot.com";
    case "enterprise":
      return "https://api.enterprise.githubcopilot.com";
    default:
      return "https://api.githubcopilot.com";
  }
}

export function copilotHeaders(
  env: Cloudflare.Env,
  token: string,
  request: Request,
): Headers {
  const headers = new Headers();
  headers.set("Authorization", `Bearer ${token}`);
  headers.set("Content-Type", request.headers.get("content-type") || "application/json");
  headers.set("Accept", request.headers.get("accept") || "application/json");
  headers.set("Copilot-Integration-Id", "vscode-chat");
  headers.set("Editor-Version", `vscode/${env.VSCODE_VERSION}`);
  headers.set("Editor-Plugin-Version", `copilot-chat/${env.COPILOT_CHAT_VERSION}`);
  headers.set("User-Agent", `GitHubCopilotChat/${env.COPILOT_CHAT_VERSION}`);
  headers.set("Openai-Intent", "conversation-agent");
  headers.set("X-Request-Id", crypto.randomUUID());
  headers.set("X-Vscode-User-Agent-Library-Version", "electron-fetch");
  headers.set("X-Initiator", request.headers.get("x-initiator") === "agent" ? "agent" : "user");
  for (const name of ["anthropic-beta", "anthropic-version", "copilot-vision-request"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  return headers;
}

function githubHeaders(env: Cloudflare.Env, token: string): Headers {
  return new Headers({
    Authorization: `token ${token}`,
    Accept: "application/json",
    "Content-Type": "application/json",
    "Editor-Version": `vscode/${env.VSCODE_VERSION}`,
    "Editor-Plugin-Version": `copilot-chat/${env.COPILOT_CHAT_VERSION}`,
    "User-Agent": `GitHubCopilotChat/${env.COPILOT_CHAT_VERSION}`,
    "X-Github-Api-Version": env.GITHUB_API_VERSION,
    "X-Vscode-User-Agent-Library-Version": "electron-fetch",
  });
}

async function parseGitHubResponse<T>(response: Response, fallback: string): Promise<T> {
  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${fallback} (${response.status})`);
  }
  if (!response.ok) {
    const message = isObject(body) && typeof body.message === "string" ? body.message : fallback;
    throw new Error(`${message} (${response.status})`);
  }
  return body as T;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
