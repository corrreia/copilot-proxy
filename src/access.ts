import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from "jose";

export interface AccessUser {
  email: string;
  name: string;
}

type RemoteJWKSet = ReturnType<typeof createRemoteJWKSet>;
let cachedJwks: { issuer: string; keys: RemoteJWKSet } | null = null;

export async function requireAccessUser(
  request: Request,
  env: Cloudflare.Env,
  access?: CloudflareAccessContext,
): Promise<AccessUser> {
  const hostname = new URL(request.url).hostname;
  if ((hostname === "localhost" || hostname === "127.0.0.1") && env.LOCAL_DEV_EMAIL) {
    return { email: env.LOCAL_DEV_EMAIL, name: "Local developer" };
  }

  if (access) {
    try {
      const identity = await access.getIdentity();
      if (identity?.email) {
        return {
          email: identity.email,
          name: typeof identity.name === "string" && identity.name.trim() ? identity.name : identity.email,
        };
      }
    } catch (error) {
      console.warn(JSON.stringify({ event: "native_access_identity_failed", reason: errorMessage(error) }));
    }
  }

  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw new AccessError("Sign in through Cloudflare Access to continue", 401);
  return verifyAccessAssertion(token);
}

export function requireSameOrigin(request: Request): void {
  const origin = request.headers.get("origin");
  if (!origin || origin !== new URL(request.url).origin) {
    throw new AccessError("Cross-origin dashboard request rejected", 403);
  }
}

export class AccessError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function verifyAccessAssertion(token: string): Promise<AccessUser> {
  let unverified: JWTPayload;
  try {
    unverified = decodeJwt(token);
  } catch {
    throw new AccessError("Your Cloudflare Access session is invalid or expired", 401);
  }
  const issuer = validAccessIssuer(unverified.iss);
  if (!issuer || !hasAudience(unverified.aud)) {
    throw new AccessError("Your Cloudflare Access session is invalid or expired", 401);
  }

  if (!cachedJwks || cachedJwks.issuer !== issuer) {
    cachedJwks = {
      issuer,
      keys: createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`)),
    };
  }

  try {
    const { payload } = await jwtVerify(token, cachedJwks.keys, {
      issuer,
      algorithms: ["RS256"],
    });
    if (typeof payload.email !== "string" || !payload.email) {
      throw new Error("Access assertion is missing email");
    }
    const name = payload.name;
    return {
      email: payload.email,
      name: typeof name === "string" && name.trim() ? name : payload.email,
    };
  } catch (error) {
    console.warn(JSON.stringify({ event: "access_jwt_rejected", reason: errorMessage(error) }));
    throw new AccessError("Your Cloudflare Access session is invalid or expired", 401);
  }
}

function validAccessIssuer(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.port ||
      !url.hostname.endsWith(".cloudflareaccess.com") ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function hasAudience(value: JWTPayload["aud"]): boolean {
  return typeof value === "string" ? value.length > 0 : Array.isArray(value) && value.length > 0;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}
