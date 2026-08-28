declare namespace Cloudflare {
  interface Env {
    /** Base64-encoded 32-byte AES key, stored with `wrangler secret put`. */
    TOKEN_ENCRYPTION_KEY: string;
    /** Optional localhost-only identity for `wrangler dev`; never set in production. */
    LOCAL_DEV_EMAIL?: string;
  }
}
