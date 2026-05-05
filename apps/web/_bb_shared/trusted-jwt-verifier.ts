// binarybeachio shared trusted-JWT verifier.
//
// PORTABLE BETWEEN FORKS: this file is intended to be vendored verbatim into
// each fork that exposes a Bucket 4 trusted-JWT endpoint. It has zero
// dependencies on the host fork's app internals — only `jsonwebtoken` (which
// every Node fork pulls in anyway) and the standard `fetch` API.
//
// Why this module exists: the bridge mints RS256 JWTs signed with its
// BRIDGE_SIGNING_KEY. Earlier iterations passed the matching public key
// through each fork's env (BB_BRIDGE_PUBLIC_KEY). That route is fragile —
// Coolify's .env-write path escapes backslashes (`\` -> `\\`), so
// `\nMIIBIj...` in the source becomes `\\nMIIBIj...` in the consumer
// container. The defensive PEM parser then either fails (`secretOrPublicKey
// must be an asymmetric key when using RS256`) or silently corrupts the
// base64 (a stripped `n` is a valid base64 char and survives). One bridge
// failure mode, every fork's responsibility to defend against.
//
// This module replaces that pattern: forks fetch the bridge's public key
// over HTTP from `/.well-known/bb-bridge.pub.pem`, cache it, and refresh
// on verification failure. The PEM never traverses the env path.
//
// Threat model: the public key is, by definition, public. The bridge route
// is unauthenticated by design (it has its own Traefik priority router
// that bypasses oauth2-proxy). MITM is mitigated by HTTPS to
// `bridge.binarybeach.io` — for in-cluster URLs (http://auth-bridge-<uuid>)
// the network is the docker bridge network, trust-equivalent to env vars.
//
// Not implemented (deliberately): JWKS / kid rotation. We sign with one key
// at a time. When we eventually rotate, we can add a `kid` claim and serve
// a JWKS document at `/.well-known/jwks.json` — at that point this module
// gets a key-set abstraction. Today, one key, one fingerprint, simple.

import { verify as jwtVerify } from "jsonwebtoken";

export interface VerifiedClaims {
  sub: string;
  email: string;
  name?: string;
  first_name?: string;
  last_name?: string;
  groups?: string[];
  tenant?: string;
  jti?: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string | string[];
}

export interface TrustedJwtVerifierOptions {
  /** Full URL to the bridge's PEM endpoint, e.g.
   *  `https://bridge.binarybeach.io/.well-known/bb-bridge.pub.pem`. */
  bridgePublicKeyUrl: string;
  /** Expected `iss` claim. The bridge always uses `bb-bridge`. */
  issuer: string;
  /** Expected `aud` claim. Each fork picks its own audience string —
   *  AP uses `activepieces`, Plane uses `plane`, Formbricks uses
   *  `formbricks`. */
  audience: string;
  /** Clock skew tolerance in seconds. Default 30. */
  clockToleranceSeconds?: number;
  /** Soft-cache TTL for the fetched key, in milliseconds. After this the
   *  key is refetched on the next call (the previous value is also kept
   *  for fallback if the refetch fails). Default 5 min. */
  cacheTtlMs?: number;
  /** Optional logger. Defaults to console.warn. */
  log?: (level: "info" | "warn" | "error", msg: string, meta?: unknown) => void;
}

interface CachedKey {
  pem: string;
  fetchedAt: number;
}

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_CLOCK_TOLERANCE_S = 30;

export class TrustedJwtVerifier {
  private cache?: CachedKey;
  private inFlight?: Promise<string>;
  private readonly opts: Required<TrustedJwtVerifierOptions>;

  constructor(opts: TrustedJwtVerifierOptions) {
    this.opts = {
      cacheTtlMs: DEFAULT_CACHE_TTL_MS,
      clockToleranceSeconds: DEFAULT_CLOCK_TOLERANCE_S,
      log: (lvl, msg, meta) =>
        // eslint-disable-next-line no-console
        console[lvl === "info" ? "log" : lvl](`[trusted-jwt] ${msg}`, meta ?? ""),
      ...opts,
    };
  }

  /** Verify a JWT minted by the bridge. Returns the decoded claims on
   *  success; throws on failure. The caller is responsible for translating
   *  the throw into an HTTP response and for jti single-use tracking.
   *
   *  Behavior on signature failure: refetch the key once (in case the bridge
   *  rotated) and retry. Two consecutive signature failures = real failure.
   *  Other verify failures (expired, wrong issuer/audience, malformed) do
   *  NOT trigger a refetch — those are tampering or clock issues, not key
   *  drift. */
  async verify(token: string): Promise<VerifiedClaims> {
    const key = await this.getKey();
    try {
      return this.verifyWithKey(token, key);
    } catch (err) {
      if (this.isLikelyKeyDriftError(err)) {
        this.opts.log(
          "warn",
          "verify failed with possible key drift — refetching bridge public key",
          { err: (err as Error).message },
        );
        const fresh = await this.getKey({ forceRefresh: true });
        return this.verifyWithKey(token, fresh);
      }
      throw err;
    }
  }

  /** Expose the cached fingerprint for diagnostics. Computed lazily on
   *  first key fetch; logged on key load. */
  async getKeyFingerprint(): Promise<string> {
    const pem = await this.getKey();
    return sha256Hex(pemToDer(pem));
  }

  private verifyWithKey(token: string, pem: string): VerifiedClaims {
    return jwtVerify(token, pem, {
      algorithms: ["RS256"],
      issuer: this.opts.issuer,
      audience: this.opts.audience,
      clockTolerance: this.opts.clockToleranceSeconds,
    }) as VerifiedClaims;
  }

  private isLikelyKeyDriftError(err: unknown): boolean {
    const msg = err instanceof Error ? err.message : String(err);
    return msg === "invalid signature";
  }

  private async getKey(opts: { forceRefresh?: boolean } = {}): Promise<string> {
    const now = Date.now();
    if (!opts.forceRefresh && this.cache && now - this.cache.fetchedAt < this.opts.cacheTtlMs) {
      return this.cache.pem;
    }
    if (this.inFlight) {
      return this.inFlight;
    }
    this.inFlight = this.fetchKey()
      .then((pem) => {
        this.cache = { pem, fetchedAt: Date.now() };
        return pem;
      })
      .catch((err) => {
        if (this.cache) {
          this.opts.log("warn", "bridge public-key fetch failed, using stale cache", {
            err: (err as Error).message,
          });
          return this.cache.pem;
        }
        throw err;
      })
      .finally(() => {
        this.inFlight = undefined;
      });
    return this.inFlight;
  }

  private async fetchKey(): Promise<string> {
    const resp = await fetch(this.opts.bridgePublicKeyUrl, {
      headers: { accept: "application/x-pem-file, text/plain" },
    });
    if (!resp.ok) {
      throw new Error(
        `bridge public-key fetch failed: HTTP ${resp.status} from ${this.opts.bridgePublicKeyUrl}`,
      );
    }
    const pem = await resp.text();
    if (!pem.includes("-----BEGIN PUBLIC KEY-----")) {
      throw new Error(
        `bridge public-key fetch returned non-PEM body (first 80 chars: ${pem.slice(0, 80)})`,
      );
    }
    const fingerprint = resp.headers.get("x-bb-bridge-key-fingerprint");
    this.opts.log("info", "bridge public key fetched", {
      fingerprint,
      url: this.opts.bridgePublicKeyUrl,
    });
    return pem;
  }
}

// ---- internal helpers ----

function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(Buffer.from(base64, "base64"));
}

function sha256Hex(bytes: Uint8Array): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createHash } = require("crypto") as typeof import("crypto");
  return createHash("sha256").update(bytes).digest("hex");
}
