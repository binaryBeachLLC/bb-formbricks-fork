// binarybeachio Bucket 4 trusted-JWT sign-in endpoint.
//
// This file is the **only** place in the fork that bridges binarybeachio's
// auth-bridge into Formbricks' NextAuth-managed session model. It is
// additive (a new route, no upstream files modified) and lives entirely in
// AGPL-licensed space — `apps/web/modules/ee/` is not touched.
//
// SESSION-STRATEGY NOTE (v3.17.1): Formbricks v3.17.1 uses NextAuth's JWT
// session strategy (default — no `strategy:` field in authOptions.ts:292).
// The session cookie is a JWE-encrypted JWT signed with NEXTAUTH_SECRET; no
// DB Session row. We mint a compatible JWT via `encode()` from
// `next-auth/jwt` and set it as `__Secure-next-auth.session-token`.
// On the next request, NextAuth's jwt() callback (authOptions.ts:296)
// hydrates the token with `profile` and `isActive` from the User row.
//
// FLOW (GET-with-token, mirrors bb-plane-fork's trusted view):
//   1. Bridge dispatcher resolves the tenant, runs the per-tenant email
//      allowlist, mints an RS256 JWT with claims:
//        { sub, email, name?, groups?, jti, iat, exp, iss=bb-bridge,
//          aud=formbricks }
//      and 302s the browser to:
//        https://formbricks.binarybeach.io/api/auth/sign-in-trusted
//          ?token=<jwt>&rd=<original-target>
//   2. This handler verifies signature + iss/aud/exp via TrustedJwtVerifier
//      (which fetches the bridge's public PEM from /.well-known on first
//      use). Failure → 401.
//   3. We enforce jti single-use via Redis SETNX with TTL =
//      (exp - now) + 30s. Replay attempts inside the JWT's lifetime are
//      rejected (the JWT exp is short — bridge default 60s — but jti
//      catches the case of a leaked URL inside that window).
//   4. We `prisma.user.upsert({email})` — bridge-created users get
//      identityProvider='openid' and identityProviderAccountId=<sub>.
//      User.password stays null (User.password is nullable in the
//      Prisma schema; no auto-generated bridge-marker that could later
//      be confused for a real password).
//   5. If the user has zero memberships, auto-create an Organization
//      named "<name>'s Organization" + Membership(role=owner). Mirrors
//      the upstream signup flow's `handleOrganizationCreation`. Gated
//      by env BB_BRIDGE_AUTO_CREATE_ORG (default true).
//   6. INSERT a `Session` row directly via Prisma. Formbricks uses
//      `session.strategy: "database"` (apps/web/modules/auth/lib/
//      authOptions.ts:329), so a Session row with a random sessionToken
//      is all NextAuth needs to recognize the user as logged in on the
//      next request — no custom NextAuth provider, no callback hijack.
//   7. Respond with a 302 to the sanitized rd= path. Set-Cookie carries:
//      - `__Secure-next-auth.session-token` (HTTPS) or
//        `next-auth.session-token` — the standard NextAuth name
//      - `_bb_edge_sub` — the per-app edge-identity marker per
//        docs/conventions/per-app-edge-identity-validation.md
//
// Why GET-with-token (not POST):
//   - Same-origin cookie scope: cookies set by this route bind to
//     formbricks.binarybeach.io. The bridge can't set cookies for
//     formbricks.binarybeach.io from bridge.binarybeach.io.
//   - Single round-trip. No bridge-app server-to-server dependency at
//     sign-in time.
//   - jti single-use + 60s exp + HTTPS-only matches OAuth's
//     authorization-code security model. URL-leakage threat is bounded.
//
// NOT-DONE on purpose:
//   - We don't call NextAuth's `signIn()` callback. Doing so would route
//     through the EE-licensed `handleSsoCallback` (authOptions.ts:374,
//     gated on ENTERPRISE_LICENSE_KEY). For the bridge flow we want the
//     user-create path that doesn't depend on EE.
//   - We don't email-verify. The bridge already validated the user
//     against Zitadel; double-verification serves no purpose. We set
//     `emailVerified=now` on user-creation so the regular session
//     callback (which checks emailVerified for the credentials provider)
//     is satisfied if the user ever interacts with that path.

import { Prisma } from "@prisma/client";
import { encode as encodeJwt } from "next-auth/jwt";
import { type NextRequest, NextResponse } from "next/server";
import { prisma } from "@formbricks/database";
import { logger } from "@formbricks/logger";
import { TrustedJwtVerifier, type VerifiedClaims } from "@/_bb_shared/trusted-jwt-verifier";
import { BILLING_LIMITS, PROJECT_FEATURE_KEYS } from "@/lib/constants";
import { NEXTAUTH_SECRET, SESSION_MAX_AGE, WEBAPP_URL } from "@/lib/constants";
import { getRedisClient } from "@/modules/cache/redis";

// ---- Configuration (env-driven, evaluated lazily) ----

const env = (name: string, fallback?: string): string => {
  const v = process.env[name];
  if (v && v.length > 0) return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`bb-bridge: required env ${name} is unset`);
};

let _verifier: TrustedJwtVerifier | undefined;
const verifier = (): TrustedJwtVerifier => {
  if (!_verifier) {
    _verifier = new TrustedJwtVerifier({
      bridgePublicKeyUrl: env(
        "BB_BRIDGE_PUBLIC_KEY_URL",
        "https://bridge.binarybeach.io/.well-known/bb-bridge.pub.pem",
      ),
      issuer: env("BB_BRIDGE_ISSUER", "bb-bridge"),
      audience: env("BB_BRIDGE_AUDIENCE", "formbricks"),
      log: (level, msg, meta) =>
        logger[level === "info" ? "info" : level]({ meta }, `[bb-bridge] ${msg}`),
    });
  }
  return _verifier;
};

const autoCreateOrg = (): boolean =>
  (process.env.BB_BRIDGE_AUTO_CREATE_ORG ?? "true").toLowerCase() === "true";

// ---- Handler ----

export const GET = async (req: NextRequest): Promise<NextResponse> => {
  const url = req.nextUrl;
  const token = url.searchParams.get("token") ?? "";
  if (!token) {
    return NextResponse.json({ error: "missing token query param" }, { status: 400 });
  }

  let claims: VerifiedClaims;
  try {
    claims = await verifier().verify(token);
  } catch (err) {
    logger.warn({ err: (err as Error).message }, "[bb-bridge] JWT verification failed");
    return NextResponse.json({ error: "invalid token" }, { status: 401 });
  }

  if (!claims.email) {
    return NextResponse.json({ error: "token missing email claim" }, { status: 400 });
  }

  // jti single-use via Redis SETNX. Soft-fail open if Redis is down — the
  // JWT exp is short (bridge default 60s), so the replay window without
  // jti enforcement is bounded. We prefer a degraded-but-functional sign-
  // in to a hard outage on Redis blips.
  if (claims.jti) {
    const redis = getRedisClient();
    if (redis) {
      const nowSec = Math.floor(Date.now() / 1000);
      const ttlSec = Math.max(claims.exp - nowSec, 0) + 30;
      try {
        const result = await redis.set(`bb_bridge_jti:${claims.jti}`, "1", {
          NX: true,
          EX: ttlSec,
        });
        if (result !== "OK") {
          logger.warn({ jti: claims.jti }, "[bb-bridge] jti replay rejected");
          return NextResponse.json({ error: "token replayed" }, { status: 401 });
        }
      } catch (err) {
        logger.warn(
          { err: (err as Error).message, jti: claims.jti },
          "[bb-bridge] redis SETNX failed, proceeding without jti enforcement",
        );
      }
    }
  }

  const redirectTo = sanitizeRd(url.searchParams.get("rd"));

  // Upsert User + ensure membership + mint Session, all in one transaction.
  const email = claims.email.toLowerCase();
  const displayName =
    claims.name?.trim() ||
    [claims.first_name, claims.last_name].filter(Boolean).join(" ").trim() ||
    email.split("@")[0];

  let userId: string;
  let userIsActive: boolean;

  try {
    const result = await prisma.$transaction(async (tx) => {
      const user = await tx.user.upsert({
        where: { email },
        update: {
          identityProvider: "openid",
          identityProviderAccountId: claims.sub,
          isActive: true,
          lastLoginAt: new Date(),
        },
        create: {
          email,
          name: displayName.length > 0 ? displayName : email,
          emailVerified: new Date(),
          identityProvider: "openid",
          identityProviderAccountId: claims.sub,
          locale: "en-US",
          isActive: true,
          lastLoginAt: new Date(),
        },
        select: {
          id: true,
          name: true,
          isActive: true,
          memberships: { select: { organizationId: true } },
        },
      });

      if (user.memberships.length === 0 && autoCreateOrg()) {
        // Inline createOrganization + createMembership so they run inside
        // the same `tx`. The lib/{organization,membership}/service.ts
        // helpers use the outer `prisma` client and don't accept a tx
        // parameter; calling them here would cause a FK violation
        // because the User upsert isn't visible to the outer client
        // until the transaction commits.
        const org = await tx.organization.create({
          data: {
            name: `${user.name || email}'s Organization`,
            billing: {
              plan: PROJECT_FEATURE_KEYS.FREE,
              limits: {
                projects: BILLING_LIMITS.FREE.PROJECTS,
                monthly: {
                  responses: BILLING_LIMITS.FREE.RESPONSES,
                  miu: BILLING_LIMITS.FREE.MIU,
                },
              },
              stripeCustomerId: null,
              periodStart: new Date(),
              period: "monthly",
            },
          },
          select: { id: true },
        });
        await tx.membership.create({
          data: {
            userId: user.id,
            organizationId: org.id,
            role: "owner",
            accepted: true,
          },
        });
      }

      return { userId: user.id, isActive: user.isActive };
    });

    userId = result.userId;
    userIsActive = result.isActive;
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError) {
      logger.error({ code: err.code, msg: err.message }, "[bb-bridge] Prisma error during upsert");
    } else {
      logger.error({ err }, "[bb-bridge] unexpected error during sign-in");
    }
    return NextResponse.json({ error: "internal error" }, { status: 500 });
  }

  // Mint a NextAuth-compatible JWT. Formbricks v3.17.1 uses the JWT session
  // strategy (authOptions.ts:292 has only maxAge — no `strategy:` field, so
  // NextAuth defaults to JWT). The session cookie is a JWE encrypted with
  // NEXTAUTH_SECRET. We populate the same fields NextAuth's `jwt()`
  // callback would set (authOptions.ts:296):
  //   email      — the user's email (used by getUserByEmail in the callback)
  //   sub        — the user id (NextAuth standard)
  //   profile.id — what authOptions.ts's session() callback projects to
  //                session.user
  //   isActive   — set by the same callback
  // The next request after this trusted sign-in still hits the jwt()
  // callback which re-fetches the user; our pre-populated values let the
  // first render work without an extra round-trip.
  if (!NEXTAUTH_SECRET) {
    logger.error("[bb-bridge] NEXTAUTH_SECRET not set — cannot mint session");
    return NextResponse.json({ error: "server misconfigured" }, { status: 500 });
  }
  let sessionJwt: string;
  try {
    sessionJwt = await encodeJwt({
      token: {
        email,
        sub: userId,
        profile: { id: userId },
        isActive: userIsActive,
      },
      secret: NEXTAUTH_SECRET,
      maxAge: SESSION_MAX_AGE,
    });
  } catch (err) {
    logger.error({ err }, "[bb-bridge] failed to encode NextAuth JWT");
    return NextResponse.json({ error: "internal error" }, { status: 500 });
  }
  const sessionExpires = new Date(Date.now() + SESSION_MAX_AGE * 1000);

  logger.info(
    { userId, email, sub: claims.sub, redirectTo },
    "[bb-bridge] trusted sign-in completed",
  );

  // 302 to redirectTo with Set-Cookie. Both cookies:
  //   - __Secure-next-auth.session-token: NextAuth session cookie that
  //     the database adapter looks up against the Session table.
  //   - _bb_edge_sub: per-app edge-identity marker.
  const isSecure = (process.env.NEXTAUTH_URL ?? WEBAPP_URL ?? "").startsWith("https://");
  const cookieName = isSecure ? "__Secure-next-auth.session-token" : "next-auth.session-token";

  const response = NextResponse.redirect(redirectTo);
  response.cookies.set({
    name: cookieName,
    value: sessionJwt,
    expires: sessionExpires,
    httpOnly: true,
    secure: isSecure,
    sameSite: "lax",
    path: "/",
  });
  response.cookies.set({
    name: "_bb_edge_sub",
    value: claims.sub,
    httpOnly: true,
    secure: isSecure,
    sameSite: "lax",
    path: "/",
    // No expires — session cookie tied to browser lifetime per the convention.
  });

  return response;
};

const sanitizeRd = (rd: string | null): string => {
  if (!rd) return WEBAPP_URL || "/";
  try {
    const u = new URL(rd, WEBAPP_URL);
    const base = new URL(WEBAPP_URL);
    if (u.origin !== base.origin) {
      return WEBAPP_URL;
    }
    return u.toString();
  } catch {
    return WEBAPP_URL || "/";
  }
};

// Block POST so probes don't accidentally trigger logic.
export const POST = (): NextResponse =>
  NextResponse.json({ error: "method not allowed (use GET)" }, { status: 405 });
