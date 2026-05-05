// binarybeachio per-app edge-identity validation helper.
//
// Implements the marker-cookie pattern from
// `docs/conventions/per-app-edge-identity-validation.md` for Next.js apps.
//
// Why a separate helper file: the host fork's own middleware.ts already
// handles auth + domain routing; this module is a small additive piece
// that the host imports and calls in its middleware chain.
//
// Behavior:
//   - On any request that carries an `X-Auth-Request-User` header (set by
//     oauth2-proxy at the edge), compare it to the `_bb_edge_sub` cookie.
//   - If they don't match, the user has switched identity at the edge —
//     clear the NextAuth session cookie + the marker cookie, redirect to
//     the app's login route so a fresh OIDC dance lands the new identity
//     in the app's local session.
//   - If the header is present but the cookie is missing (legacy session
//     pre-dating this patch), lazy-populate the cookie and pass through.
//   - If the header is absent (request didn't traverse oauth2-proxy:
//     healthchecks, public webhooks bypassing forward-auth), pass through.
//
// The middleware DOES NOT issue a sign-in itself; it only invalidates and
// redirects. The bridge handles re-authentication.

import { NextResponse, type NextRequest } from "next/server";

const EDGE_HEADER = "x-auth-request-user";
const MARKER_COOKIE = "_bb_edge_sub";

const NEXTAUTH_SESSION_COOKIES = [
  "__Secure-next-auth.session-token",
  "next-auth.session-token",
];

/** Paths that should NEVER be edge-validated. The middleware passes
 *  through unchanged for these. Order: most-specific to least-specific
 *  is irrelevant since this is a flat startsWith match. */
const SKIP_PREFIXES = [
  // OIDC / NextAuth callback-and-error endpoints
  "/api/auth/",
  // Bridge sign-in: edge-validation is meaningless because the bridge
  // route IS what sets the marker cookie.
  "/api/auth/sign-in-trusted",
  // Public client API for embedded SDKs (survey-take, identify-user,
  // displays). Survey respondents are not Zitadel users.
  "/api/v1/client/",
  // Embedded SDK static bundles
  "/js/",
  // Operator healthchecks (Docker / Coolify)
  "/api/health",
  "/health",
  // Static assets — Next will short-circuit these via matcher anyway,
  // but defense in depth.
  "/_next/static",
  "/_next/image",
  // Survey-take routes (formbricks survey URL pattern is `/s/<id>`)
  "/s/",
  // Storage proxy (delivers files; gating it would break public surveys)
  "/storage/",
];

export interface EdgeIdentityContext {
  /** Where to redirect when the marker doesn't match. Default
   *  `/auth/login` (Formbricks' sign-in page per
   *  `apps/web/modules/auth/lib/authOptions.ts:399`). */
  loginPath?: string;
  /** Domain to scope the marker cookie to. Leave undefined to bind to
   *  the request host (most apps want this). */
  cookieDomain?: string;
}

const shouldSkip = (pathname: string): boolean =>
  SKIP_PREFIXES.some((p) => pathname === p || pathname.startsWith(p));

/** Returns a NextResponse if the middleware should short-circuit (mismatch
 *  redirect, or lazy-populate). Returns `null` if the host middleware
 *  should continue with its own logic. */
export const enforceEdgeIdentity = (
  request: NextRequest,
  ctx: EdgeIdentityContext = {},
): NextResponse | null => {
  const pathname = request.nextUrl.pathname;
  if (shouldSkip(pathname)) return null;

  const edgeSub = request.headers.get(EDGE_HEADER);
  if (!edgeSub) {
    // No oauth2-proxy header — request is either pre-edge-gate (deploy
    // in progress, mismatched compose) or local-dev. Don't reject.
    return null;
  }

  const cookieSub = request.cookies.get(MARKER_COOKIE)?.value;

  if (!cookieSub) {
    // Legacy session pre-dating this patch (or a session minted outside
    // the trusted-JWT route). Lazy-populate so subsequent requests are
    // guarded; pass through.
    const passthrough = NextResponse.next();
    passthrough.cookies.set({
      name: MARKER_COOKIE,
      value: edgeSub,
      httpOnly: true,
      secure: request.nextUrl.protocol === "https:",
      sameSite: "lax",
      path: "/",
      domain: ctx.cookieDomain,
    });
    return passthrough;
  }

  if (cookieSub === edgeSub) {
    // Healthy: identities match. Host middleware should continue.
    return null;
  }

  // Mismatch — invalidate everything and bounce to login. The bridge
  // bypass redirect on /auth/login (when configured in the compose's
  // Traefik regex) sends the user through the bridge, which mints a
  // fresh JWT and the trusted route sets a new marker.
  const loginUrl = new URL(ctx.loginPath ?? "/auth/login", request.nextUrl.origin);
  loginUrl.searchParams.set("bb_edge_swap", "1");
  const response = NextResponse.redirect(loginUrl);
  response.cookies.set({
    name: MARKER_COOKIE,
    value: "",
    expires: new Date(0),
    path: "/",
    domain: ctx.cookieDomain,
  });
  for (const name of NEXTAUTH_SESSION_COOKIES) {
    response.cookies.set({
      name,
      value: "",
      expires: new Date(0),
      path: "/",
      domain: ctx.cookieDomain,
    });
  }
  return response;
};
