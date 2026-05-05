# bb-formbricks-fork — manual smoke tests

Unofficial walkthroughs to run after a deploy. Not Vitest, not Playwright — just things you click through with the dev tools open.

## 0. Pre-flight (one-time per build)

- [ ] Image pulled by Coolify; container is `healthy` per `docker ps`.
- [ ] `https://formbricks.binarybeach.io/api/health` returns 200 from a public curl (this path bypasses oauth-required per the public Traefik router).
- [ ] `https://formbricks.binarybeach.io/api/auth/sign-in-trusted` (no params) returns 400 `{"error":"missing token query param"}` — proves the route is wired and reachable without the token, but rejects unauthenticated probes.
- [ ] Coolify env shows `ENTERPRISE_LICENSE_KEY` is **NOT** set. (If it is set, the EE OIDC providers would also try to register and the auth flow could behave unpredictably.)

## 1. Bridge handoff (the golden path)

In an incognito window:

1. Visit `https://formbricks.binarybeach.io/`.
2. Expect: 302 chain through `bridge.binarybeach.io/handoff?app=formbricks...` → Zitadel sign-in (if no edge session) → `/api/auth/sign-in-trusted?token=...&rd=...` → land at the Formbricks dashboard.
3. Open dev tools → Application → Cookies. Expect:
   - `_bb_oauth2` on `.binarybeach.io` (the edge session)
   - `__Secure-next-auth.session-token` on `formbricks.binarybeach.io` (the NextAuth session — bridge-minted)
   - `_bb_edge_sub` on `formbricks.binarybeach.io` (the marker cookie matching `X-Auth-Request-User`)
4. Open Formbricks → top-right user menu → Organizations. Expect: one Org named `<your name>'s Organization`, you are Owner. (This is the auto-create-on-first-login from the Bucket 4 route.)

## 2. The native Formbricks login form is never rendered

1. In incognito, visit `https://formbricks.binarybeach.io/auth/login` directly.
2. Expect: 302 to `bridge.binarybeach.io/handoff?app=formbricks&tenant=binarybeach&rd=https%3A%2F%2Fformbricks.binarybeach.io%2F` — caught by the `formbricks-signin-redirect` Traefik regex.
3. NOT expected: the actual NextAuth sign-in page rendering for any visible duration.

## 3. JWT replay protection

1. Sign in once (per smoke test 1) — capture the `?token=<jwt>&rd=...` URL from the redirect chain (dev tools Network tab).
2. Open a new incognito window.
3. Paste that exact URL.
4. Expect: 401 `{"error":"token replayed"}` (jti was already consumed in shared-redis on the first use, even though the JWT signature + exp would still validate).
5. If you don't see 401 — check that `REDIS_URL` is set in the formbricks Coolify env and the container can reach `shared-redis`. Soft-fail on Redis was deliberate (degraded > outage), but it means lab testing replay needs Redis up.

## 4. Edge-identity validation (per-app marker cookie)

This requires two Zitadel users you can sign in as.

1. Sign in as user A (smoke test 1). Land in Formbricks.
2. In another tab, hit `https://bridge.binarybeach.io/switch-account?rd=https://formbricks.binarybeach.io/`. Pick user B from the Zitadel account picker.
3. Return to the original Formbricks tab. Refresh.
4. Expect: redirect to `/auth/login?bb_edge_swap=1` → bridge → Zitadel session is now B's → trusted route mints a fresh session for B → land back in Formbricks as user B.
5. Verify: A's data is not visible. The user-menu now shows B.

## 5. R2 upload (Patch B verification)

1. Inside Formbricks, create a new survey with a "File upload" question.
2. Take the survey via the Preview button. Upload a small image (PNG, < 1MB).
3. Open dev tools Network tab BEFORE clicking submit. Expect to see:
   - `POST /api/v1/client/<envId>/storage` returning JSON with `signedUrl` (an R2 URL ending in `.r2.cloudflarestorage.com/...`), `fileUrl`, but NO `presignedFields`.
   - `PUT <signedUrl>` with `Content-Type: image/png` (or whatever) and request body = the raw file blob. Returns 200 from R2.
4. Verify the uploaded file is reachable via `fileUrl` (which goes through Formbricks' own `/storage/...` proxy, not directly to R2).

## 6. Embedded SDK survey-take (public bypass)

1. Get a survey's public link: `https://formbricks.binarybeach.io/s/<survey-id>`.
2. Visit it from an incognito window with NO Zitadel session (clear `_bb_oauth2` cookie).
3. Expect: the survey loads. NO redirect to Zitadel. NO 401.
4. This proves the `formbricks-public` Traefik router (priority 200) is catching `/s/*` before the `formbricks-signin-redirect` middleware has a chance to fire.

## 7. Sign-out (synced)

1. Sign in (smoke test 1).
2. Click sign-out in Formbricks → expect navigation to `/auth/logout` → expect chain through `bridge.binarybeach.io/logout` → expect Zitadel back-channel end_session → land somewhere unauthenticated.
3. Visit `https://formbricks.binarybeach.io/` again. Expect: bridge bounces you back through Zitadel sign-in (no auto-skip from a stale session).
4. (Note: at the time of this fork's scaffolding, the platform-wide `/logout` synced flow may not be wired for Formbricks specifically. If clicking sign-out only clears the Formbricks session and leaves the edge session, that's the known gap — file as a follow-up: register Formbricks in the bridge's `/logout` handler.)

## 8. The "TODO before first build" callout in BINARYBEACHIO.md

Patch B deleted 5 upstream test files that mocked `createPresignedPost` and asserted `presignedFields` shapes. If a fresh `pnpm test` run says all-green, congrats — the build pipeline either skipped the deleted files cleanly, or upstream restructured those tests on a newer base than `v3.17.1`. If a fresh `pnpm test` blows up, that's likely a different test referencing the changed shape — search for `createPresignedPost` again, ensure the only hits are inside the patched `apps/web/lib/storage/service.ts`.

## When a test fails

Don't try to write a Vitest spec. Open dev tools, watch the Network tab, follow the redirect chain. The right diagnostic question is "did the cookie get set on the right origin" or "did the JWT signature verify against the bridge's published key" — both are visible in inspector + container logs (`docker logs <formbricks-container-uuid>`).

The bridge's verifier logs `[trusted-jwt]` lines for every fetch / verify. The trusted route logs `[bb-bridge]` lines. Grep both when in doubt.
