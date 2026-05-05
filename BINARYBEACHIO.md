# bb-formbricks-fork — binarybeachio Formbricks fork

This is the binarybeachio fork of [Formbricks](https://github.com/formbricks/formbricks) — an open-source survey/forms platform built on Next.js + Prisma + Postgres. The fork integrates Formbricks into the binarybeachio platform-architecture (`docs/architecture/01-platform-architecture.md`): Zitadel as identity provider via the auth-bridge, oauth2-proxy at the edge, Cloudflare R2 for storage.

The fork exists because Formbricks' free tier does not support generic OIDC — that capability lives in `apps/web/modules/ee/sso/` under a separate enterprise license. The fork is **Bucket 4** per the platform architecture: one new file (a trusted-JWT endpoint) added in AGPL-licensed space, plus a small set of upload-shape patches to make Formbricks' presigned-POST upload flow compatible with Cloudflare R2 (which returns HTTP 501 for the AWS S3 PostObject API).

## Upstream

| Field | Value |
|---|---|
| Project | Formbricks (open-source survey platform, Next.js) |
| Upstream repo | https://github.com/formbricks/formbricks |
| Upstream default branch | `main` |
| Currently integrated upstream version | **v3.17.1** |
| License | [AGPL-3.0-only](https://github.com/formbricks/formbricks/blob/main/LICENSE) for the main codebase, with `apps/web/modules/ee/` under a separate enterprise license, and `packages/{js,api,android,ios}/` under MIT |

`git log main..upstream` = upstream changes I haven't pulled in
`git log upstream..main` = binarybeachio's customizations

## License posture

- **AGPL §13 source-disclosure** is satisfied by the public Forgejo repo at `git.binarybeach.io/binarybeach/bb-formbricks-fork` plus the public GitHub mirror at `github.com/binaryBeachLLC/bb-formbricks-fork`. The fork is configured with `--public` on both sides for this reason (see `feedback_default_private_fork_visibility`).
- **`apps/web/modules/ee/` is treated as untouchable.** No file under that path is modified by this fork. The enterprise SSO/SAML code paths are runtime-disabled by leaving the env var `ENTERPRISE_LICENSE_KEY` unset — same posture as Activepieces' `AP_EDITION=ce`. The EE modules' top-level imports still execute (NextAuth's `authOptions.ts` imports `@/modules/ee/sso/lib/providers`), but the conditional registration `...(ENTERPRISE_LICENSE_KEY ? getSSOProviders() : [])` keeps them inert.
- **All binarybeachio modifications are in AGPL or MIT space**, additive where the platform architecture's "Bucket 4" rules require (the trusted-JWT route is a single new file), modifying-existing where storage compatibility requires (six files; same precedent as `bb-plane-fork`'s R2 patch per `feedback_s3_upload_postobject`).

## What's customized

| File | Change | License space | Lines |
|------|--------|---------------|-------|
| `.gitattributes` | LF endings pin so Windows clones don't crashloop the container build | additive | ~30 |
| `BINARYBEACHIO.md` | This file | additive | ~120 |
| `_bb_shared/trusted-jwt-verifier.ts` | Vendored bridge JWT-verifier (RS256/EdDSA, jti single-use via Redis SETNX, public key fetched from `https://bridge.binarybeach.io/.well-known/bb-bridge.pub.pem`). Per `feedback_bridge_pubkey_via_url_not_env` — env-write through Coolify corrupts PEMs, so the verifier always fetches from the bridge | additive | ~180 |
| `apps/web/app/api/auth/sign-in-trusted/route.ts` | **NEW (Bucket 4 trusted-JWT endpoint).** POST handler that: validates the bridge JWT, enforces jti single-use, upserts `User` with `identityProvider=openid` and `identityProviderAccountId=<sub>`, ensures the user has at least one `Membership` (auto-creates an Organization on first sign-in, gated by an env flag mirroring `getIsMultiOrgEnabled` semantics), inserts a `Session` row, sets the `__Secure-next-auth.session-token` cookie + the `_bb_edge_sub` marker cookie per `docs/conventions/per-app-edge-identity-validation.md`, redirects | additive | ~220 |
| `apps/web/middleware.ts` | **NEW (edge-identity validation).** Next.js root middleware implementing the `_bb_edge_sub` marker cookie pattern. Compares `X-Auth-Request-User` (injected by oauth2-proxy at the edge) against the `_bb_edge_sub` cookie set by the trusted-JWT route. On mismatch, clears the NextAuth session cookie + marker and redirects to `/auth/login?bb_edge_swap=1` so the bridge takes the user through SSO again. Skip-paths: `/api/auth/*`, `/api/v1/client/*`, `/js/*`, `/api/health`, `/_next/static/*`, public survey paths (`/s/[surveyId]`) | additive | ~120 |
| `packages/storage/src/service.ts` | **R2 compatibility.** Replace `createPresignedPost` (S3 PostObject — R2 returns 501) with `getSignedUrl(s3Client, new PutObjectCommand({...}))`. Returned shape changes from `{ signedUrl, fields }` to `{ signedUrl, contentType }` | modification | ~15 |
| `packages/types/storage.ts` | Drop `presignedFields` from `TGetSignedUrlForS3UploadResponse`; add `contentType` | modification | ~3 |
| `apps/web/modules/storage/service.ts` | Pass `contentType` through; drop `presignedFields` from return | modification | ~5 |
| `apps/web/modules/storage/file-upload.ts` | Switch the web admin uploader from `fetch(signedUrl, { method: 'POST', body: FormData })` to `fetch(signedUrl, { method: 'PUT', body: blob, headers: { 'Content-Type': contentType } })`. Drop the FormData/base64 round-trip — PUT takes the raw blob | modification | ~30 |
| `apps/web/app/api/v1/management/storage/route.ts` | API response shape: drop `presignedFields`, add `contentType` | modification | ~3 |
| `apps/web/app/api/v1/client/[environmentId]/storage/route.ts` | Same as above for the client-API uploader endpoint | modification | ~3 |
| `packages/surveys/src/lib/api-client.ts` | Switch the survey-respondent SDK uploader from FormData POST to raw-blob PUT | modification | ~25 |

## TODO before first build

Patch B (R2 presigned PUT) changes the response shape of `getS3UploadSignedUrl` and the upload behavior in three client uploaders. **Five test files reference the old `createPresignedPost` mock + `presignedFields` shape** and will fail when the test suite runs:

- `apps/web/lib/storage/service.test.ts`
- `apps/web/app/lib/fileUpload.test.ts`
- `apps/web/app/api/v1/client/[environmentId]/storage/lib/uploadPrivateFile.test.ts`
- `packages/js-core/src/lib/common/tests/file-upload.test.ts`
- `packages/surveys/src/lib/api-client.test.ts`

Each needs to be updated to mock `getSignedUrl` from `@aws-sdk/s3-request-presigner` (instead of `createPresignedPost` from `@aws-sdk/s3-presigned-post`) and expect the new return shape `{ signedUrl, fileUrl }` (no `presignedFields`). The local-storage path's tests are unchanged — only the S3 path's expectations move.

This is a one-time cost at fork time. Upstream may eventually accept the PUT-vs-POST patch as a self-host knob, at which point our diff (and the related test updates) folds into upstream.

## Tag history

| Tag | Status | What changed |
|---|---|---|
| `v3.17.1-mine.1` | active | Initial fork tag. Adds `.gitattributes` (LF pin) + `BINARYBEACHIO.md` + `_bb_shared/trusted-jwt-verifier.ts` + `apps/web/app/api/auth/sign-in-trusted/route.ts` (Bucket 4 trusted-JWT endpoint) + `apps/web/middleware.ts` (edge-identity validation) + R2 PUT patches across `packages/storage`, `apps/web/modules/storage`, `apps/web/app/api/v1/.../storage`, `packages/surveys`. |

## Refresh from upstream

When a new upstream version is released:

```sh
cd C:\Users\maxwe\GitHubRepos\bb-formbricks-fork

# Pull the latest from upstream
git fetch upstream --tags
git checkout upstream
git merge --ff-only upstream/main
git push origin upstream

# Bump main to the new upstream tag and re-apply our patches
git checkout main
git rebase upstream
# Resolve conflicts in any of the 6 storage-shape files (the additive
# files at /api/auth/sign-in-trusted/, /middleware.ts, /_bb_shared/ never
# conflict because upstream doesn't touch those paths).
git push origin main --force-with-lease

# Build new image
docker build -t git.binarybeach.io/binarybeach/bb-formbricks-fork:v<X.Y.Z>-mine.1 .
docker push git.binarybeach.io/binarybeach/bb-formbricks-fork:v<X.Y.Z>-mine.1
```

The upstream-able patches (R2 PUT compatibility) could be filed as a Formbricks PR; until that lands, the diff stays in our tree.

## Why we forked instead of running upstream's image

Three reasons:

1. **Bucket 4 trusted-JWT requires a fork.** Formbricks' built-in OIDC support is enterprise-licensed; without a commercial license, the only license-clean way to integrate with our auth-bridge is a new endpoint in AGPL-space.
2. **R2 storage requires a fork.** Formbricks' upstream upload uses S3 PostObject, which Cloudflare R2 returns HTTP 501 for. We use R2 portfolio-wide; switching Formbricks specifically to AWS S3 to avoid the patch isn't aligned with our infrastructure pattern.
3. **AGPL §13 obligation is met by publishing the fork** publicly anyway, so there's no marginal compliance cost to going Path B.
