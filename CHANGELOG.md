# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-07-30

### Added
- **Password reset flow**: `POST /auth/forgot-password` and `POST /auth/reset-password`. The package generates/validates single-use, hashed (SHA-256), expiring reset tokens; sending the actual email is left to the host app via a new `passwordReset.onRequest(user, token)` config callback. Resetting a password revokes all of the user's existing refresh tokens. `/forgot-password` always returns the same generic message regardless of whether the email exists (no user enumeration).
- **MFA (TOTP) support** via [`otplib`](https://www.npmjs.com/package/otplib) (new runtime dependency), Google Authenticator/Authy compatible:
  - `POST /auth/mfa/setup`, `POST /auth/mfa/enable`, `POST /auth/mfa/disable` (all require an authenticated user).
  - Two-step login challenge: when a user has MFA enabled, `/auth/login` returns `{ mfaRequired: true, challengeToken }` instead of tokens; `POST /auth/mfa/verify` completes the login with a TOTP code or a single-use backup code.
  - New short-lived `mfa_challenge` JWT token type (5 minutes), scoped only to `/auth/mfa/verify`.
  - 10 single-use backup codes generated on enable, stored as SHA-256 hashes only, shown once in the `/mfa/enable` response.
- New optional `UserRepository` methods: `updateUser(userId, data)` and `findByPasswordResetToken(tokenHash)`. **Both password reset and MFA routes are only registered on the router if the provided repository implements the methods they need** — no error, no crash, the routes simply don't exist if unsupported. `MemoryUserRepository` implements both.
- New `AuthConfig` fields: `passwordReset` (`tokenExpiresIn`, `onRequest`) and `mfa` (`issuer`, `backupCodesCount`).
- New exported services: `MFAService`/`createMFAService`, `PasswordResetService`/`createPasswordResetService`.
- New `AuthUser` fields (all optional, populated automatically by the package): `passwordResetTokenHash`, `passwordResetExpiresAt`, `mfaEnabled`, `mfaSecret`, `mfaBackupCodeHashes`.
- README "Password Reset" and "Multi-Factor Authentication (MFA)" sections; `docs/database-adapters.md` updated with the new optional interface methods.
- 3 new end-to-end tests: full MFA setup→enable→challenge→verify flow (incl. backup code single-use), password reset flow with session revocation, and forgot-password enumeration-safety check.

### Fixed
- **MFA setup bypass**: `POST /auth/mfa/setup` now returns `409` when MFA is already enabled, so a stolen access token cannot disable MFA by starting a new setup.
- **Sensitive field leakage**: API responses (`/login`, `/me`, `/mfa/verify`, password-reset callbacks) now strip `mfaSecret`, `mfaBackupCodeHashes`, `passwordResetTokenHash`, and `passwordResetExpiresAt` — not only `passwordHash`.
- **Session revocation on MFA change**: enabling or disabling MFA revokes all of the user's refresh tokens.
- **Atomic MFA backup codes**: optional `UserRepository.consumeMfaBackupCode`; implemented in `MemoryUserRepository` to prevent single-use codes being redeemed twice under concurrency.
- **Per-user MFA verify rate limiting**: `/auth/mfa/verify` applies an additional user-scoped limit (same defaults as auth rate limit) and records failed attempts in `SecurityMonitor`.

- Refactored `/login` and `/refresh` to share a single `issueAuthTokens` helper for token generation + cookie/CSRF issuance, removing ~30 lines of duplication and one class of drift risk between the two flows.

This release is purely additive — no existing config, routes, or repository behavior changes for users who don't opt into `passwordReset`/`mfa` or implement the new optional repository methods.

## [2.0.0] - 2026-07-30

### BREAKING CHANGES
- **CSRF protection is now enabled by default for cookie-based auth flows.** When `cookie` is configured, `/auth/refresh` requests that carry the refresh token via cookie must now include a matching `X-CSRF-Token` header, or they receive `403`.
  - **Migration**: read the `csrfToken` field returned by `/login` and `/refresh` (also set as a non-httpOnly `csrfToken` cookie) and send it back in the `X-CSRF-Token` header on refresh requests.
  - **Opt-out**: set `csrf: { enabled: false }` in `AuthConfig` to restore the old behavior.
  - Clients that send the refresh token in the request body (mobile/API clients) are **not affected**.

### Added
- New `CSRFService` / `createCSRFService` (double-submit cookie pattern, stateless, constant-time comparison via `crypto.timingSafeEqual`) exported from the package.
- New `csrf` option in `AuthConfig` (`enabled`, `cookieName`, `headerName`).
- `/login` and `/refresh` responses now include a `csrfToken` field when cookie flow + CSRF are active; `/logout` and `/logout-all` clear the CSRF cookie.
- Three new end-to-end CSRF tests (missing token → 403, valid token → 200 + rotation, opt-out → 200).
- README "CSRF Protection" section with SPA integration example and `cookie-parser` requirement note.

## [1.1.0] - 2026-07-30

### Added
- Rate limiting now enabled **by default** on `/register`, `/login`, and `/refresh` endpoints (5 requests per 15 minutes per IP). Can be customized or disabled via `AuthConfig.rateLimit` option.
- GitHub Actions CI pipeline: lint, test, build, and audit on push and pull requests (Node 18.x/20.x/22.x matrix).
- Dependabot configuration for automated dependency updates (weekly, minor/patch grouped).
- New test case for rate-limit functionality to verify 429 responses.
- Jest `testTimeout` configuration (15s) to support slower CI runners and bcrypt hashing overhead on Node 18.x.

### Fixed
- **Critical bug in `RateLimitService`**: `defaultHandler` method was not bound when assigned to config, causing `TypeError` when rate limit was exceeded (now properly bound via `.bind(this)`).
- ESLint configuration: migrated from legacy `.eslintrc.js` to flat config (`eslint.config.js`) for ESLint 10.x compatibility.
- TypeScript configuration: updated `moduleResolution` and `ignoreDeprecations` to support TypeScript 6.0.3 (until `@typescript-eslint` supports TS 7.x).
- Removed deprecated `@types/bcryptjs` (bcryptjs@3.x now ships its own type definitions).

### Changed
- Upgrade dependencies:
  - `@typescript-eslint/eslint-plugin` and `@typescript-eslint/parser` from 8.32.0 to 8.65.0
  - `eslint` from 9.26.0 to 10.8.0
  - `jest` from 29.7.0 to 30.4.2
  - `ts-jest` from 29.3.2 to 29.4.12
  - `bcryptjs` from 2.4.3 to 3.0.3
  - `typescript` from 5.9.3 to 6.0.3
  - Added `@eslint/js` and `globals` as devDependencies for ESLint 10 flat config.
- `package-lock.json` now committed to repository (was in `.gitignore`), ensuring reproducible CI builds.
- Updated README.md with "Rate Limiting" section documenting default behavior and configuration examples.

### Security
- Fixed npm audit vulnerabilities (33 initially, 0 remaining):
  - Resolved dependency chain issues through version upgrades and `overrides` (brace-expansion).
  - All tests, lint, build, and audit steps now enforced in CI to prevent silent regressions.

## [1.0.2] - Previous releases

### Security

- Refresh tokens are now hashed before being stored in the configured repository by default.
  Existing applications that previously stored raw refresh tokens will require users to log in again after upgrading, because old raw token records will no longer match the hashed lookup value.
  To temporarily keep the old behavior during a migration, set `hashRefreshTokens: false`.

### Fixed

- Public registration no longer trusts `roles` from the request body by default.
- Refresh token database expiry and cookie `maxAge` now follow `refreshTokenExpiresIn`.
- `loadUserOnRequest: true` now rejects deleted or inactive users instead of falling back to stale JWT payload data.
- Refresh token rotation can now use the optional repository `consumeToken` method for atomic one-time token use.
