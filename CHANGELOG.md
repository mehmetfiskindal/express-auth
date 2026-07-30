# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
