# Changelog

## Unreleased

### Security

- Refresh tokens are now hashed before being stored in the configured repository by default.
  Existing applications that previously stored raw refresh tokens will require users to log in again after upgrading, because old raw token records will no longer match the hashed lookup value.
  To temporarily keep the old behavior during a migration, set `hashRefreshTokens: false`.

### Fixed

- Public registration no longer trusts `roles` from the request body by default.
- Refresh token database expiry and cookie `maxAge` now follow `refreshTokenExpiresIn`.
- `loadUserOnRequest: true` now rejects deleted or inactive users instead of falling back to stale JWT payload data.
- Refresh token rotation can now use the optional repository `consumeToken` method for atomic one-time token use.
