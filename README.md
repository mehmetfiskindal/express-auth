# @developersailor/express-auth

Secure, flexible authentication package for Express.js with JWT, refresh tokens, and role-based access control.

[![npm version](https://badge.fury.io/js/@developersailor%2Fexpress-auth.svg)](https://www.npmjs.com/package/@developersailor/express-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

See [CHANGELOG.md](./CHANGELOG.md) for release notes and migration guidance.

## Features

- 🔐 **JWT Authentication** - Secure access tokens with configurable expiration
- 🔄 **Refresh Token Rotation** - Secure refresh token handling with automatic rotation
- 👤 **Role-based Access Control** - Fine-grained permission system
- 🗄️ **Repository Pattern** - Database-agnostic design (bring your own ORM)
- 📝 **TypeScript** - Full type safety and IntelliSense support
- 🧪 **Test Adapters** - Built-in memory adapters for testing
- 🍪 **Cookie Support** - Secure httpOnly cookie handling
- 🎨 **Decorators** - Metadata decorators for route protection
- 🚀 **Production Ready** - Security best practices built-in

## Installation

```bash
npm install @developersailor/express-auth
```

Peer dependencies:
```bash
npm install express reflect-metadata
```

## Quick Start

```typescript
import 'reflect-metadata';
import express from 'express';
import { createAuthRouter, createAuthMiddleware, JWTService } from '@developersailor/express-auth';

const app = express();
app.use(express.json());

// Create auth router with your configuration
const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories: {
    userRepository: myUserRepository,
    refreshTokenRepository: myRefreshTokenRepository,
  },
});

app.use('/auth', authRouter);

// Protect routes
const jwtService = new JWTService({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
});

const authMiddleware = createAuthMiddleware(jwtService);

app.get('/api/protected', authMiddleware, (req, res) => {
  res.json({ message: 'This is protected' });
});
```

## Core Concepts

### Repository Pattern

This package uses the repository pattern, meaning you bring your own database implementation:

```typescript
import { UserRepository, RefreshTokenRepository, AuthUser } from '@developersailor/express-auth';

// Implement the interfaces with your ORM (Prisma, TypeORM, etc.)
class PrismaUserRepository implements UserRepository {
  async findByEmail(email: string): Promise<AuthUser | null> {
    // Your implementation
  }
  
  async findById(id: string): Promise<AuthUser | null> {
    // Your implementation
  }
  
  async createUser(data: { email: string; passwordHash: string }): Promise<AuthUser> {
    // Your implementation
  }
}
```

### Security Best Practices

This package follows security best practices:

- ✅ **No secrets in code** - All secrets passed via configuration
- ✅ **Strong password hashing** - bcrypt with configurable rounds
- ✅ **Token rotation** - Refresh tokens are rotated on each use
- ✅ **Hashed refresh token storage** - Refresh tokens are hashed before persistence by default
- ✅ **Generic error messages** - No information leakage
- ✅ **JWT best practices** - Algorithm explicitly set to HS256
- ✅ **Secure by default** - Secure cookie settings

## API Endpoints

The `createAuthRouter` creates the following endpoints:

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register new user | No |
| POST | `/auth/login` | Login and get tokens | No |
| POST | `/auth/refresh` | Refresh access token | No |
| POST | `/auth/logout` | Logout (revoke token) | No |
| POST | `/auth/logout-all` | Logout all devices | Yes |
| GET | `/auth/me` | Get current user | Yes |
| POST | `/auth/forgot-password` | Request a password reset token | No* |
| POST | `/auth/reset-password` | Reset password with a valid token | No* |
| POST | `/auth/mfa/setup` | Start MFA setup, get a TOTP secret | Yes* |
| POST | `/auth/mfa/enable` | Confirm setup, get backup codes | Yes* |
| POST | `/auth/mfa/disable` | Turn MFA off (requires password) | Yes* |
| POST | `/auth/mfa/verify` | Complete a login MFA challenge | No* |

\* Password reset and MFA routes are only registered if your `UserRepository` implements the optional `updateUser` (and, for password reset, `findByPasswordResetToken`) methods — see [Password Reset](#password-reset) and [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa).

## Configuration

```typescript
interface AuthConfig {
  // Required: JWT secrets (from environment variables)
  jwtSecret: string;
  refreshTokenSecret: string;
  
  // Optional: Token expiration
  accessTokenExpiresIn?: string | number;  // default: '15m'
  refreshTokenExpiresIn?: string | number; // default: '7d'
  
  // Required: Repositories
  repositories: {
    userRepository: UserRepository;
    refreshTokenRepository: RefreshTokenRepository;
  };

  // Optional: Registration configuration
  registration?: {
    defaultRoles?: string[];           // Default: ['user']
    allowRolesFromRequest?: boolean;   // Default: false
  };

  // Optional: Hash refresh tokens before repository storage
  // Default: true
  // Migration note: enabling this for apps with existing raw refresh token
  // records will require users to log in again.
  hashRefreshTokens?: boolean;
  
  // Optional: Authorization configuration
  authorization?: {
    getRoles?: (user: AuthUser) => string[];           // Default: (u) => u.roles || []
    getPermissions?: (user: AuthUser) => Permission[]; // Default: (u) => u.permissions || []
    loadUserOnRequest?: boolean;                       // Default: false
    userCacheTTL?: number;                             // Default: 60 (seconds)
    ownershipBypassRoles?: string[];                   // Default: ['admin']
    hierarchicalPermissions?: boolean;                 // Default: false
  };
  
  // Optional: Cookie settings
  cookie?: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    path?: string;
  };
  
  // Optional: Password validation rules
  passwordRules?: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecialChars?: boolean;
  };
  
  // Optional: Custom error messages
  errorMessages?: {
    invalidCredentials?: string;
    unauthorized?: string;
    forbidden?: string;
    tokenExpired?: string;
    invalidToken?: string;
  };
}
```

## Middleware

### Authentication Middleware

```typescript
import { createAuthMiddleware, JWTService } from '@developersailor/express-auth';

const jwtService = new JWTService({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
});

const authMiddleware = createAuthMiddleware(jwtService);

// Protect a route
app.get('/api/protected', authMiddleware, handler);
```

### Role-based Middleware

```typescript
import { requireRoles, requireAllRoles } from '@developersailor/express-auth';

// Require any of the roles
app.get('/api/admin', authMiddleware, requireRoles('admin', 'moderator'), handler);

// Require all roles
app.get('/api/super-admin', authMiddleware, requireAllRoles('admin', 'verified'), handler);

// Custom permission check
import { requirePermission } from '@developersailor/express-auth';

app.get('/api/custom', authMiddleware, requirePermission((user) => {
  return user.roles.includes('admin') || user.email.endsWith('@company.com');
}), handler);
```

### Permission-based Middleware

```typescript
import { requirePermissions, requireAllPermissions } from '@developersailor/express-auth';

// Require any of the permissions (herhangi biri yeterli)
app.get('/api/orders', 
  authMiddleware, 
  requirePermissions('order.read', 'order.admin'), 
  handler
);

// Require all permissions (hepsi gerekli)
app.get('/api/admin/orders', 
  authMiddleware, 
  requireAllPermissions('order.read', 'order.delete'), 
  handler
);

// Wildcard permissions
app.get('/api/users', 
  authMiddleware, 
  requirePermissions('user.*'), // matches user.read, user.write, etc.
  handler
);

// Combined role and permission check
import { requireRolesOrPermissions } from '@developersailor/express-auth';

app.delete('/api/users/:id', 
  authMiddleware, 
  requireRolesOrPermissions(['admin'], ['user.delete']), 
  handler
);
```

### Advanced Authorization Configuration

```typescript
const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories: { userRepository, refreshTokenRepository },
  
  // Authorization yapılandırması
  authorization: {
    // Rolleri nasıl okuyacağız?
    getRoles: (user) => user.roles || [],
    
    // Permission'ları nasıl okuyacağız?
    getPermissions: (user) => user.permissions || [],
    
    // Her request'te DB'den güncel kullanıcı çek?
    // true: Güvenli ama yavaş (cache ile iyileştirilir)
    // false: JWT payload'dan okur (hızlı ama güncel olmayabilir)
    loadUserOnRequest: true,
    
    // Cache süresi (saniye)
    userCacheTTL: 60,
    
    // Ownership kontrolünde bypass edilecek roller
    ownershipBypassRoles: ['admin', 'superuser'],
  },
});
```

### Ownership Control

```typescript
import { requireOwnership } from '@developersailor/express-auth';

// Kullanıcı sadece kendi kaynaklarına erişebilir
// Admin ve superuser rolleri bypass eder (config'den ayarlanabilir)
app.get('/api/users/:userId/orders', 
  authMiddleware, 
  requireOwnership((req) => req.params.userId),
  handler
);

// Özel bypass rolleri ile
app.get('/api/users/:userId/private', 
  authMiddleware, 
  requireOwnership(
    (req) => req.params.userId,
    ['admin', 'support'] // Bu roller bypass eder
  ),
  handler
);
```

## Decorators

```typescript
import { Protected, Public, Roles, Permissions } from '@developersailor/express-auth';

class UserController {
  @Protected()
  @Roles('admin')
  async getAllUsers() {
    // Only admins can access
  }
  
  @Protected()
  @Permissions('user.read', 'user.write')
  async manageUsers() {
    // Requires user.read OR user.write permission
  }
  
  @Protected()
  @Roles('admin')
  @Permissions('order.refund')
  async refundOrder() {
    // Requires admin role AND order.refund permission
  }
  
  @Public()
  async getPublicInfo() {
    // Anyone can access
  }
}
```

### Permission Formats

The package supports two permission formats:

**Flat Format (Default):**
```typescript
// JWT Payload
{
  "permissions": ["user.read", "user.write", "order.*"]
}

// Wildcard support
requirePermissions('user.*')  // Matches user.read, user.write, etc.
```

**Hierarchical Format:**
```typescript
// JWT Payload
{
  "permissions": {
    "user": { "read": true, "write": true },
    "order": { "read": true, "refund": true }
  }
}

// Enable in config
authorization: {
  hierarchicalPermissions: true
}
```

## Testing

Use the built-in memory adapters for testing:

```typescript
import { createMemoryRepositories } from '@developersailor/express-auth';

const { userRepository, refreshTokenRepository } = createMemoryRepositories();

const authRouter = createAuthRouter({
  jwtSecret: 'test-secret-min-32-chars-long!!!',
  refreshTokenSecret: 'another-test-secret-min-32-chars!!!',
  repositories: { userRepository, refreshTokenRepository },
});
```

## Database Support

This package is **database-agnostic** and works with any database through the repository pattern. We provide ready-to-use examples for popular databases:

| Database | ORM | Example Location |
|----------|-----|-----------------|
| **MongoDB** | Mongoose | `examples/express-mongodb/` |
| **MySQL** | TypeORM | `examples/express-mysql/` |
| **PostgreSQL** | Prisma | `examples/express-prisma/` |
| **MSSQL** | Sequelize | `examples/express-mssql/` |
| **SQLite** | Prisma | `examples/express-prisma/` |
| **In-Memory** | Built-in | Package built-in |

### Quick Start with Different Databases

#### MongoDB
```bash
cd examples/express-mongodb
npm install
# Start MongoDB, then:
npm run dev
```

#### MySQL
```bash
cd examples/express-mysql
npm install
# Setup MySQL database, then:
npm run db:sync
npm run dev
```

#### MSSQL
```bash
cd examples/express-mssql
npm install
# Setup SQL Server, then:
npm run db:sync
npm run dev
```

#### Prisma (PostgreSQL, MySQL, SQLite, SQL Server)
```bash
cd examples/express-prisma
npm install
npx prisma migrate dev
npm run dev
```

Read the [Database Adapter Guide](./docs/database-adapters.md) for detailed instructions on creating custom adapters.

> **Note:** All four examples enable `cookie: {...}` in their `AuthConfig`, so [CSRF Protection](#csrf-protection) (on by default) applies to their `/auth/refresh` endpoint for cookie-based clients.

## Examples

### Express + Prisma + OpenAPI

See the [express-prisma example](./examples/express-prisma) for a complete implementation with:
- Prisma ORM integration
- OpenAPI/Swagger documentation
- TypeScript decorators
- SQLite database
- JWT authentication

```bash
cd examples/express-prisma
npm install
npx prisma migrate dev
npm run dev
```

### OpenAPI Integration

The example includes OpenAPI decorator support:

```bash
# Swagger UI available at
http://localhost:3000/api-docs
```

## Environment Variables

```env
# Required
JWT_SECRET="your-super-secret-jwt-key-at-least-32-chars-long"
REFRESH_TOKEN_SECRET="your-different-super-secret-refresh-token-key"

# Database connection (your implementation)
DATABASE_URL="your-database-url"

# Optional
NODE_ENV=production
PORT=3000
```

### Generating Secrets

```bash
# Generate secure random strings
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## Rate Limiting

`createAuthRouter` applies rate limiting to `/register`, `/login`, and `/refresh` **by default** — 5 requests per 15 minutes per IP. No manual wiring is required.

Customize or disable it via `rateLimit` in `AuthConfig`:

```typescript
const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories,
  rateLimit: {
    // enabled: false,           // turn off entirely (not recommended in production)
    auth: {
      windowMs: 15 * 60 * 1000,  // 15 minutes
      maxRequests: 5,
    },
  },
});
```

This only covers the auth router's own endpoints. `createSecurityMiddleware` (from `@developersailor/express-auth`) can additionally be applied to the rest of your app for general-purpose rate limiting on non-auth routes.

## CSRF Protection

When cookie-based auth is enabled (`cookie` is set in `AuthConfig`), CSRF protection is **on by default** using the stateless double-submit cookie pattern:

1. On successful `/login` and `/refresh`, the server sets a non-httpOnly `csrfToken` cookie and also returns the token in the JSON response (`csrfToken` field).
2. When the client calls `/auth/refresh` **with the refresh token cookie**, it must echo the token back in the `X-CSRF-Token` header.
3. The server compares cookie and header with a constant-time check; a missing or mismatched token gets `403`.

The check only applies when the refresh token actually arrives via cookie. Clients that send the refresh token in the request body (mobile apps, server-to-server) are unaffected — they don't use ambient cookie authority, so there is no CSRF vector.

```typescript
// SPA example
const login = await fetch('/auth/login', { /* ... */ }).then(r => r.json());

// Later, refresh using the cookie + CSRF header:
await fetch('/auth/refresh', {
  method: 'POST',
  credentials: 'include',
  headers: { 'X-CSRF-Token': login.csrfToken }, // or read the csrfToken cookie
});
```

Configuration:

```typescript
const authRouter = createAuthRouter({
  // ...
  cookie: {},                    // cookie flow enables CSRF automatically
  csrf: {
    // enabled: false,           // opt out (not recommended for browser clients)
    // cookieName: 'csrfToken',  // default
    // headerName: 'x-csrf-token', // default; add custom names to CORS allowedHeaders
  },
});
```

Notes:

- Cookie flows require [`cookie-parser`](https://www.npmjs.com/package/cookie-parser) in your app (`app.use(cookieParser())`); the router reads `req.cookies`.
- The default `X-CSRF-Token` header is already in the CORS defaults' `allowedHeaders`. If you set a custom `headerName`, add it to your CORS config.
- `/logout` and `/logout-all` are protected by the `Authorization` Bearer header, which cross-site attackers cannot forge, so they don't need the CSRF check.

## Password Reset

`/auth/forgot-password` and `/auth/reset-password` are only registered if your `UserRepository` implements the optional `updateUser` **and** `findByPasswordResetToken` methods (the built-in `MemoryUserRepository` implements both). The package generates and validates reset tokens; **sending the actual email is your responsibility**, via the `passwordReset.onRequest` callback:

```typescript
const authRouter = createAuthRouter({
  // ...
  passwordReset: {
    tokenExpiresIn: 60 * 60 * 1000, // 1 hour (default)
    onRequest: async (user, token) => {
      // Send this token via your own mail service (SendGrid, SES, nodemailer, ...)
      const resetLink = `https://yourapp.com/reset-password?token=${token}`;
      await sendEmail(user.email, 'Reset your password', resetLink);
    },
  },
});
```

Flow:

```bash
# 1. Request a reset (always returns a generic message — doesn't reveal whether the email exists)
curl -X POST http://localhost:3000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# 2. User clicks the emailed link, submits the token + new password
curl -X POST http://localhost:3000/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "TOKEN_FROM_EMAIL", "newPassword": "NewSecurePass123!"}'
```

Notes:

- The response to `/forgot-password` is identical whether or not the email exists, to prevent user enumeration.
- Reset tokens are single-use, expire after `tokenExpiresIn` (default 1 hour), and are stored hashed (SHA-256) — never in plain text.
- On successful reset, **all of the user's existing refresh tokens are revoked** (`revokeAllUserTokens`), forcing re-login on every device.
- Applies your configured `passwordRules` (if any) to the new password, same as `/register`.

## Multi-Factor Authentication (MFA)

`/auth/mfa/*` routes are only registered if your `UserRepository` implements the optional `updateUser` method. MFA uses TOTP (Time-based One-Time Password, Google Authenticator / Authy compatible) via [`otplib`](https://www.npmjs.com/package/otplib), plus one-time backup codes.

```typescript
const authRouter = createAuthRouter({
  // ...
  mfa: {
    issuer: 'MyApp',       // shown in the authenticator app; default 'ExpressAuth'
    backupCodesCount: 10,  // default 10
  },
});
```

Setup flow (user must already be logged in):

```bash
# 1. Start setup — returns a secret + otpauth:// URI (render this as a QR code)
curl -X POST http://localhost:3000/auth/mfa/setup \
  -H "Authorization: Bearer ACCESS_TOKEN"
# => { "secret": "JBSWY3DPEHPK3PXP", "otpauthUrl": "otpauth://totp/MyApp:user@example.com?..." }

# 2. Confirm with a code from the authenticator app to actually enable MFA
curl -X POST http://localhost:3000/auth/mfa/enable \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
# => { "backupCodes": ["a1b2c-3d4e5", ...] }  -- shown ONCE, store them safely
```

Login flow once MFA is enabled:

```bash
# 1. Normal login returns a challenge instead of tokens
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "..."}'
# => { "mfaRequired": true, "challengeToken": "..." }

# 2. Complete the challenge with a TOTP code (or a backup code)
curl -X POST http://localhost:3000/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"challengeToken": "...", "code": "123456"}'
# => { "user": {...}, "tokens": {...} }
```

To turn MFA off:

```bash
curl -X POST http://localhost:3000/auth/mfa/disable \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "current-password"}'
```

Notes:

- The challenge token is short-lived (5 minutes) and only usable at `/auth/mfa/verify` — it cannot be used to access any other endpoint.
- Backup codes are single-use; each one is removed after it's consumed. Only the SHA-256 hash is stored. Prefer implementing `UserRepository.consumeMfaBackupCode` for atomic consumption under concurrency.
- `/mfa/setup` returns `409` if MFA is already enabled — disable first (password required). This prevents a stolen access token from turning MFA off via re-setup.
- Enabling or disabling MFA revokes all of the user's refresh tokens.
- `/mfa/verify` is rate-limited by IP (same as `/login`) **and** per user (same defaults: 5 / 15 min), limiting brute-force against stolen challenge tokens.
- User objects in API responses never include `mfaSecret`, backup-code hashes, or password-reset fields.

## Security Checklist

Before going to production:

- [x] Use strong JWT secrets (min 32 chars, random)
- [x] Enable HTTPS (secure cookies)
- [x] Rate limiting on auth endpoints (on by default, see [Rate Limiting](#rate-limiting))
- [x] CSRF protection for cookie flows (on by default, see [CSRF Protection](#csrf-protection))
- [x] Configure CORS properly
- [x] Use environment variables for secrets
- [x] Enable password validation rules
- [x] Review token expiration times
- [x] Set up refresh token cleanup
- [x] Monitor for suspicious activity
- [ ] Consider enabling MFA (see [Multi-Factor Authentication](#multi-factor-authentication-mfa)) — off by default, requires `UserRepository.updateUser`
- [ ] Consider enabling password reset (see [Password Reset](#password-reset)) — requires `UserRepository.updateUser` + `findByPasswordResetToken`, and you must supply an email-sending `onRequest` callback

## Type Exports

```typescript
import {
  // Types
  AuthUser,
  AuthConfig,
  UserRepository,
  RefreshTokenRepository,
  RefreshTokenRecord,
  JWTPayload,
  TokenPair,
  LoginResult,
  AuthenticatedRequest,
  RefreshResult,
  // Services
  JWTService,
  PasswordService,
  // Middleware
  createAuthMiddleware,
  createOptionalAuthMiddleware,
  requireRoles,
  requireAllRoles,
  requirePermission,
  requireOwnership,
  getUser,
  isAuthenticated,
  // Decorators
  Protected,
  Public,
  Roles,
  PublicRoute,
  // Routes
  createAuthRouter,
  // Adapters
  createMemoryRepositories,
  MemoryUserRepository,
  MemoryRefreshTokenRepository,
} from '@developersailor/express-auth';
```

## License

MIT © DeveloperSailor

## Contributing

Contributions are welcome! Please read the [contributing guide](./CONTRIBUTING.md) first.

## Support

- 📖 [Documentation](https://github.com/developersailor/express-auth#readme)
- 🐛 [Issue Tracker](https://github.com/developersailor/express-auth/issues)
- 💬 [Discussions](https://github.com/developersailor/express-auth/discussions)
