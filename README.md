# @developersailor/express-auth

Secure, flexible authentication package for Express.js with JWT, refresh tokens, and role-based access control.

[![npm version](https://badge.fury.io/js/@developersailor%2Fexpress-auth.svg)](https://www.npmjs.com/package/@developersailor/express-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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

## Security Checklist

Before going to production:

- [ ] Use strong JWT secrets (min 32 chars, random)
- [ ] Enable HTTPS (secure cookies)
- [ ] Set up rate limiting
- [ ] Configure CORS properly
- [ ] Use environment variables for secrets
- [ ] Enable password validation rules
- [ ] Review token expiration times
- [ ] Set up refresh token cleanup
- [ ] Monitor for suspicious activity

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
