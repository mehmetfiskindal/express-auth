# Database Adapter Guide

This guide explains how to implement custom database adapters for `@developersailor/express-auth`. The package uses the repository pattern, allowing you to integrate with any database or ORM.

## Table of Contents

- [Overview](#overview)
- [Repository Interfaces](#repository-interfaces)
- [Available Examples](#available-examples)
- [Creating Custom Adapters](#creating-custom-adapters)
- [Best Practices](#best-practices)

## Overview

The auth package requires two repositories:

1. **UserRepository** - Manages user data (create, find, update)
2. **RefreshTokenRepository** - Manages refresh tokens (save, find, revoke, cleanup)

You implement these interfaces using your preferred database/ORM.

## Repository Interfaces

### UserRepository

```typescript
interface UserRepository {
  findByEmail(email: string): Promise<AuthUser | null>;
  findById(id: string): Promise<AuthUser | null>;
  createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser>;
  updatePassword?(userId: string, newPasswordHash: string): Promise<void>;
}
```

**AuthUser Interface:**

```typescript
interface AuthUser {
  id: string;
  email: string;
  passwordHash: string;
  roles?: string[];
  isActive?: boolean;
  [key: string]: unknown; // Allow additional fields
}
```

### RefreshTokenRepository

```typescript
interface RefreshTokenRepository {
  saveToken(record: RefreshTokenRecord): Promise<void>;
  findToken(token: string): Promise<RefreshTokenRecord | null>;
  revokeToken(token: string): Promise<void>;
  revokeAllUserTokens(userId: string): Promise<void>;
  cleanupExpiredTokens?(): Promise<void>;
}
```

**RefreshTokenRecord Interface:**

```typescript
interface RefreshTokenRecord {
  token: string;
  userId: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date;
}
```

## Available Examples

### ✅ MongoDB (Mongoose)

**Location:** `examples/express-mongodb/`

```typescript
import { MongoUserRepository, MongoRefreshTokenRepository } from './repositories';

const userRepository = new MongoUserRepository();
const refreshTokenRepository = new MongoRefreshTokenRepository();

const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories: {
    userRepository,
    refreshTokenRepository,
  },
});
```

**Key Features:**
- TTL index for automatic token cleanup
- Efficient queries with proper indexing
- Full MongoDB feature support

**Dependencies:**
```bash
npm install mongoose
```

### ✅ MySQL (TypeORM)

**Location:** `examples/express-mysql/`

```typescript
import { Repository } from 'typeorm';
import { MySQLUserRepository, MySQLRefreshTokenRepository } from './repositories';

const userRepository = new MySQLUserRepository(dataSource.getRepository(User));
const refreshTokenRepository = new MySQLRefreshTokenRepository(dataSource.getRepository(RefreshToken));

const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories: {
    userRepository,
    refreshTokenRepository,
  },
});
```

**Key Features:**
- Type-safe queries
- Automatic migration support
- Connection pooling

**Dependencies:**
```bash
npm install typeorm mysql2 reflect-metadata
```

### ✅ MSSQL (Sequelize)

**Location:** `examples/express-mssql/`

```typescript
import { MSSQLUserRepository, MSSQLRefreshTokenRepository } from './repositories';
import { initUserModel, initRefreshTokenModel } from './models';

const User = initUserModel(sequelize);
const RefreshToken = initRefreshTokenModel(sequelize);

const userRepository = new MSSQLUserRepository(User);
const refreshTokenRepository = new MSSQLRefreshTokenRepository(RefreshToken);

const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories: {
    userRepository,
    refreshTokenRepository,
  },
});
```

**Key Features:**
- Windows Authentication support
- Enterprise-grade connection management
- Transaction support

**Dependencies:**
```bash
npm install sequelize tedious mssql
```

### ✅ Prisma

**Location:** `examples/express-prisma/`

```typescript
import { PrismaUserRepository, PrismaRefreshTokenRepository } from './repositories';

const prisma = new PrismaClient();

const userRepository = new PrismaUserRepository(prisma);
const refreshTokenRepository = new PrismaRefreshTokenRepository(prisma);

const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories: {
    userRepository,
    refreshTokenRepository,
  },
});
```

**Key Features:**
- Type-safe database queries
- Auto-generated client
- Excellent DX

**Dependencies:**
```bash
npm install @prisma/client
npm install -D prisma
```

### ✅ In-Memory (Testing)

**Built-in:** Available from the package

```typescript
import { createMemoryRepositories } from '@developersailor/express-auth';

const { userRepository, refreshTokenRepository } = createMemoryRepositories();

// Perfect for unit testing!
```

## Creating Custom Adapters

### Step 1: Understand the Data Model

Your database should support:

**Users Table:**
- `id` (string/UUID)
- `email` (string, unique)
- `passwordHash` (string)
- `roles` (string array or comma-separated)
- `isActive` (boolean)
- `createdAt` (datetime)
- `updatedAt` (datetime)

**Refresh Tokens Table:**
- `token` (string, unique)
- `userId` (string, foreign key)
- `expiresAt` (datetime)
- `createdAt` (datetime)
- `revokedAt` (datetime, nullable)

### Step 2: Implement UserRepository

```typescript
import { AuthUser, UserRepository } from '@developersailor/express-auth';

export class CustomUserRepository implements UserRepository {
  constructor(private db: YourDatabaseClient) {}

  async findByEmail(email: string): Promise<AuthUser | null> {
    const user = await this.db.query(
      'SELECT * FROM users WHERE email = ?',
      [email.toLowerCase()]
    );
    
    if (!user) return null;
    
    return {
      id: user.id,
      email: user.email,
      passwordHash: user.password_hash,
      roles: user.roles.split(','),
      isActive: user.is_active,
    };
  }

  async findById(id: string): Promise<AuthUser | null> {
    // Your implementation
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser> {
    // Your implementation
  }
}
```

### Step 3: Implement RefreshTokenRepository

```typescript
import { RefreshTokenRepository, RefreshTokenRecord } from '@developersailor/express-auth';

export class CustomRefreshTokenRepository implements RefreshTokenRepository {
  constructor(private db: YourDatabaseClient) {}

  async saveToken(record: RefreshTokenRecord): Promise<void> {
    await this.db.query(
      'INSERT INTO refresh_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
      [record.token, record.userId, record.expiresAt, record.createdAt]
    );
  }

  async findToken(token: string): Promise<RefreshTokenRecord | null> {
    // Your implementation
  }

  async revokeToken(token: string): Promise<void> {
    // Your implementation
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    // Your implementation
  }
}
```

### Step 4: Use Your Adapters

```typescript
import { createAuthRouter } from '@developersailor/express-auth';
import { CustomUserRepository, CustomRefreshTokenRepository } from './repositories';

const userRepository = new CustomUserRepository(db);
const refreshTokenRepository = new CustomRefreshTokenRepository(db);

const authRouter = createAuthRouter({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  repositories: {
    userRepository,
    refreshTokenRepository,
  },
});

app.use('/auth', authRouter);
```

## Best Practices

### 1. Index Important Fields

```sql
-- Users table
CREATE INDEX idx_users_email ON users(email);

-- Refresh tokens table
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

### 2. Handle Case Sensitivity

Always normalize emails to lowercase:

```typescript
async findByEmail(email: string): Promise<AuthUser | null> {
  return this.db.users.findOne({ 
    email: email.toLowerCase() // 👈 Normalize
  });
}
```

### 3. Store Roles Efficiently

Option A: Array (PostgreSQL, MongoDB)
```typescript
roles: ['admin', 'moderator']
```

Option B: Comma-separated (MySQL, MSSQL)
```typescript
roles: 'admin,moderator'
// Parse: user.roles.split(',')
```

### 4. Cleanup Expired Tokens

Schedule regular cleanup jobs:

```typescript
// MongoDB: TTL index (automatic)
RefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Others: Periodic cleanup
setInterval(() => {
  refreshTokenRepository.cleanupExpiredTokens();
}, 24 * 60 * 60 * 1000); // Daily
```

### 5. Use Transactions

For critical operations:

```typescript
async revokeAllUserTokens(userId: string): Promise<void> {
  await this.db.transaction(async (trx) => {
    await trx('refresh_tokens')
      .where({ userId, revokedAt: null })
      .update({ revokedAt: new Date() });
  });
}
```

### 6. Error Handling

Always handle database errors gracefully:

```typescript
async findById(id: string): Promise<AuthUser | null> {
  try {
    const user = await this.db.users.findById(id);
    return user ? this.toAuthUser(user) : null;
  } catch (error) {
    console.error('Database error in findById:', error);
    throw new Error('Database operation failed');
  }
}
```

## Troubleshooting

### Issue: "Cannot find module" errors

**Solution:** Ensure proper imports:
```typescript
// Correct
import { UserRepository, AuthUser } from '@developersailor/express-auth';

// Check your tsconfig paths if using aliases
```

### Issue: Type mismatches

**Solution:** Ensure your AuthUser conversion includes all required fields:
```typescript
return {
  id: user.id.toString(), // Ensure string
  email: user.email,
  passwordHash: user.password_hash || user.passwordHash,
  roles: Array.isArray(user.roles) ? user.roles : user.roles.split(','),
  isActive: user.is_active !== false, // Default to true
};
```

### Issue: Token cleanup not working

**Solution:** Check your indexes and cleanup implementation:
```typescript
// Verify indexes exist
await db.collection('refreshTokens').indexes();

// For non-TTL databases, ensure cleanup is called
await refreshTokenRepository.cleanupExpiredTokens?.();
```

## Community Adapters

Have you created an adapter for a database not listed here? Consider contributing it!

Popular databases that could use adapters:
- PostgreSQL (with raw SQL or pg)
- DynamoDB
- Couchbase
- Redis (for token storage)
- Firebase/Firestore

## Need Help?

- 📖 Check the [examples directory](../examples/)
- 🐛 [Open an issue](https://github.com/developersailor/express-auth/issues)
- 💬 [Start a discussion](https://github.com/developersailor/express-auth/discussions)
