import { AuthUser, RefreshTokenRecord, UserRepository, RefreshTokenRepository } from '../types';

/**
 * In-memory User Repository
 * Test ve development için kullanılır
 * NOT: Production'da kullanmayın!
 */
export class MemoryUserRepository implements UserRepository {
  private users: Map<string, AuthUser> = new Map();
  private emailIndex: Map<string, string> = new Map(); // email -> id

  async findByEmail(email: string): Promise<AuthUser | null> {
    const id = this.emailIndex.get(email.toLowerCase());
    if (!id) return null;
    return this.users.get(id) || null;
  }

  async findById(id: string): Promise<AuthUser | null> {
    return this.users.get(id) || null;
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser> {
    const id = Math.random().toString(36).substring(2, 15);
    const user: AuthUser = {
      id,
      email: data.email.toLowerCase(),
      passwordHash: data.passwordHash,
      roles: data.roles || ['user'],
      isActive: true,
    };

    this.users.set(id, user);
    this.emailIndex.set(data.email.toLowerCase(), id);

    return user;
  }

  // Test yardımcı metodları
  clear(): void {
    this.users.clear();
    this.emailIndex.clear();
  }

  getAll(): AuthUser[] {
    return Array.from(this.users.values());
  }
}

/**
 * In-memory Refresh Token Repository
 * Test ve development için kullanılır
 * NOT: Production'da kullanmayın!
 */
export class MemoryRefreshTokenRepository implements RefreshTokenRepository {
  private tokens: Map<string, RefreshTokenRecord> = new Map();

  async saveToken(record: RefreshTokenRecord): Promise<void> {
    this.tokens.set(record.token, { ...record });
  }

  async findToken(token: string): Promise<RefreshTokenRecord | null> {
    return this.tokens.get(token) || null;
  }

  async revokeToken(token: string): Promise<void> {
    const record = this.tokens.get(token);
    if (record) {
      record.revokedAt = new Date();
      this.tokens.set(token, record);
    }
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    for (const [token, record] of this.tokens.entries()) {
      if (record.userId === userId && !record.revokedAt) {
        record.revokedAt = new Date();
        this.tokens.set(token, record);
      }
    }
  }

  async cleanupExpiredTokens(): Promise<void> {
    const now = new Date();
    for (const [token, record] of this.tokens.entries()) {
      if (record.expiresAt < now) {
        this.tokens.delete(token);
      }
    }
  }

  // Test yardımcı metodları
  clear(): void {
    this.tokens.clear();
  }

  getAll(): RefreshTokenRecord[] {
    return Array.from(this.tokens.values());
  }
}

/**
 * Repository factory
 * Test için hazır memory repository'leri
 */
export function createMemoryRepositories() {
  return {
    userRepository: new MemoryUserRepository(),
    refreshTokenRepository: new MemoryRefreshTokenRepository(),
  };
}
