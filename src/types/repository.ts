import type { Permission } from './auth-config';

/**
 * AuthUser - Kullanıcı modeli
 * Paket dışarıdan bu yapıyı bekler
 */
export interface AuthUser {
  id: string;
  email: string;
  passwordHash: string;
  roles?: string[];
  permissions?: Permission[];
  isActive?: boolean;
  [key: string]: unknown; // Ek alanlar için
}

/**
 * Refresh token kaydı için interface
 */
export interface RefreshTokenRecord {
  /**
   * Persisted token identifier. When hashRefreshTokens is enabled, this is a
   * SHA-256 hash of the raw refresh token.
   */
  token: string;
  userId: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date;
}

/**
 * Kullanıcı repository'si - Kullanıcı tarafından implemente edilir
 */
export interface UserRepository {
  /**
   * Email ile kullanıcı bul
   */
  findByEmail(email: string): Promise<AuthUser | null>;

  /**
   * ID ile kullanıcı bul
   */
  findById(id: string): Promise<AuthUser | null>;

  /**
   * Yeni kullanıcı oluştur
   */
  createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser>;

  /**
   * Kullanıcı şifresini güncelle (opsiyonel)
   */
  updatePassword?(userId: string, newPasswordHash: string): Promise<void>;
}

/**
 * Refresh token repository'si - Token revoke ve rotation için
 */
export interface RefreshTokenRepository {
  /**
   * Token kaydet
   */
  saveToken(token: RefreshTokenRecord): Promise<void>;

  /**
   * Token bul
   */
  findToken(token: string): Promise<RefreshTokenRecord | null>;

  /**
   * Token'ı revoke et
   */
  revokeToken(token: string): Promise<void>;

  /**
   * Token'ı atomik olarak consume/revoke et ve eski kaydı döndür.
   * Refresh token rotation race condition'larını engellemek için önerilir.
   */
  consumeToken?(token: string): Promise<RefreshTokenRecord | null>;

  /**
   * Kullanıcının tüm tokenlarını revoke et (logout everywhere)
   */
  revokeAllUserTokens(userId: string): Promise<void>;

  /**
   * Süresi dolmuş tokenları temizle (opsiyonel)
   */
  cleanupExpiredTokens?(): Promise<void>;
}

/**
 * Repository factory - Hem user hem refresh token repository'si
 */
export interface AuthRepositories {
  userRepository: UserRepository;
  refreshTokenRepository: RefreshTokenRepository;
}
