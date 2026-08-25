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
  /** Parola sıfırlama token'ının hash'i (SHA-256). Sadece bekleyen bir istek varken dolu. */
  passwordResetTokenHash?: string;
  /** Parola sıfırlama token'ının son kullanma zamanı. */
  passwordResetExpiresAt?: Date;
  /** MFA (TOTP) etkin mi? */
  mfaEnabled?: boolean;
  /** TOTP secret (Base32). mfaEnabled=false iken de "kurulum bekliyor" secret'ı tutabilir. */
  mfaSecret?: string;
  /** Kullanılmamış yedek kodların hash'leri (SHA-256, her biri tek kullanımlık). */
  mfaBackupCodeHashes?: string[];
  [key: string]: unknown; // Ek alanlar için
}

/**
 * API yanıtlarında ve host callback'lerinde güvenle dönülebilecek kullanıcı alanları.
 * Secret / hash / reset token alanları asla buraya dahil edilmez.
 */
export type PublicAuthUser = Omit<
  AuthUser,
  | 'passwordHash'
  | 'mfaSecret'
  | 'mfaBackupCodeHashes'
  | 'passwordResetTokenHash'
  | 'passwordResetExpiresAt'
>;

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

  /**
   * Kullanıcı kaydını kısmi güncelle (opsiyonel).
   * Parola sıfırlama ve MFA özellikleri bu metoda dayanır — implemente
   * edilmezse bu özelliklerin route'ları router'a hiç eklenmez.
   */
  updateUser?(userId: string, data: Partial<AuthUser>): Promise<AuthUser | null>;

  /**
   * Parola sıfırlama token hash'ine göre kullanıcı bul (opsiyonel).
   * Parola sıfırlama özelliği bu metoda dayanır.
   */
  findByPasswordResetToken?(tokenHash: string): Promise<AuthUser | null>;

  /**
   * MFA yedek kodunu atomik olarak tüket (opsiyonel ama şiddetle önerilir).
   * `codeHash` listede varsa kaldırıp `true` döner; yoksa `false`.
   * Race condition'da aynı kodun iki kez kullanılmasını engeller.
   * Yoksa router read-modify-write fallback kullanır (tek instance'ta zayıf).
   */
  consumeMfaBackupCode?(userId: string, codeHash: string): Promise<boolean>;
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
