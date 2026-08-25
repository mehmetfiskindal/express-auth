import { randomBytes, createHash } from 'crypto';

/**
 * Password Reset Service - Token üretimi/hash'leme
 * E-posta gönderimi host uygulamanın sorumluluğundadır (bkz. AuthConfig.passwordReset.onRequest)
 */
export interface PasswordResetConfig {
  /** Reset token'ının geçerlilik süresi (ms). Varsayılan: 1 saat */
  tokenExpiresIn?: number;
}

export class PasswordResetService {
  private readonly tokenExpiresIn: number;

  constructor(config: PasswordResetConfig = {}) {
    this.tokenExpiresIn = config.tokenExpiresIn ?? 60 * 60 * 1000;
  }

  /**
   * Kriptografik olarak güvenli, düz metin reset token üret (kullanıcıya/e-postaya gider)
   */
  generateToken(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Token'ı saklama için hash'le (SHA-256) - repository'de düz metin tutulmaz
   */
  hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  /**
   * Token'ın son kullanma zamanı
   */
  getExpiresAt(): Date {
    return new Date(Date.now() + this.tokenExpiresIn);
  }
}

/**
 * Password reset service factory
 */
export const createPasswordResetService = (config?: PasswordResetConfig): PasswordResetService => {
  return new PasswordResetService(config);
};
