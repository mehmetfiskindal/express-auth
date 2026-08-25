import { randomBytes, createHash } from 'crypto';
import { authenticator } from 'otplib';

/**
 * MFA (TOTP) Service - Google Authenticator uyumlu iki adımlı doğrulama
 */
export interface MFAConfig {
  /** otpauth:// URI'sindeki issuer adı (authenticator app'te görünür) */
  issuer?: string;
  /** Üretilecek yedek kod sayısı */
  backupCodesCount?: number;
}

export class MFAService {
  private readonly issuer: string;
  private readonly backupCodesCount: number;

  constructor(config: MFAConfig = {}) {
    this.issuer = config.issuer ?? 'ExpressAuth';
    this.backupCodesCount = config.backupCodesCount ?? 10;
    // ±1 zaman adımı (30sn) tolerans - saat kaymasına karşı makul bir varsayılan
    authenticator.options = { window: 1 };
  }

  /**
   * Yeni bir Base32 TOTP secret üret
   */
  generateSecret(): string {
    return authenticator.generateSecret();
  }

  /**
   * Authenticator app'te QR kod olarak taratılacak otpauth:// URI'si
   */
  getOtpAuthUrl(email: string, secret: string): string {
    return authenticator.keyuri(email, this.issuer, secret);
  }

  /**
   * Kullanıcının girdiği TOTP kodunu doğrula (±1 zaman adımı toleransı ile)
   */
  async verifyToken(token: string, secret: string): Promise<boolean> {
    try {
      return authenticator.check(token, secret);
    } catch {
      return false;
    }
  }

  /**
   * Kriptografik olarak güvenli, insan tarafından okunabilir yedek kodlar üret
   */
  generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < this.backupCodesCount; i++) {
      const raw = randomBytes(5).toString('hex'); // 10 hex karakter
      codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
    }
    return codes;
  }

  /**
   * Bir yedek kodu saklama için hash'le (SHA-256)
   */
  hashBackupCode(code: string): string {
    return createHash('sha256').update(code.trim().toLowerCase()).digest('hex');
  }

  /**
   * Girilen kodu saklanan hash listesine karşı doğrula.
   * Eşleşirse tekrar kullanılamaması için hangi hash'in tüketileceğini döner.
   */
  verifyBackupCode(code: string, hashes: string[]): { valid: boolean; matchedHash?: string } {
    const hash = this.hashBackupCode(code);
    return hashes.includes(hash) ? { valid: true, matchedHash: hash } : { valid: false };
  }
}

/**
 * MFA service factory
 */
export const createMFAService = (config?: MFAConfig): MFAService => {
  return new MFAService(config);
};
