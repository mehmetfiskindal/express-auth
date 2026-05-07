import bcrypt from 'bcryptjs';

/**
 * Password Service - Şifre hash ve doğrulama işlemleri
 * bcryptjs kullanır
 */
export class PasswordService {
  private readonly saltRounds: number;

  constructor(saltRounds: number = 12) {
    this.saltRounds = saltRounds;
  }

  /**
   * Şifreyi hash'le
   */
  async hashPassword(password: string): Promise<string> {
    if (!password || password.length < 1) {
      throw new Error('Password is required');
    }
    return bcrypt.hash(password, this.saltRounds);
  }

  /**
   * Şifreyi doğrula
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    if (!password || !hash) {
      return false;
    }
    return bcrypt.compare(password, hash);
  }

  /**
   * Şifre güçlülüğünü kontrol et
   */
  validatePasswordStrength(
    password: string,
    rules: {
      minLength?: number;
      requireUppercase?: boolean;
      requireLowercase?: boolean;
      requireNumbers?: boolean;
      requireSpecialChars?: boolean;
    } = {}
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Default rules
    const minLength = rules.minLength ?? 8;
    const requireUppercase = rules.requireUppercase ?? true;
    const requireLowercase = rules.requireLowercase ?? true;
    const requireNumbers = rules.requireNumbers ?? true;
    const requireSpecialChars = rules.requireSpecialChars ?? true;

    if (password.length < minLength) {
      errors.push(`Password must be at least ${minLength} characters long`);
    }

    if (requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Güvenli şifre üret (opsiyonel)
   */
  generateSecurePassword(length: number = 16): string {
    const charset = {
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      numbers: '0123456789',
      special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    };

    const allChars = Object.values(charset).join('');
    let password = '';

    // Ensure at least one of each type
    password += charset.uppercase[Math.floor(Math.random() * charset.uppercase.length)];
    password += charset.lowercase[Math.floor(Math.random() * charset.lowercase.length)];
    password += charset.numbers[Math.floor(Math.random() * charset.numbers.length)];
    password += charset.special[Math.floor(Math.random() * charset.special.length)];

    // Fill the rest
    for (let i = 4; i < length; i++) {
      password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle
    return password
      .split('')
      .sort(() => Math.random() - 0.5)
      .join('');
  }
}
