import jwt from 'jsonwebtoken';
import { JWTPayload, TokenPair } from '../types';

/**
 * JWT Service - Token üretimi ve doğrulama
 * Secret'lar dışarıdan alınır, paket içinde saklanmaz
 */
export class JWTService {
  private readonly jwtSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly accessTokenExpiresIn: string | number;
  private readonly refreshTokenExpiresIn: string | number;

  constructor(config: {
    jwtSecret: string;
    refreshTokenSecret: string;
    accessTokenExpiresIn?: string | number;
    refreshTokenExpiresIn?: string | number;
  }) {
    this.validateSecret(config.jwtSecret, 'jwtSecret');
    this.validateSecret(config.refreshTokenSecret, 'refreshTokenSecret');

    this.jwtSecret = config.jwtSecret;
    this.refreshTokenSecret = config.refreshTokenSecret;
    this.accessTokenExpiresIn = config.accessTokenExpiresIn || '15m';
    this.refreshTokenExpiresIn = config.refreshTokenExpiresIn || '7d';
  }

  /**
   * Secret'ın güçlü olup olmadığını kontrol et
   */
  private validateSecret(secret: string, name: string): void {
    if (!secret || typeof secret !== 'string') {
      throw new Error(`${name} is required and must be a string`);
    }
    if (secret.length < 32) {
      throw new Error(`${name} must be at least 32 characters long`);
    }
    // Weak secret detection
    const weakSecrets = ['secret', 'password', '123456', 'admin', 'test', 'default'];
    if (weakSecrets.some(weak => secret.toLowerCase().includes(weak))) {
      throw new Error(`${name} appears to be weak. Use a strong random string.`);
    }
  }

  /**
   * Access token ve refresh token üret
   */
  generateTokenPair(payload: Omit<JWTPayload, 'iat' | 'exp' | 'type'>): TokenPair {
    const now = Math.floor(Date.now() / 1000);
    
    // Access token expires in calculation
    const accessExpiresInSeconds = this.parseExpiresIn(this.accessTokenExpiresIn);
    const refreshExpiresInSeconds = this.parseExpiresIn(this.refreshTokenExpiresIn);

    const accessToken = jwt.sign(
      {
        ...payload,
        type: 'access',
        iat: now,
        exp: now + accessExpiresInSeconds,
      } as JWTPayload,
      this.jwtSecret,
      { algorithm: 'HS256' }
    );

    const refreshToken = jwt.sign(
      {
        sub: payload.sub,
        type: 'refresh',
        iat: now,
        exp: now + refreshExpiresInSeconds,
      } as JWTPayload,
      this.refreshTokenSecret,
      { algorithm: 'HS256' }
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: accessExpiresInSeconds,
    };
  }

  /**
   * ExpiresIn değerini saniyeye çevir
   */
  private parseExpiresIn(expiresIn: string | number): number {
    if (typeof expiresIn === 'number') {
      return expiresIn;
    }

    const match = expiresIn.match(/^(\d+)([smhdw])$/);
    if (!match) {
      throw new Error(`Invalid expiresIn format: ${expiresIn}`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers: Record<string, number> = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
      w: 604800,
    };

    return value * multipliers[unit];
  }

  /**
   * Access token doğrula
   */
  verifyAccessToken(token: string): JWTPayload {
    try {
      const decoded = jwt.verify(token, this.jwtSecret, {
        algorithms: ['HS256'],
      }) as JWTPayload;

      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid token');
      }
      throw error;
    }
  }

  /**
   * Refresh token doğrula
   */
  verifyRefreshToken(token: string): JWTPayload {
    try {
      const decoded = jwt.verify(token, this.refreshTokenSecret, {
        algorithms: ['HS256'],
      }) as JWTPayload;

      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid token');
      }
      throw error;
    }
  }

  /**
   * Token'ı decode et (doğrulama yapmadan)
   * Sadece bilgi almak için kullanılır
   */
  decodeToken(token: string): JWTPayload | null {
    try {
      return jwt.decode(token) as JWTPayload | null;
    } catch {
      return null;
    }
  }
}
