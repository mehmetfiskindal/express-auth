import { randomBytes, timingSafeEqual } from 'crypto';
import { Request, Response, NextFunction } from 'express';

/**
 * CSRF Protection Service - Double-submit cookie pattern (stateless)
 *
 * Sunucu login/refresh sırasında rastgele bir token üretir ve httpOnly
 * OLMAYAN bir cookie'ye yazar. İstemci aynı token'ı CSRF header'ında geri
 * gönderir; cookie ile header eşleşmezse istek reddedilir. Cross-site bir
 * saldırgan cookie'yi okuyamadığı için doğru header'ı üretemez.
 */
export interface CSRFConfig {
  /** CSRF cookie adı (varsayılan: 'csrfToken') */
  cookieName?: string;
  /** CSRF header adı, küçük harf (varsayılan: 'x-csrf-token') */
  headerName?: string;
}

export class CSRFService {
  private readonly cookieName: string;
  private readonly headerName: string;

  constructor(config: CSRFConfig = {}) {
    this.cookieName = config.cookieName ?? 'csrfToken';
    this.headerName = (config.headerName ?? 'x-csrf-token').toLowerCase();
  }

  getCookieName(): string {
    return this.cookieName;
  }

  getHeaderName(): string {
    return this.headerName;
  }

  /**
   * Kriptografik olarak güvenli yeni bir CSRF token üret
   */
  generateToken(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * İstekteki CSRF cookie'si ile header'ını karşılaştır.
   * Cookie okuma host uygulamanın cookie-parser'ına dayanır (req.cookies).
   */
  validateRequest(req: Request): boolean {
    const cookieToken = (req as Request & { cookies?: Record<string, string> }).cookies?.[this.cookieName];
    const headerToken = req.headers[this.headerName];

    if (!cookieToken || typeof headerToken !== 'string' || !headerToken) {
      return false;
    }

    const cookieBuffer = Buffer.from(cookieToken);
    const headerBuffer = Buffer.from(headerToken);

    if (cookieBuffer.length !== headerBuffer.length) {
      return false;
    }

    return timingSafeEqual(cookieBuffer, headerBuffer);
  }

  /**
   * Express middleware - geçersiz/eksik CSRF token'ında 403 döner
   */
  middleware(req: Request, res: Response, next: NextFunction): void {
    if (!this.validateRequest(req)) {
      res.status(403).json({
        error: 'Invalid CSRF token',
        message: 'CSRF token missing or does not match. Send the csrf cookie value in the CSRF header.',
      });
      return;
    }
    next();
  }
}

/**
 * CSRF service factory
 */
export const createCSRFService = (config?: CSRFConfig): CSRFService => {
  return new CSRFService(config);
};
