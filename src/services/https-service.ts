import { Request, Response, NextFunction } from 'express';

/**
 * HTTPS Enforcement Configuration
 */
export interface HTTPSConfig {
  /** Enable HTTPS enforcement (default: true in production) */
  enabled: boolean;
  /** Trust proxy headers (default: true) */
  trustProxy: boolean;
  /** HTTP port to redirect from (default: 80) */
  redirectPort: number;
  /** HTTPS port to redirect to (default: 443) */
  httpsPort: number;
  /** Status code for redirect (default: 301) */
  redirectCode: 301 | 302 | 307 | 308;
  /** HSTS max age in seconds (default: 31536000 - 1 year) */
  hstsMaxAge: number;
  /** Include subdomains in HSTS (default: true) */
  hstsIncludeSubdomains: boolean;
  /** Enable HSTS preload (default: true) */
  hstsPreload: boolean;
  /** Paths to exclude from HTTPS enforcement (e.g., health checks) */
  excludePaths: string[];
}

/**
 * Default HTTPS configuration for production
 */
export const defaultHTTPSConfig: HTTPSConfig = {
  enabled: true,
  trustProxy: true,
  redirectPort: 80,
  httpsPort: 443,
  redirectCode: 301,
  hstsMaxAge: 31536000, // 1 year
  hstsIncludeSubdomains: true,
  hstsPreload: true,
  excludePaths: ['/health', '/healthz', '/ping'],
};

/**
 * Check if request is secure
 */
function isSecureRequest(req: Request, trustProxy: boolean): boolean {
  // Check direct secure connection
  if (req.secure) {
    return true;
  }

  // Check proxy headers if trusting proxy
  if (trustProxy) {
    // X-Forwarded-Proto header
    const forwardedProto = req.headers['x-forwarded-proto'];
    if (forwardedProto === 'https') {
      return true;
    }

    // X-Forwarded-SSL header
    const forwardedSSL = req.headers['x-forwarded-ssl'];
    if (forwardedSSL === 'on') {
      return true;
    }

    // X-Forwarded-Port header
    const forwardedPort = req.headers['x-forwarded-port'];
    if (forwardedPort === '443') {
      return true;
    }

    // Forwarded header (RFC 7239)
    const forwarded = req.headers.forwarded;
    if (forwarded && forwarded.includes('proto=https')) {
      return true;
    }
  }

  return false;
}

/**
 * Create HTTPS enforcement middleware
 */
export function createHTTPSMiddleware(
  config: Partial<HTTPSConfig> = {}
): (req: Request, res: Response, next: NextFunction) => void {
  const httpsConfig: HTTPSConfig = {
    ...defaultHTTPSConfig,
    ...config,
  };

  return function httpsMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    // Skip if disabled
    if (!httpsConfig.enabled) {
      return next();
    }

    // Skip excluded paths
    if (httpsConfig.excludePaths.includes(req.path)) {
      return next();
    }

    // Check if already secure
    if (isSecureRequest(req, httpsConfig.trustProxy)) {
      // Add HSTS header for secure requests
      let hstsValue = `max-age=${httpsConfig.hstsMaxAge}`;
      if (httpsConfig.hstsIncludeSubdomains) {
        hstsValue += '; includeSubDomains';
      }
      if (httpsConfig.hstsPreload) {
        hstsValue += '; preload';
      }
      res.setHeader('Strict-Transport-Security', hstsValue);

      // Add additional security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

      return next();
    }

    // Redirect to HTTPS
    const host = req.headers.host?.split(':')[0] || req.hostname;
    const httpsPort = httpsConfig.httpsPort !== 443 ? `:${httpsConfig.httpsPort}` : '';
    const redirectUrl = `https://${host}${httpsPort}${req.originalUrl}`;

    // Add HSTS header even in redirect (some browsers respect this)
    let hstsValue = `max-age=${httpsConfig.hstsMaxAge}`;
    if (httpsConfig.hstsIncludeSubdomains) {
      hstsValue += '; includeSubDomains';
    }
    res.setHeader('Strict-Transport-Security', hstsValue);

    res.redirect(httpsConfig.redirectCode, redirectUrl);
  };
}

/**
 * Simple HTTPS redirect middleware
 * Redirects all HTTP traffic to HTTPS
 */
export function httpsRedirectMiddleware(
  options: {
    trustProxy?: boolean;
    excludePaths?: string[];
    statusCode?: 301 | 302 | 307 | 308;
  } = {}
): (req: Request, res: Response, next: NextFunction) => void {
  return createHTTPSMiddleware({
    enabled: true,
    trustProxy: options.trustProxy ?? true,
    excludePaths: options.excludePaths ?? ['/health', '/healthz'],
    redirectCode: options.statusCode ?? 301,
  });
}

/**
 * Security headers middleware
 * Adds common security headers without HTTPS enforcement
 */
export function securityHeadersMiddleware(): (
  req: Request,
  res: Response,
  next: NextFunction
) => void {
  return function securityHeaders(
    _req: Request,
    res: Response,
    next: NextFunction
  ): void {
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');

    // XSS Protection
    res.setHeader('X-XSS-Protection', '1; mode=block');

    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy (Feature Policy)
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), interest-cohort=()'
    );

    // Content Security Policy (basic)
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
    );

    next();
  };
}
