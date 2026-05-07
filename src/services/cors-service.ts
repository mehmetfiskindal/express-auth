import { Request, Response, NextFunction } from 'express';

/**
 * CORS Configuration Options
 */
export interface CORSConfig {
  /** Allowed origins (default: ['*'] in dev, [] in prod) */
  origin: string | string[] | ((origin: string, callback: (err: Error | null, allow?: boolean) => void) => void);
  /** Allow credentials (cookies, authorization headers) (default: true) */
  credentials: boolean;
  /** Allowed HTTP methods (default: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) */
  methods: string[];
  /** Allowed headers (default: ['Content-Type', 'Authorization', 'X-Requested-With']) */
  allowedHeaders: string[];
  /** Exposed headers (default: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']) */
  exposedHeaders: string[];
  /** Max age for preflight cache in seconds (default: 86400) */
  maxAge: number;
  /** Preflight continue (default: false) */
  preflightContinue: boolean;
  /** Options success status (default: 204) */
  optionsSuccessStatus: number;
}

/**
 * Default CORS configuration for development
 */
export const defaultDevCORS: CORSConfig = {
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin',
    'X-CSRF-Token',
  ],
  exposedHeaders: [
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
    'X-Total-Count',
  ],
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

/**
 * Default CORS configuration for production
 */
export const defaultProdCORS: CORSConfig = {
  origin: [], // Must be explicitly set in production
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin',
    'X-CSRF-Token',
  ],
  exposedHeaders: [
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
  ],
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

/**
 * Check if origin is allowed
 */
function isOriginAllowed(
  origin: string,
  allowedOrigins: string | string[]
): boolean {
  if (Array.isArray(allowedOrigins)) {
    return allowedOrigins.some((allowed) => {
      if (allowed === '*') return true;
      if (allowed === origin) return true;
      // Support wildcard subdomains: *.example.com
      if (allowed.startsWith('*.')) {
        const domain = allowed.slice(2);
        return origin.endsWith(domain);
      }
      return false;
    });
  }
  return allowedOrigins === '*' || allowedOrigins === origin;
}

/**
 * CORS Middleware Factory
 */
export function createCORSMiddleware(
  config: Partial<CORSConfig> = {},
  isProduction = process.env.NODE_ENV === 'production'
): (req: Request, res: Response, next: NextFunction) => void {
  const defaultConfig = isProduction ? defaultProdCORS : defaultDevCORS;
  const corsConfig: CORSConfig = {
    ...defaultConfig,
    ...config,
  };

  // Validate production CORS
  if (isProduction) {
    const origin = corsConfig.origin;
    const hasValidOrigin =
      (typeof origin === 'string' && origin !== '*') ||
      (Array.isArray(origin) && origin.length > 0 && !origin.includes('*'));

    if (!hasValidOrigin) {
      console.warn(
        '[CORS] WARNING: Running in production with wildcard or no origin restriction. ' +
        'This is a security risk. Please configure specific allowed origins.'
      );
    }
  }

  return function corsMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    const requestOrigin = req.headers.origin;

    // Handle origin
    if (typeof corsConfig.origin === 'function') {
      corsConfig.origin(requestOrigin || '', (err, allow) => {
        if (err) {
          return next(err);
        }
        applyCORSHeaders(allow ? (requestOrigin || false) : false);
      });
    } else {
      const allowed =
        !requestOrigin ||
        corsConfig.origin === '*' ||
        isOriginAllowed(requestOrigin, corsConfig.origin);
      applyCORSHeaders(allowed ? (requestOrigin || false) : false);
    }

    function applyCORSHeaders(allowedOrigin: string | false): void {
      // Set origin header
      if (allowedOrigin) {
        res.header('Access-Control-Allow-Origin', allowedOrigin);
      }

      // Set credentials header
      if (corsConfig.credentials) {
        res.header('Access-Control-Allow-Credentials', 'true');
      }

      // Set exposed headers
      if (corsConfig.exposedHeaders.length > 0) {
        res.header(
          'Access-Control-Expose-Headers',
          corsConfig.exposedHeaders.join(',')
        );
      }

      // Handle preflight requests
      if (req.method === 'OPTIONS') {
        // Set allowed methods
        res.header(
          'Access-Control-Allow-Methods',
          corsConfig.methods.join(',')
        );

        // Set allowed headers
        const requestedHeaders = req.headers['access-control-request-headers'];
        if (requestedHeaders) {
          res.header('Access-Control-Allow-Headers', requestedHeaders);
        } else {
          res.header(
            'Access-Control-Allow-Headers',
            corsConfig.allowedHeaders.join(',')
          );
        }

        // Set max age
        res.header('Access-Control-Max-Age', corsConfig.maxAge.toString());

        // Respond to preflight
        res.status(corsConfig.optionsSuccessStatus).end();
        return;
      }

      // Vary header for caching
      if (allowedOrigin && allowedOrigin !== '*') {
        res.vary('Origin');
      }

      next();
    }
  };
}

/**
 * Simple CORS middleware with allowed origins
 */
export function corsMiddleware(
  allowedOrigins: string | string[] = '*',
  options: Partial<Omit<CORSConfig, 'origin'>> = {}
): (req: Request, res: Response, next: NextFunction) => void {
  return createCORSMiddleware({
    origin: allowedOrigins,
    ...options,
  });
}

/**
 * Strict CORS middleware - only allows specific origins
 */
export function strictCORSMiddleware(
  allowedOrigins: string[],
  options: Partial<Omit<CORSConfig, 'origin'>> = {}
): (req: Request, res: Response, next: NextFunction) => void {
  return createCORSMiddleware({
    origin: allowedOrigins,
    credentials: true,
    ...options,
  });
}
