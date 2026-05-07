import { Request, Response, NextFunction } from 'express';
import { RateLimitService, createAuthRateLimiter, createGeneralRateLimiter, createStrictRateLimiter } from '../services/rate-limit-service';
import { SecurityMonitor } from '../services/security-monitor';
import { createCORSMiddleware } from '../services/cors-service';
import { createHTTPSMiddleware, securityHeadersMiddleware } from '../services/https-service';
import { AuthConfig } from '../types';

// Store for middleware instances
const middlewareInstances = new Map<string, any>();

/**
 * Create security middleware bundle for Express app
 * This combines rate limiting, CORS, HTTPS enforcement, and security headers
 */
export function createSecurityMiddleware(config: AuthConfig) {
  const isProduction = process.env.NODE_ENV === 'production';
  const instances: {
    rateLimiters?: {
      general: RateLimitService;
      auth: RateLimitService;
      strict: RateLimitService;
    };
    securityMonitor?: SecurityMonitor;
    corsMiddleware?: (req: Request, res: Response, next: NextFunction) => void;
    httpsMiddleware?: (req: Request, res: Response, next: NextFunction) => void;
    securityHeaders?: (req: Request, res: Response, next: NextFunction) => void;
  } = {};

  // Initialize rate limiters
  if (config.rateLimit?.enabled !== false) {
    instances.rateLimiters = {
      general: createGeneralRateLimiter(config.rateLimit?.general),
      auth: createAuthRateLimiter(config.rateLimit?.auth),
      strict: createStrictRateLimiter(config.rateLimit?.strict),
    };
  }

  // Initialize security monitor
  if (config.securityMonitor?.enabled !== false) {
    instances.securityMonitor = new SecurityMonitor(config.securityMonitor);
  }

  // Initialize CORS middleware
  if (config.cors) {
    instances.corsMiddleware = createCORSMiddleware(config.cors, isProduction);
  }

  // Initialize HTTPS middleware
  if (isProduction && config.https?.enabled !== false) {
    instances.httpsMiddleware = createHTTPSMiddleware({
      ...config.https,
      enabled: true,
    });
  }

  // Security headers middleware (always enabled)
  instances.securityHeaders = securityHeadersMiddleware();

  // Store instances for cleanup
  const instanceKey = Math.random().toString(36).substring(7);
  middlewareInstances.set(instanceKey, instances);

  return {
    /**
     * Apply all security middleware to Express app
     */
    apply(app: any): void {
      // Security headers first
      if (instances.securityHeaders) {
        app.use(instances.securityHeaders);
      }

      // HTTPS enforcement
      if (instances.httpsMiddleware) {
        app.use(instances.httpsMiddleware);
      }

      // CORS
      if (instances.corsMiddleware) {
        app.use(instances.corsMiddleware);
      }

      // Blocked IP check
      if (instances.securityMonitor) {
        app.use((req: Request, res: Response, next: NextFunction) => {
          instances.securityMonitor!.checkBlockedMiddleware(req, res, next);
        });
      }

      // General rate limiter for all routes
      if (instances.rateLimiters?.general) {
        app.use((req: Request, res: Response, next: NextFunction) => {
          // Skip auth routes - they have their own rate limiter
          if (!req.path.startsWith('/auth/')) {
            instances.rateLimiters!.general.middleware(req, res, next);
          } else {
            next();
          }
        });
      }
    },

    /**
     * Auth routes rate limiter middleware
     * Apply this specifically to auth routes
     */
    authRateLimit(req: Request, res: Response, next: NextFunction): void {
      if (instances.rateLimiters?.auth) {
        instances.rateLimiters.auth.middleware(req, res, next);
      } else {
        next();
      }
    },

    /**
     * Strict rate limiter middleware
     * Use for very sensitive operations
     */
    strictRateLimit(req: Request, res: Response, next: NextFunction): void {
      if (instances.rateLimiters?.strict) {
        instances.rateLimiters.strict.middleware(req, res, next);
      } else {
        next();
      }
    },

    /**
     * Get security monitor instance
     */
    getSecurityMonitor(): SecurityMonitor | undefined {
      return instances.securityMonitor;
    },

    /**
     * Get rate limiter instances
     */
    getRateLimiters() {
      return instances.rateLimiters;
    },

    /**
     * Cleanup all resources
     */
    cleanup(): void {
      instances.rateLimiters?.general?.stopCleanupJob();
      instances.rateLimiters?.auth?.stopCleanupJob();
      instances.rateLimiters?.strict?.stopCleanupJob();
      instances.securityMonitor?.stopCleanupJob();
      middlewareInstances.delete(instanceKey);
    },

    /**
     * Get security statistics
     */
    getStats() {
      return {
        rateLimiterSizes: {
          general: instances.rateLimiters?.general?.getStoreSize() ?? 0,
          auth: instances.rateLimiters?.auth?.getStoreSize() ?? 0,
          strict: instances.rateLimiters?.strict?.getStoreSize() ?? 0,
        },
        securityMonitor: instances.securityMonitor?.getStats(),
        blockedIPs: instances.securityMonitor?.getBlockedIPs(),
      };
    },
  };
}

/**
 * Simple rate limit middleware factory
 */
export function createRateLimitMiddleware(
  windowMs: number = 15 * 60 * 1000,
  maxRequests: number = 100
): (req: Request, res: Response, next: NextFunction) => void {
  const rateLimiter = new RateLimitService({ windowMs, maxRequests });
  return rateLimiter.middleware.bind(rateLimiter);
}

/**
 * Security headers only middleware
 */
export { securityHeadersMiddleware } from '../services/https-service';

/**
 * CORS middleware factory
 */
export { createCORSMiddleware, corsMiddleware, strictCORSMiddleware } from '../services/cors-service';

/**
 * HTTPS redirect middleware factory
 */
export { createHTTPSMiddleware, httpsRedirectMiddleware } from '../services/https-service';
