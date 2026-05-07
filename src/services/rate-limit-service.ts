/**
 * Rate Limiting Service - In-memory rate limiting
 * Production'da Redis ile değiştirilebilir
 */
export interface RateLimitConfig {
  /** Window size in milliseconds (default: 15 minutes) */
  windowMs: number;
  /** Max requests per window (default: 100) */
  maxRequests: number;
  /** Skip successful requests (default: false) */
  skipSuccessfulRequests?: boolean;
  /** Key generator function (default: IP address) */
  keyGenerator?: (req: any) => string;
  /** Handler when limit is exceeded */
  handler?: (req: any, res: any) => void;
  /** Skip rate limiting for certain requests */
  skip?: (req: any) => boolean;
}

export interface RateLimitEntry {
  count: number;
  resetTime: number;
  firstRequestTime: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

export class RateLimitService {
  private store: Map<string, RateLimitEntry> = new Map();
  private config: Required<RateLimitConfig>;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = {
      windowMs: config.windowMs ?? 15 * 60 * 1000, // 15 minutes
      maxRequests: config.maxRequests ?? 100,
      skipSuccessfulRequests: config.skipSuccessfulRequests ?? false,
      keyGenerator: config.keyGenerator ?? ((req: any) => req.ip || req.connection?.remoteAddress || 'unknown'),
      handler: config.handler ?? this.defaultHandler,
      skip: config.skip ?? (() => false),
    };

    // Cleanup old entries every 5 minutes
    this.startCleanupJob();
  }

  /**
   * Check if request is allowed
   */
  checkLimit(key: string): RateLimitResult {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now > entry.resetTime) {
      // New window
      const newEntry: RateLimitEntry = {
        count: 1,
        resetTime: now + this.config.windowMs,
        firstRequestTime: now,
      };
      this.store.set(key, newEntry);

      return {
        allowed: true,
        limit: this.config.maxRequests,
        remaining: this.config.maxRequests - 1,
        resetTime: newEntry.resetTime,
      };
    }

    // Existing window
    if (entry.count >= this.config.maxRequests) {
      const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
      return {
        allowed: false,
        limit: this.config.maxRequests,
        remaining: 0,
        resetTime: entry.resetTime,
        retryAfter,
      };
    }

    entry.count++;
    return {
      allowed: true,
      limit: this.config.maxRequests,
      remaining: this.config.maxRequests - entry.count,
      resetTime: entry.resetTime,
    };
  }

  /**
   * Increment count for a key
   */
  increment(key: string): RateLimitResult {
    return this.checkLimit(key);
  }
  
  /**
   * Decrement count (for skipped successful requests)
   */
  decrement(key: string): void {
    const entry = this.store.get(key);
    if (entry && entry.count > 0) {
      entry.count--;
    }
  }

  /**
   * Reset limit for a key
   */
  reset(key: string): void {
    this.store.delete(key);
  }

  /**
   * Get current status for a key
   */
  getStatus(key: string): RateLimitResult | null {
    const entry = this.store.get(key);
    if (!entry) return null;

    const now = Date.now();
    if (now > entry.resetTime) return null;

    return {
      allowed: entry.count < this.config.maxRequests,
      limit: this.config.maxRequests,
      remaining: Math.max(0, this.config.maxRequests - entry.count),
      resetTime: entry.resetTime,
    };
  }

  /**
   * Default handler when limit is exceeded
   */
  private defaultHandler(req: any, res: any): void {
    const key = this.config.keyGenerator(req);
    const result = this.getStatus(key);
    const retryAfter = result?.retryAfter ?? Math.ceil(this.config.windowMs / 1000);

    res.status(429).json({
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
      retryAfter,
    });
  }

  /**
   * Middleware function for Express
   */
  middleware(req: any, res: any, next: any): void {
    if (this.config.skip(req)) {
      return next();
    }

    const key = this.config.keyGenerator(req);
    const result = this.checkLimit(key);

    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', result.limit);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, result.remaining));
    res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetTime / 1000));

    if (!result.allowed) {
      res.setHeader('Retry-After', result.retryAfter!);
      return this.config.handler(req, res);
    }

    // Store the key on the response for decrementing later
    (req as any)._rateLimitKey = key;

    // Override res.end to decrement on successful requests if configured
    if (this.config.skipSuccessfulRequests) {
      const originalEnd = res.end.bind(res);
      res.end = (...args: any[]) => {
        if (res.statusCode < 400) {
          this.decrement(key);
        }
        originalEnd(...args);
      };
    }

    next();
  }

  /**
   * Start cleanup job to remove expired entries
   */
  private startCleanupJob(): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store.entries()) {
        if (now > entry.resetTime) {
          this.store.delete(key);
        }
      }
    }, 5 * 60 * 1000); // Cleanup every 5 minutes
  }

  /**
   * Stop cleanup job
   */
  stopCleanupJob(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Get store size (for monitoring)
   */
  getStoreSize(): number {
    return this.store.size;
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.store.clear();
  }
}

/**
 * Pre-configured rate limiters for different endpoints
 */
export const createAuthRateLimiter = (options?: Partial<RateLimitConfig>) => {
  return new RateLimitService({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5, // Stricter for auth endpoints
    ...options,
  });
};

export const createGeneralRateLimiter = (options?: Partial<RateLimitConfig>) => {
  return new RateLimitService({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    ...options,
  });
};

export const createStrictRateLimiter = (options?: Partial<RateLimitConfig>) => {
  return new RateLimitService({
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 10, // Very strict
    ...options,
  });
};
