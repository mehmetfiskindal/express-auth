import { EventEmitter } from 'events';
import { RateLimitService } from './rate-limit-service';

/**
 * Security event types
 */
export type SecurityEventType =
  | 'failed_login'
  | 'brute_force_attempt'
  | 'suspicious_activity'
  | 'token_reuse'
  | 'rate_limit_exceeded'
  | 'ip_blocked'
  | 'multiple_failed_attempts'
  | 'concurrent_login'
  | 'unusual_location'
  | 'permission_violation';

/**
 * Security event data
 */
export interface SecurityEvent {
  type: SecurityEventType;
  userId?: string;
  email?: string;
  ip: string;
  userAgent?: string;
  timestamp: Date;
  details?: Record<string, unknown>;
  riskScore: number; // 0-100
}

/**
 * Failed login attempt record
 */
interface FailedAttempt {
  count: number;
  firstAttempt: number;
  lastAttempt: number;
  emails: Set<string>;
}

/**
 * Security monitoring configuration
 */
export interface SecurityMonitorConfig {
  /** Max failed attempts before blocking (default: 5) */
  maxFailedAttempts: number;
  /** Time window for failed attempts in ms (default: 15 min) */
  failedAttemptsWindow: number;
  /** Block duration in ms (default: 30 min) */
  blockDuration: number;
  /** Enable monitoring (default: true) */
  enabled: boolean;
  /** Risk score threshold for alerts (default: 70) */
  alertThreshold: number;
  /** Track concurrent logins from different IPs (default: true) */
  trackConcurrentLogins: boolean;
  /** Max concurrent sessions per user (default: 5) */
  maxConcurrentSessions: number;
}

/**
 * Security Monitor Service
 * Tracks and alerts on suspicious activities
 */
export class SecurityMonitor extends EventEmitter {
  private config: Required<SecurityMonitorConfig>;
  private failedAttempts: Map<string, FailedAttempt> = new Map();
  private blockedIPs: Map<string, number> = new Map();
  private userSessions: Map<string, Set<string>> = new Map(); // userId -> Set of IPs
  private rateLimitService: RateLimitService;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(config: Partial<SecurityMonitorConfig> = {}) {
    super();
    this.config = {
      maxFailedAttempts: config.maxFailedAttempts ?? 5,
      failedAttemptsWindow: config.failedAttemptsWindow ?? 15 * 60 * 1000,
      blockDuration: config.blockDuration ?? 30 * 60 * 1000,
      enabled: config.enabled ?? true,
      alertThreshold: config.alertThreshold ?? 70,
      trackConcurrentLogins: config.trackConcurrentLogins ?? true,
      maxConcurrentSessions: config.maxConcurrentSessions ?? 5,
    };

    this.rateLimitService = new RateLimitService({
      windowMs: this.config.failedAttemptsWindow,
      maxRequests: this.config.maxFailedAttempts,
    });

    if (this.config.enabled) {
      this.startCleanupJob();
    }
  }

  /**
   * Record a failed login attempt
   */
  recordFailedAttempt(ip: string, email?: string, userAgent?: string): void {
    if (!this.config.enabled) return;

    const now = Date.now();
    const attempt = this.failedAttempts.get(ip) ?? {
      count: 0,
      firstAttempt: now,
      lastAttempt: now,
      emails: new Set(),
    };

    attempt.count++;
    attempt.lastAttempt = now;
    if (email) attempt.emails.add(email);

    this.failedAttempts.set(ip, attempt);

    // Check rate limit
    this.rateLimitService.checkLimit(ip);

    // Emit event for monitoring
    const event: SecurityEvent = {
      type: 'failed_login',
      email,
      ip,
      userAgent,
      timestamp: new Date(),
      riskScore: Math.min(100, attempt.count * 10),
      details: {
        attemptCount: attempt.count,
        emailsTried: Array.from(attempt.emails),
      },
    };
    this.emit('securityEvent', event);

    // Check for brute force
    if (attempt.count >= this.config.maxFailedAttempts) {
      this.blockIP(ip, 'Too many failed login attempts');
      
      this.emit('securityEvent', {
        ...event,
        type: 'brute_force_attempt',
        riskScore: 90,
      });
    }

    // Check for suspicious patterns
    if (attempt.emails.size > 3) {
      this.emit('securityEvent', {
        ...event,
        type: 'suspicious_activity',
        riskScore: 80,
        details: {
          ...event.details,
          reason: 'Multiple different emails tried from same IP',
        },
      });
    }
  }

  /**
   * Record a successful login
   */
  recordSuccessfulLogin(userId: string, ip: string, userAgent?: string): void {
    if (!this.config.enabled) return;

    // Clear failed attempts for this IP
    this.failedAttempts.delete(ip);
    this.rateLimitService.reset(ip);

    // Track concurrent sessions
    if (this.config.trackConcurrentLogins) {
      const sessions = this.userSessions.get(userId) ?? new Set();
      sessions.add(ip);
      this.userSessions.set(userId, sessions);

      if (sessions.size > this.config.maxConcurrentSessions) {
        this.emit('securityEvent', {
          type: 'concurrent_login',
          userId,
          ip,
          userAgent,
          timestamp: new Date(),
          riskScore: 60,
          details: {
            sessionCount: sessions.size,
            maxAllowed: this.config.maxConcurrentSessions,
          },
        });
      }
    }
  }

  /**
   * Record logout
   */
  recordLogout(userId: string, ip: string): void {
    if (!this.config.enabled) return;

    const sessions = this.userSessions.get(userId);
    if (sessions) {
      sessions.delete(ip);
      if (sessions.size === 0) {
        this.userSessions.delete(userId);
      }
    }
  }

  /**
   * Record token reuse attempt (potential attack)
   */
  recordTokenReuse(userId: string, ip: string, tokenType: 'access' | 'refresh'): void {
    if (!this.config.enabled) return;

    this.emit('securityEvent', {
      type: 'token_reuse',
      userId,
      ip,
      timestamp: new Date(),
      riskScore: 95,
      details: {
        tokenType,
        severity: 'high',
      },
    });
  }

  /**
   * Record rate limit exceeded
   */
  recordRateLimitExceeded(ip: string, endpoint: string): void {
    if (!this.config.enabled) return;

    this.emit('securityEvent', {
      type: 'rate_limit_exceeded',
      ip,
      timestamp: new Date(),
      riskScore: 40,
      details: {
        endpoint,
      },
    });
  }

  /**
   * Check if IP is blocked
   */
  isBlocked(ip: string): boolean {
    const blockedUntil = this.blockedIPs.get(ip);
    if (!blockedUntil) return false;

    if (Date.now() > blockedUntil) {
      this.blockedIPs.delete(ip);
      return false;
    }

    return true;
  }

  /**
   * Block an IP address
   */
  blockIP(ip: string, reason: string): void {
    const blockedUntil = Date.now() + this.config.blockDuration;
    this.blockedIPs.set(ip, blockedUntil);

    this.emit('securityEvent', {
      type: 'ip_blocked',
      ip,
      timestamp: new Date(),
      riskScore: 100,
      details: {
        reason,
        blockedUntil: new Date(blockedUntil),
        duration: this.config.blockDuration,
      },
    });
  }

  /**
   * Unblock an IP address
   */
  unblockIP(ip: string): void {
    this.blockedIPs.delete(ip);
    this.failedAttempts.delete(ip);
  }

  /**
   * Get security statistics
   */
  getStats(): {
    blockedIPs: number;
    failedAttempts: number;
    activeSessions: number;
  } {
    return {
      blockedIPs: this.blockedIPs.size,
      failedAttempts: this.failedAttempts.size,
      activeSessions: Array.from(this.userSessions.values()).reduce(
        (sum, sessions) => sum + sessions.size,
        0
      ),
    };
  }

  /**
   * Get blocked IPs list
   */
  getBlockedIPs(): Array<{ ip: string; blockedUntil: Date }> {
    const now = Date.now();
    const result: Array<{ ip: string; blockedUntil: Date }> = [];

    for (const [ip, blockedUntil] of this.blockedIPs.entries()) {
      if (now < blockedUntil) {
        result.push({
          ip,
          blockedUntil: new Date(blockedUntil),
        });
      }
    }

    return result;
  }

  /**
   * Middleware to check if IP is blocked
   */
  checkBlockedMiddleware(req: any, res: any, next: any): void {
    if (!this.config.enabled) {
      return next();
    }

    const ip = req.ip || req.connection?.remoteAddress || 'unknown';

    if (this.isBlocked(ip)) {
      const blockedUntil = this.blockedIPs.get(ip);
      const retryAfter = blockedUntil ? Math.ceil((blockedUntil - Date.now()) / 1000) : 1800;

      res.status(403).json({
        error: 'Access denied',
        message: 'IP address has been temporarily blocked due to suspicious activity.',
        retryAfter,
        blockedUntil: blockedUntil ? new Date(blockedUntil) : undefined,
      });
      return;
    }

    next();
  }

  /**
   * Start cleanup job
   */
  private startCleanupJob(): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();

      // Cleanup expired failed attempts
      for (const [ip, attempt] of this.failedAttempts.entries()) {
        if (now - attempt.lastAttempt > this.config.failedAttemptsWindow) {
          this.failedAttempts.delete(ip);
        }
      }

      // Cleanup expired blocks
      for (const [ip, blockedUntil] of this.blockedIPs.entries()) {
        if (now > blockedUntil) {
          this.blockedIPs.delete(ip);
        }
      }
    }, 60 * 1000); // Cleanup every minute
  }

  /**
   * Stop cleanup job
   */
  stopCleanupJob(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.rateLimitService.stopCleanupJob();
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.failedAttempts.clear();
    this.blockedIPs.clear();
    this.userSessions.clear();
  }
}
