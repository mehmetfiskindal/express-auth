import { Request, Response, NextFunction } from 'express';
import { JWTService } from '../services';
import { AuthenticatedRequest, JWTPayload, UserRepository, AuthorizationConfig, AuthUser } from '../types';

// Simple in-memory cache for user data
const userCache = new Map<string, { user: AuthUser; expiresAt: number }>();

/**
 * Clear user cache (useful for testing or manual cache invalidation)
 */
export function clearUserCache(): void {
  userCache.clear();
}

/**
 * Get cached user or null
 */
function getCachedUser(userId: string): AuthUser | null {
  const cached = userCache.get(userId);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.user;
  }
  if (cached) {
    userCache.delete(userId);
  }
  return null;
}

/**
 * Set user in cache
 */
function setCachedUser(userId: string, user: AuthUser, ttlSeconds: number): void {
  userCache.set(userId, {
    user,
    expiresAt: Date.now() + (ttlSeconds * 1000),
  });
}

/**
 * JWT Authentication Middleware
 * Bearer token'ı doğrular ve req.user'a ekler
 * 
 * @param jwtService - JWT servisi
 * @param options - Middleware seçenekleri
 */
export function createAuthMiddleware(
  jwtService: JWTService,
  options?: {
    errorMessages?: { unauthorized?: string; tokenExpired?: string; invalidToken?: string };
    userRepository?: UserRepository;
    authorization?: AuthorizationConfig;
  }
) {
  const messages = {
    unauthorized: options?.errorMessages?.unauthorized || 'Unauthorized',
    tokenExpired: options?.errorMessages?.tokenExpired || 'Token expired',
    invalidToken: options?.errorMessages?.invalidToken || 'Invalid token',
  };

  const loadUserOnRequest = options?.authorization?.loadUserOnRequest || false;
  const userRepository = options?.userRepository;
  const cacheTTL = options?.authorization?.userCacheTTL || 60;
  const getRoles = options?.authorization?.getRoles || ((user: AuthUser) => user.roles || []);
  const getPermissions = options?.authorization?.getPermissions || ((user: AuthUser) => user.permissions || []);

  return async function authMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // Get token from Authorization header
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: messages.unauthorized });
        return;
      }

      const token = authHeader.substring(7); // Remove 'Bearer '

      if (!token) {
        res.status(401).json({ error: messages.unauthorized });
        return;
      }

      // Verify token
      const payload = jwtService.verifyAccessToken(token);

      let finalPayload: JWTPayload = payload;

      // If loadUserOnRequest is enabled, fetch fresh user data from DB
      if (loadUserOnRequest) {
        if (!userRepository) {
          res.status(500).json({ error: 'Auth middleware is missing userRepository' });
          return;
        }

        try {
          // Check cache first
          let user = getCachedUser(payload.sub);

          if (!user) {
            // Fetch from database
            user = await userRepository.findById(payload.sub);
            
            if (user) {
              // Cache the user data
              setCachedUser(payload.sub, user, cacheTTL);
            }
          }

          if (!user || user.isActive === false) {
            res.status(401).json({ error: messages.unauthorized });
            return;
          }

          // Update payload with fresh roles/permissions from DB
          finalPayload = {
            ...payload,
            roles: getRoles(user),
            permissions: getPermissions(user),
          };
        } catch (dbError) {
          console.error('Error loading user from DB:', dbError);
          res.status(503).json({ error: 'Unable to verify user' });
          return;
        }
      }

      // Attach user to request
      (req as AuthenticatedRequest).user = finalPayload;

      next();
    } catch (error) {
      if (error instanceof Error) {
        if (error.message === 'Token expired') {
          res.status(401).json({ error: messages.tokenExpired });
          return;
        }
        if (error.message === 'Invalid token') {
          res.status(401).json({ error: messages.invalidToken });
          return;
        }
      }
      res.status(401).json({ error: messages.unauthorized });
    }
  };
}

/**
 * Optional authentication middleware
 * Token varsa doğrular, yoksa devam eder
 */
export function createOptionalAuthMiddleware(jwtService: JWTService) {
  return function optionalAuthMiddleware(
    req: Request,
    _res: Response,
    next: NextFunction
  ): void {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        next();
        return;
      }

      const token = authHeader.substring(7);
      
      if (!token) {
        next();
        return;
      }

      const payload = jwtService.verifyAccessToken(token);
      (req as AuthenticatedRequest).user = payload;

      next();
    } catch {
      // Token invalid but that's okay for optional auth
      next();
    }
  };
}

/**
 * Get user from request (helper function)
 */
export function getUser(req: Request): JWTPayload | undefined {
  return (req as AuthenticatedRequest).user;
}

/**
 * Check if user is authenticated (helper function)
 */
export function isAuthenticated(req: Request): boolean {
  return !!(req as AuthenticatedRequest).user;
}
