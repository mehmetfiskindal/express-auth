import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest, AuthorizationConfig } from '../types';

/**
 * Default authorization config
 */
const defaultAuthzConfig: Required<AuthorizationConfig> = {
  getRoles: (user: any) => user.roles || [],
  getPermissions: (user: any) => user.permissions || [],
  loadUserOnRequest: false,
  userCacheTTL: 60,
  ownershipBypassRoles: ['admin'],
  hierarchicalPermissions: false,
};

/**
 * Role-based authorization middleware factory
 * Belirtilen rollerden en az birine sahip olmalı
 * 
 * @param allowedRoles - İzin verilen roller
 * @param authzConfig - Authorization yapılandırması (opsiyonel)
 */
export function requireRoles(
  ...allowedRoles: string[]
) {
  return function roleMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    const user = (req as AuthenticatedRequest).user;

    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const userRoles = user.roles || [];

    // Check if user has any of the required roles
    const hasRole = allowedRoles.some(role => userRoles.includes(role));

    if (!hasRole) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Require all specified roles
 * Belirtilen tüm rollere sahip olmalı
 */
export function requireAllRoles(...requiredRoles: string[]) {
  return function roleMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    const user = (req as AuthenticatedRequest).user;

    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const userRoles = user.roles || [];

    // Check if user has all required roles
    const hasAllRoles = requiredRoles.every(role => userRoles.includes(role));

    if (!hasAllRoles) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Custom check middleware
 */
export function requirePermission(
  checkFn: (user: AuthenticatedRequest['user']) => boolean
) {
  return function permissionMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    const user = (req as AuthenticatedRequest).user;

    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    if (!checkFn(user)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Resource ownership check
 * Kullanıcı kendi kaynağına mı erişiyor kontrolü
 * 
 * @param getUserIdFromRequest - Request'ten kaynak sahibi ID'sini çıkaran fonksiyon
 * @param bypassRoles - Bu rollere sahip kullanıcılar bypass eder (varsayılan: ['admin'])
 */
export function requireOwnership(
  getUserIdFromRequest: (req: Request) => string,
  bypassRoles?: string[]
) {
  return function ownershipMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    const user = (req as AuthenticatedRequest).user;

    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const resourceUserId = getUserIdFromRequest(req);
    const rolesToBypass = bypassRoles || defaultAuthzConfig.ownershipBypassRoles;

    // Bypass rollerine sahip kullanıcılar her zaman erişebilir
    const hasBypassRole = user.roles?.some(role => rolesToBypass.includes(role));
    if (hasBypassRole) {
      next();
      return;
    }

    // Kendi kaynağı mı?
    if (user.sub !== resourceUserId) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}
