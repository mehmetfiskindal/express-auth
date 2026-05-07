import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest, Permission } from '../types';

/**
 * Permission utility functions
 */

/**
 * Check if user has a specific permission (flat format)
 * @param userPermissions - User's permissions array
 * @param requiredPermission - Required permission string
 */
function hasFlatPermission(userPermissions: Permission[], requiredPermission: string): boolean {
  return userPermissions.some(perm => {
    if (typeof perm === 'string') {
      // Direct match
      if (perm === requiredPermission) return true;
      // Wildcard match (e.g., "user.*" matches "user.read")
      if (perm.endsWith('.*')) {
        const prefix = perm.slice(0, -2);
        return requiredPermission.startsWith(prefix + '.');
      }
    }
    return false;
  });
}

/**
 * Check if user has a specific permission (hierarchical format)
 * @param userPermissions - User's permissions object
 * @param requiredPermission - Required permission string (e.g., "user.read")
 */
function hasHierarchicalPermission(
  userPermissions: Record<string, boolean | Record<string, boolean>>,
  requiredPermission: string
): boolean {
  const parts = requiredPermission.split('.');
  
  if (parts.length === 2) {
    const [resource, action] = parts;
    const resourcePerms = userPermissions[resource];
    
    if (typeof resourcePerms === 'boolean') {
      return resourcePerms; // Full access to resource
    }
    
    if (typeof resourcePerms === 'object') {
      // Check specific action or wildcard
      return resourcePerms[action] === true || resourcePerms['*'] === true;
    }
  }
  
  return false;
}

/**
 * Check if user has a permission (auto-detects format)
 */
function checkPermission(
  userPermissions: Permission[],
  requiredPermission: string,
  hierarchical: boolean = false
): boolean {
  if (hierarchical) {
    // Convert flat array to hierarchical object for checking
    const hierarchicalPerms: Record<string, boolean | Record<string, boolean>> = {};
    
    for (const perm of userPermissions) {
      if (typeof perm === 'string') {
        const parts = perm.split('.');
        if (parts.length === 2) {
          const [resource, action] = parts;
          if (!hierarchicalPerms[resource]) {
            hierarchicalPerms[resource] = {};
          }
          if (typeof hierarchicalPerms[resource] === 'object') {
            (hierarchicalPerms[resource] as Record<string, boolean>)[action] = true;
          }
        }
      } else if (typeof perm === 'object') {
        Object.assign(hierarchicalPerms, perm);
      }
    }
    
    return hasHierarchicalPermission(hierarchicalPerms, requiredPermission);
  }
  
  return hasFlatPermission(userPermissions, requiredPermission);
}

/**
 * Require at least one of the specified permissions
 * Herhangi biri yeterli
 */
export function requirePermissions(
  ...requiredPermissions: string[]
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

    const userPermissions = user.permissions || [];

    // Check if user has any of the required permissions
    const hasPermission = requiredPermissions.some(reqPerm =>
      checkPermission(userPermissions, reqPerm, false)
    );

    if (!hasPermission) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Require all specified permissions
 * Hepsi gerekli
 */
export function requireAllPermissions(
  ...requiredPermissions: string[]
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

    const userPermissions = user.permissions || [];

    // Check if user has all required permissions
    const hasAllPermissions = requiredPermissions.every(reqPerm =>
      checkPermission(userPermissions, reqPerm, false)
    );

    if (!hasAllPermissions) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Require permission with custom check function
 */
export function requirePermissionCheck(
  checkFn: (permissions: Permission[]) => boolean
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

    const userPermissions = user.permissions || [];

    if (!checkFn(userPermissions)) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

/**
 * Combined role and permission check
 * Hem rol hem permission kontrolü (herhangi biri yeterli)
 */
export function requireRolesOrPermissions(
  roles: string[] = [],
  permissions: string[] = []
) {
  return function combinedMiddleware(
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
    const userPermissions = user.permissions || [];

    // Check roles
    const hasRole = roles.length === 0 || roles.some(role => userRoles.includes(role));

    // Check permissions
    const hasPermission = permissions.length === 0 || permissions.some(perm =>
      checkPermission(userPermissions, perm, false)
    );

    // Must have at least one role OR at least one permission
    if (!hasRole && !hasPermission) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}

export { checkPermission, hasFlatPermission, hasHierarchicalPermission };
