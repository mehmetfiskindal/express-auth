// Core exports
export * from './types';
export * from './services';
export * from './middleware';
export * from './decorators';
export * from './routes';

// Adapters
export * from './adapters';

// Convenience exports
export { createAuthRouter } from './routes';
export { JWTService, PasswordService } from './services';
export { 
  createAuthMiddleware, 
  requireRoles, 
  requireAllRoles, 
  requirePermission, 
  requireOwnership,
  requirePermissions,
  requireAllPermissions,
  requirePermissionCheck,
  requireRolesOrPermissions,
  clearUserCache,
} from './middleware';
export { Protected, Public, Roles, PublicRoute, Permissions } from './decorators';
export { createMemoryRepositories } from './adapters';

// Version
export const version = '1.0.0';
