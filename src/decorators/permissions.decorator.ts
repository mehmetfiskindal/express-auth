import 'reflect-metadata';

export const PERMISSIONS_METADATA_KEY = Symbol('auth:permissions');

/**
 * @Permissions() decorator
 * Route için gerekli permission'ları belirtir (herhangi biri yeterli)
 */
export function Permissions(...permissions: string[]): MethodDecorator {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    const existingPermissions = Reflect.getMetadata(PERMISSIONS_METADATA_KEY, target, propertyKey) || [];
    Reflect.defineMetadata(
      PERMISSIONS_METADATA_KEY,
      [...existingPermissions, ...permissions],
      target,
      propertyKey
    );
    return descriptor;
  };
}

/**
 * Get required permissions for route
 */
export function getRequiredPermissions(
  target: object,
  propertyKey: string | symbol
): string[] {
  return Reflect.getMetadata(PERMISSIONS_METADATA_KEY, target, propertyKey) || [];
}

/**
 * Check if route has permission requirements
 */
export function hasPermissionRequirements(
  target: object,
  propertyKey: string | symbol
): boolean {
  const permissions = getRequiredPermissions(target, propertyKey);
  return permissions.length > 0;
}
