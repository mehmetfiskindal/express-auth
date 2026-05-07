import 'reflect-metadata';

export const ROLES_METADATA_KEY = Symbol('auth:roles');

/**
 * @Roles() decorator
 * Route için gerekli rolleri belirtir
 */
export function Roles(...roles: string[]): MethodDecorator {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    const existingRoles = Reflect.getMetadata(ROLES_METADATA_KEY, target, propertyKey) || [];
    Reflect.defineMetadata(
      ROLES_METADATA_KEY,
      [...existingRoles, ...roles],
      target,
      propertyKey
    );
    return descriptor;
  };
}

/**
 * Get required roles for route
 */
export function getRequiredRoles(
  target: object,
  propertyKey: string | symbol
): string[] {
  return Reflect.getMetadata(ROLES_METADATA_KEY, target, propertyKey) || [];
}

/**
 * Check if route has role requirements
 */
export function hasRoleRequirements(
  target: object,
  propertyKey: string | symbol
): boolean {
  const roles = getRequiredRoles(target, propertyKey);
  return roles.length > 0;
}
