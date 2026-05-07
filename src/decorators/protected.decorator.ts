import 'reflect-metadata';

export const AUTH_METADATA_KEY = Symbol('auth:protected');

/**
 * @Protected() decorator
 * Route'un authentication gerektirdiğini belirtir
 */
export function Protected(): MethodDecorator {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    Reflect.defineMetadata(AUTH_METADATA_KEY, { protected: true }, target, propertyKey);
    return descriptor;
  };
}

/**
 * @Public() decorator
 * Route'un public olduğunu belirtir (auth gerekmez)
 */
export function Public(): MethodDecorator {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    Reflect.defineMetadata(AUTH_METADATA_KEY, { protected: false }, target, propertyKey);
    return descriptor;
  };
}

/**
 * Check if route is protected
 */
export function isRouteProtected(
  target: object,
  propertyKey: string | symbol
): boolean {
  const metadata = Reflect.getMetadata(AUTH_METADATA_KEY, target, propertyKey);
  // Default to protected if not specified
  return metadata?.protected !== false;
}

/**
 * Check if route has explicit auth metadata
 */
export function hasAuthMetadata(
  target: object,
  propertyKey: string | symbol
): boolean {
  return Reflect.hasMetadata(AUTH_METADATA_KEY, target, propertyKey);
}
