import 'reflect-metadata';

export const PUBLIC_METADATA_KEY = Symbol('auth:public');

/**
 * @Public() decorator - Alternative syntax
 * Route'un herkese açık olduğunu belirtir
 */
export function PublicRoute(): MethodDecorator {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    Reflect.defineMetadata(PUBLIC_METADATA_KEY, true, target, propertyKey);
    return descriptor;
  };
}

/**
 * Check if route is explicitly public
 */
export function isRoutePublic(
  target: object,
  propertyKey: string | symbol
): boolean {
  return Reflect.getMetadata(PUBLIC_METADATA_KEY, target, propertyKey) === true;
}
