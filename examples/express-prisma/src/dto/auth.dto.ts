/**
 * Data Transfer Objects for Auth operations
 */

export class RegisterRequest {
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  password!: string;

  @IsOptional()
  @IsArray()
  roles?: string[];
}

export class LoginRequest {
  @IsEmail()
  email!: string;

  @IsString()
  password!: string;
}

export class RefreshTokenRequest {
  @IsString()
  refreshToken!: string;
}

export class TokenResponse {
  accessToken!: string;
  refreshToken!: string;
  expiresIn!: number;
}

export class UserResponse {
  id!: string;
  email!: string;
  roles!: string[];
  isActive!: boolean;
  createdAt?: Date;
}

export class LoginResponse {
  user!: UserResponse;
  tokens!: TokenResponse;
}

export class MessageResponse {
  message!: string;
}

// Decorator stubs for validation (or you can use class-validator)
function IsEmail() {
  return function (target: any, propertyKey?: string | symbol, context?: any) {};
}

function IsString() {
  return function (target: any, propertyKey?: string | symbol, context?: any) {};
}

function MinLength(min: number) {
  return function (target: any, propertyKey?: string | symbol, context?: any) {};
}

function IsOptional() {
  return function (target: any, propertyKey?: string | symbol, context?: any) {};
}

function IsArray() {
  return function (target: any, propertyKey?: string | symbol, context?: any) {};
}
