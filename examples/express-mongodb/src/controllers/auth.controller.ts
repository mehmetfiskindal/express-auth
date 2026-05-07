import { Request, Response } from 'express';
import {
  Controller,
  Post,
  Get,
  Route,
  Body,
  Tags,
  Summary,
  Description,
  Response as ApiResponse,
  Security,
} from '@developersailor/express-openapi-decorators';
import { createAuthRouter, AuthConfig } from '@developersailor/express-auth';

/**
 * Authentication Controller
 * Handles user registration, login, logout, and token refresh
 */
@Controller('/auth')
@Tags('Authentication')
export class AuthController {
  private authRouter: ReturnType<typeof createAuthRouter>;

  constructor(authConfig: AuthConfig) {
    this.authRouter = createAuthRouter(authConfig);
  }

  /**
   * Get the Express router
   */
  getRouter() {
    return this.authRouter;
  }
}

/**
 * Auth Request/Response Schemas for OpenAPI documentation
 * These are used for Swagger UI documentation
 */
export const AuthSchemas = {
  RegisterRequest: {
    type: 'object',
    required: ['email', 'password'],
    properties: {
      email: {
        type: 'string',
        format: 'email',
        description: 'User email address',
        example: 'user@example.com',
      },
      password: {
        type: 'string',
        format: 'password',
        description: 'User password (min 8 chars, must include uppercase, lowercase, number, special char)',
        example: 'SecurePass123!',
      },
      roles: {
        type: 'array',
        items: { type: 'string' },
        description: 'User roles (optional)',
        example: ['user'],
      },
    },
  },
  LoginRequest: {
    type: 'object',
    required: ['email', 'password'],
    properties: {
      email: {
        type: 'string',
        format: 'email',
        description: 'User email address',
        example: 'user@example.com',
      },
      password: {
        type: 'string',
        format: 'password',
        description: 'User password',
        example: 'SecurePass123!',
      },
    },
  },
  RefreshTokenRequest: {
    type: 'object',
    required: ['refreshToken'],
    properties: {
      refreshToken: {
        type: 'string',
        description: 'Refresh token obtained from login',
        example: 'eyJhbGciOiJIUzI1NiIs...',
      },
    },
  },
  TokenResponse: {
    type: 'object',
    properties: {
      accessToken: {
        type: 'string',
        description: 'JWT access token',
      },
      refreshToken: {
        type: 'string',
        description: 'JWT refresh token',
      },
      expiresIn: {
        type: 'number',
        description: 'Access token expiration time in seconds',
        example: 900,
      },
    },
  },
  UserResponse: {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        description: 'User ID',
      },
      email: {
        type: 'string',
        format: 'email',
      },
      roles: {
        type: 'array',
        items: { type: 'string' },
      },
      isActive: {
        type: 'boolean',
      },
      createdAt: {
        type: 'string',
        format: 'date-time',
      },
    },
  },
  LoginResponse: {
    type: 'object',
    properties: {
      user: {
        $ref: '#/components/schemas/UserResponse',
      },
      tokens: {
        $ref: '#/components/schemas/TokenResponse',
      },
    },
  },
  MessageResponse: {
    type: 'object',
    properties: {
      message: {
        type: 'string',
      },
    },
  },
  ErrorResponse: {
    type: 'object',
    properties: {
      error: {
        type: 'string',
      },
    },
  },
};
