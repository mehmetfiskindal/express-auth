import { Request, Response } from 'express';
import {
  Controller,
  Get,
  Route,
  Tags,
  Summary,
  Description,
  Response as ApiResponse,
  Security,
  Request as OpenApiRequest,
} from '@developersailor/express-openapi-decorators';
import { createAuthMiddleware, requireRoles, JWTService } from '@developersailor/express-auth';
import { ProfileResponse, AdminDataResponse, PublicDataResponse } from '../dto';

/**
 * Profile Controller
 * Protected user profile endpoints
 */
@Controller('/api')
@Tags('Profile')
export class ProfileController {
  private authMiddleware: ReturnType<typeof createAuthMiddleware>;

  constructor(jwtService: JWTService) {
    this.authMiddleware = createAuthMiddleware(jwtService);
  }

  /**
   * Get current user profile
   * Requires authentication
   */
  getProfileHandler() {
    return [
      this.authMiddleware,
      async (req: Request, res: Response) => {
        const user = (req as any).user;
        const response: ProfileResponse = {
          message: 'Protected profile data',
          userId: user.sub,
          email: user.email,
          roles: user.roles,
        };
        res.json(response);
      },
    ];
  }

  /**
   * Get admin only data
   * Requires authentication and admin role
   */
  getAdminHandler() {
    return [
      this.authMiddleware,
      requireRoles('admin'),
      async (req: Request, res: Response) => {
        const response: AdminDataResponse = {
          message: 'Admin only data',
          secret: 'This is only visible to admins',
        };
        res.json(response);
      },
    ];
  }

  /**
   * Public endpoint
   * No authentication required
   */
  getPublicHandler() {
    return [
      async (req: Request, res: Response) => {
        const response: PublicDataResponse = {
          message: 'This is public data',
        };
        res.json(response);
      },
    ];
  }
}

/**
 * Profile Request/Response Schemas for OpenAPI
 */
export const ProfileSchemas = {
  ProfileResponse: {
    type: 'object',
    properties: {
      message: {
        type: 'string',
        example: 'Protected profile data',
      },
      userId: {
        type: 'string',
        example: 'user-uuid-here',
      },
      email: {
        type: 'string',
        format: 'email',
        example: 'user@example.com',
      },
      roles: {
        type: 'array',
        items: { type: 'string' },
        example: ['user'],
      },
    },
  },
  AdminDataResponse: {
    type: 'object',
    properties: {
      message: {
        type: 'string',
        example: 'Admin only data',
      },
      secret: {
        type: 'string',
        example: 'This is only visible to admins',
      },
    },
  },
  PublicDataResponse: {
    type: 'object',
    properties: {
      message: {
        type: 'string',
        example: 'This is public data',
      },
    },
  },
};
