import { Request, Response } from 'express';
import {
  Controller,
  Get,
  Tags,
  Summary,
  Description,
  ApiResponse,
  Security,
  createRouterFromControllers,
  Middleware,
} from '@developersailor/express-openapi-decorators';
import { createAuthMiddleware, requireRoles, JWTService } from '@developersailor/express-auth';

/**
 * Profile Controller
 * Protected user profile endpoints using decorators
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
  @Get('/profile')
  @Summary('Get user profile')
  @Description('Get protected profile data for authenticated user')
  @Security('bearerAuth')
  @ApiResponse(200, 'Profile data retrieved successfully', 'ProfileResponse')
  @ApiResponse(401, 'Unauthorized')
  @Middleware('auth')
  async getProfile(req: Request, res: Response) {
    const user = (req as any).user;
    res.json({
      message: 'Protected profile data',
      userId: user.sub,
      email: user.email,
      roles: user.roles,
    });
  }

  /**
   * Get admin only data
   * Requires authentication and admin role
   */
  @Get('/admin')
  @Summary('Get admin data')
  @Description('Get admin-only data (requires admin role)')
  @Security('bearerAuth')
  @ApiResponse(200, 'Admin data retrieved successfully', 'AdminDataResponse')
  @ApiResponse(401, 'Unauthorized')
  @ApiResponse(403, 'Forbidden - requires admin role')
  @Middleware('auth')
  @Middleware('roles:admin')
  async getAdminData(req: Request, res: Response) {
    res.json({
      message: 'Admin only data',
      secret: 'This is only visible to admins',
    });
  }

  /**
   * Public endpoint
   * No authentication required
   */
  @Get('/public')
  @Summary('Get public data')
  @Description('Get public data (no authentication required)')
  @ApiResponse(200, 'Public data retrieved successfully', 'PublicDataResponse')
  async getPublicData(req: Request, res: Response) {
    res.json({ message: 'This is public data' });
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
