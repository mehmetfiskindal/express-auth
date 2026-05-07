import { OpenAPIObject, SecuritySchemeObject } from '@developersailor/express-openapi-decorators';
import { AuthSchemas } from './controllers/auth.controller';
import { ProfileSchemas } from './controllers/profile.controller';

/**
 * OpenAPI Configuration
 * Swagger/OpenAPI documentation setup
 */

export const openApiConfig: OpenAPIObject = {
  openapi: '3.0.0',
  info: {
    title: 'Express Auth API - MongoDB',
    description: 'Authentication API with JWT, Refresh Tokens, and Role-based Access Control using MongoDB',
    version: '1.0.0',
    contact: {
      name: 'DeveloperSailor',
      url: 'https://github.com/developersailor',
    },
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
  },
  servers: [
    {
      url: 'http://localhost:3000',
      description: 'Development server',
    },
  ],
  paths: {
    // Auth endpoints
    '/auth/register': {
      post: {
        tags: ['Authentication'],
        summary: 'Register new user',
        description: 'Create a new user account with email and password',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/RegisterRequest',
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'User registered successfully',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/UserResponse',
                },
              },
            },
          },
          '400': {
            description: 'Bad request - validation error',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/auth/login': {
      post: {
        tags: ['Authentication'],
        summary: 'Login user',
        description: 'Authenticate user and receive JWT tokens',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/LoginRequest',
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Login successful',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/LoginResponse',
                },
              },
            },
          },
          '401': {
            description: 'Invalid credentials',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/auth/refresh': {
      post: {
        tags: ['Authentication'],
        summary: 'Refresh access token',
        description: 'Get new access token using refresh token',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/RefreshTokenRequest',
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Token refreshed successfully',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/TokenResponse',
                },
              },
            },
          },
          '401': {
            description: 'Invalid refresh token',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/auth/logout': {
      post: {
        tags: ['Authentication'],
        summary: 'Logout user',
        description: 'Revoke current refresh token',
        requestBody: {
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/RefreshTokenRequest',
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Logout successful',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/MessageResponse',
                },
              },
            },
          },
        },
      },
    },
    '/auth/logout-all': {
      post: {
        tags: ['Authentication'],
        summary: 'Logout from all devices',
        description: 'Revoke all refresh tokens for the user',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Logged out from all devices',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/MessageResponse',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/auth/me': {
      get: {
        tags: ['Authentication'],
        summary: 'Get current user',
        description: 'Get details of the currently authenticated user',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Current user data',
            content: {
              'application/json': {
                schema: {
                  properties: {
                    user: {
                      $ref: '#/components/schemas/UserResponse',
                    },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    // Profile endpoints
    '/api/profile': {
      get: {
        tags: ['Profile'],
        summary: 'Get user profile',
        description: 'Get protected profile data for authenticated user',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Profile data',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ProfileResponse',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/api/admin': {
      get: {
        tags: ['Profile'],
        summary: 'Get admin data',
        description: 'Get admin-only data (requires admin role)',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': {
            description: 'Admin data',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/AdminDataResponse',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden - requires admin role',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/api/public': {
      get: {
        tags: ['Profile'],
        summary: 'Get public data',
        description: 'Get public data (no authentication required)',
        responses: {
          '200': {
            description: 'Public data',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PublicDataResponse',
                },
              },
            },
          },
        },
      },
    },
    '/health': {
      get: {
        tags: ['Health'],
        summary: 'Health check',
        description: 'Check if the API is running',
        responses: {
          '200': {
            description: 'API is healthy',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    status: {
                      type: 'string',
                      example: 'ok',
                    },
                    database: {
                      type: 'string',
                      example: 'connected',
                    },
                    timestamp: {
                      type: 'string',
                      format: 'date-time',
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  components: {
    schemas: {
      ...AuthSchemas,
      ...ProfileSchemas,
      ErrorResponse: {
        type: 'object',
        properties: {
          error: {
            type: 'string',
            description: 'Error message',
            example: 'Unauthorized',
          },
        },
      },
    },
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your JWT token in the format: Bearer <token>',
      } as SecuritySchemeObject,
    },
  },
};
