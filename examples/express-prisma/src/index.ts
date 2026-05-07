import 'reflect-metadata';
import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import { createAuthRouter, createAuthMiddleware, requireRoles, JWTService } from '@developersailor/express-auth';
import { ExpressAdapter } from '@developersailor/express-openapi-decorators';
import { PrismaUserRepository, PrismaRefreshTokenRepository } from './repositories';
import { AuthController, ProfileController } from './controllers';
import swaggerUi from 'swagger-ui-express';
import { openApiConfig } from './openapi.config';

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'REFRESH_TOKEN_SECRET', 'DATABASE_URL'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: ${envVar} environment variable is required`);
    process.exit(1);
  }
}

const app = express();
const prisma = new PrismaClient();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Initialize repositories
const userRepository = new PrismaUserRepository(prisma);
const refreshTokenRepository = new PrismaRefreshTokenRepository(prisma);

// Initialize auth router
const authConfig = {
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
  repositories: {
    userRepository,
    refreshTokenRepository,
  },
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' as const,
  },
  passwordRules: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
  },
};

// Initialize JWT service for middleware
const jwtService = new JWTService({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
});

// Initialize controllers
const authController = new AuthController(authConfig);

// Mount auth routes using decorators
app.use('/auth', authController.getRouter());

// Mount API routes using decorators router with ExpressAdapter
// Use ExpressAdapter to provide custom controller factory
const adapter = new ExpressAdapter(app, {
  controllerFactory: (controllerClass) => {
    if (controllerClass === ProfileController) {
      return new ProfileController(jwtService);
    }
    return new (controllerClass as any)();
  },
  namedMiddlewares: {
    auth: createAuthMiddleware(jwtService),
    'roles:admin': requireRoles(['admin']),
  },
});
adapter.registerControllers([ProfileController]);

// Swagger/OpenAPI Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiConfig, {
  explorer: true,
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Express Auth API Documentation',
}));

// OpenAPI JSON endpoint
app.get('/api-docs.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(openApiConfig);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('');
  console.log('📚 API Documentation:');
  console.log(`  Swagger UI: http://localhost:${PORT}/api-docs`);
  console.log(`  OpenAPI JSON: http://localhost:${PORT}/api-docs.json`);
  console.log('');
  console.log('🔐 Authentication Endpoints:');
  console.log('  POST /auth/register    - Register new user');
  console.log('  POST /auth/login       - Login');
  console.log('  POST /auth/refresh     - Refresh access token');
  console.log('  POST /auth/logout      - Logout');
  console.log('  POST /auth/logout-all  - Logout from all devices');
  console.log('  GET  /auth/me          - Get current user');
  console.log('');
  console.log('👤 Profile Endpoints:');
  console.log('  GET /api/public        - Public endpoint');
  console.log('  GET /api/profile       - Protected endpoint (requires auth)');
  console.log('  GET /api/admin         - Admin only endpoint');
  console.log('');
  console.log('❤️  Health Check:');
  console.log('  GET /health            - Health check');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await prisma.$disconnect();
  process.exit(0);
});
