import 'reflect-metadata';
import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import {
  createAuthRouter,
  createAuthMiddleware,
  requireRoles,
  JWTService,
  createSecurityMiddleware,
} from '@developersailor/express-auth';
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

// Initialize repositories
const userRepository = new PrismaUserRepository(prisma);
const refreshTokenRepository = new PrismaRefreshTokenRepository(prisma);

// Initialize auth router with comprehensive security configuration
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
  // Rate limiting configuration
  rateLimit: {
    enabled: true,
    general: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 100,
    },
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 5, // Stricter for auth endpoints
    },
    strict: {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxRequests: 10, // Very strict
    },
  },
  // CORS configuration
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? (process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'])
      : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true,
  },
  // HTTPS enforcement (only in production)
  https: {
    enabled: process.env.NODE_ENV === 'production',
  },
  // Security monitoring
  securityMonitor: {
    enabled: true,
    maxFailedAttempts: 5,
    failedAttemptsWindow: 15 * 60 * 1000, // 15 minutes
    blockDuration: 30 * 60 * 1000, // 30 minutes
    trackConcurrentLogins: true,
    maxConcurrentSessions: 5,
  },
  // Token cleanup job
  tokenCleanup: {
    enabled: true,
    interval: 60 * 60 * 1000, // 1 hour
    deleteAfterExpired: 24 * 60 * 60 * 1000, // 24 hours
    cleanupRevoked: true,
  },
};

// Create security middleware bundle
const security = createSecurityMiddleware(authConfig);

// Apply security middleware before body parsing
security.apply(app);

// Body parsing middleware
app.use(express.json());
app.use(cookieParser());

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
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    security: security.getStats(),
  });
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
  console.log('🛡️  Security Features Enabled:');
  console.log('  ✅ Rate Limiting: General (100/15min), Auth (5/15min)');
  console.log('  ✅ CORS: Configured for development/production');
  console.log('  ✅ Security Monitoring: Brute-force detection enabled');
  console.log('  ✅ Token Cleanup: Running every hour');
  console.log('  ✅ Security Headers: X-Frame-Options, CSP, HSTS');
  if (process.env.NODE_ENV === 'production') {
    console.log('  ✅ HTTPS Enforcement: Enabled');
  }
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
  console.log('  GET  /auth/security/stats - Security statistics (admin)');
  console.log('');
  console.log('👤 Profile Endpoints:');
  console.log('  GET /api/public        - Public endpoint');
  console.log('  GET /api/profile       - Protected endpoint (requires auth)');
  console.log('  GET /api/admin         - Admin only endpoint');
  console.log('');
  console.log('❤️  Health Check:');
  console.log('  GET /health            - Health check with security stats');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  security.cleanup();
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  security.cleanup();
  await prisma.$disconnect();
  process.exit(0);
});
