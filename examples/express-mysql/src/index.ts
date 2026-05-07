import 'reflect-metadata';
import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { DataSource } from 'typeorm';
import { createAuthRouter, createAuthMiddleware, requireRoles, JWTService } from '@developersailor/express-auth';
import { createRouterFromControllers } from '@developersailor/express-openapi-decorators';
import { User, RefreshToken } from './entities';
import { MySQLUserRepository, MySQLRefreshTokenRepository } from './repositories';
import { AuthController, ProfileController } from './controllers';
import swaggerUi from 'swagger-ui-express';
import { openApiConfig } from './openapi.config';

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'REFRESH_TOKEN_SECRET', 'DB_HOST', 'DB_PORT', 'DB_USERNAME', 'DB_PASSWORD', 'DB_NAME'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: ${envVar} environment variable is required`);
    process.exit(1);
  }
}

// Initialize TypeORM DataSource
const dataSource = new DataSource({
  type: 'mysql',
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT!),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  entities: [User, RefreshToken],
  synchronize: process.env.NODE_ENV !== 'production',
  logging: process.env.NODE_ENV === 'development',
});

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Connect to MySQL
async function connectDatabase() {
  try {
    await dataSource.initialize();
    console.log('✅ Connected to MySQL database');
  } catch (error) {
    console.error('❌ MySQL connection error:', error);
    process.exit(1);
  }
}

// Initialize repositories
const userRepository = new MySQLUserRepository(dataSource.getRepository(User));
const refreshTokenRepository = new MySQLRefreshTokenRepository(dataSource.getRepository(RefreshToken));

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
const profileController = new ProfileController(jwtService);

// Mount auth routes
app.use('/auth', authController.getRouter());

// Mount API routes using decorators router
const apiRouter = createRouterFromControllers([profileController]);
app.use('/api', apiRouter);

// Swagger/OpenAPI Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiConfig, {
  explorer: true,
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Express Auth API Documentation - MySQL',
}));

// OpenAPI JSON endpoint
app.get('/api-docs.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(openApiConfig);
});

// Health check
app.get('/health', async (req, res) => {
  const isConnected = dataSource.isInitialized;
  
  res.json({ 
    status: 'ok', 
    database: isConnected ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString() 
  });
});

// Error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;

async function startServer() {
  await connectDatabase();
  
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
}

startServer();

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (dataSource.isInitialized) {
    await dataSource.destroy();
  }
  process.exit(0);
});
