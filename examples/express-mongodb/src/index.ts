import 'reflect-metadata';
import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { createAuthRouter, createAuthMiddleware, requireRoles, JWTService } from '@developersailor/express-auth';
import { MongoUserRepository, MongoRefreshTokenRepository } from './repositories';

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'REFRESH_TOKEN_SECRET', 'MONGODB_URI'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: ${envVar} environment variable is required`);
    process.exit(1);
  }
}

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
async function connectDatabase() {
  try {
    await mongoose.connect(process.env.MONGODB_URI!);
    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
}

// Initialize repositories
const userRepository = new MongoUserRepository();
const refreshTokenRepository = new MongoRefreshTokenRepository();

// Initialize auth router
const authRouter = createAuthRouter({
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
    sameSite: 'strict',
  },
  passwordRules: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
  },
});

// Mount auth routes
app.use('/auth', authRouter);

// Initialize JWT service for middleware
const jwtService = new JWTService({
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
});

const authMiddleware = createAuthMiddleware(jwtService);

// Protected routes
app.get('/api/profile', authMiddleware, async (req, res) => {
  const user = (req as any).user;
  res.json({
    message: 'Protected profile data',
    userId: user.sub,
    email: user.email,
    roles: user.roles,
  });
});

app.get('/api/admin', authMiddleware, requireRoles('admin'), async (req, res) => {
  res.json({
    message: 'Admin only data',
    secret: 'This is only visible to admins',
  });
});

app.get('/api/public', (req, res) => {
  res.json({ message: 'This is public data' });
});

// Health check
app.get('/health', async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStatus = dbState === 1 ? 'connected' : 'disconnected';
  
  res.json({ 
    status: 'ok', 
    database: dbStatus,
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
    console.log('📚 Available endpoints:');
    console.log('  POST /auth/register    - Register new user');
    console.log('  POST /auth/login       - Login');
    console.log('  POST /auth/refresh     - Refresh access token');
    console.log('  POST /auth/logout      - Logout');
    console.log('  POST /auth/logout-all  - Logout from all devices');
    console.log('  GET  /auth/me          - Get current user');
    console.log('  GET  /api/public       - Public endpoint');
    console.log('  GET  /api/profile      - Protected endpoint (requires auth)');
    console.log('  GET  /api/admin        - Admin only endpoint');
    console.log('  GET  /health           - Health check');
  });
}

startServer();

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});
