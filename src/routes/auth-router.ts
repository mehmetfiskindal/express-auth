import { Router, Request, Response } from 'express';
import { JWTService, PasswordService, SecurityMonitor, TokenCleanupJob } from '../services';
import { AuthConfig, LoginResult, RefreshResult, AuthenticatedRequest } from '../types';
import { createAuthMiddleware } from '../middleware';

/**
 * Auth Router oluştur
 * /login, /register, /refresh, /logout endpointleri
 */
export function createAuthRouter(config: AuthConfig): Router {
  const router = Router();
  const jwtService = new JWTService({
    jwtSecret: config.jwtSecret,
    refreshTokenSecret: config.refreshTokenSecret,
    accessTokenExpiresIn: config.accessTokenExpiresIn,
    refreshTokenExpiresIn: config.refreshTokenExpiresIn,
  });
  const passwordService = new PasswordService();

  const { userRepository, refreshTokenRepository } = config.repositories;

  // Authorization config
  const getRoles = config.authorization?.getRoles || ((user: any) => user.roles || []);
  const getPermissions = config.authorization?.getPermissions || ((user: any) => user.permissions || []);
  const loadUserOnRequest = config.authorization?.loadUserOnRequest || false;

  // Error messages (güvenlik için genel mesajlar)
  const errorMessages = {
    invalidCredentials: config.errorMessages?.invalidCredentials || 'Invalid email or password',
    unauthorized: config.errorMessages?.unauthorized || 'Unauthorized',
    invalidToken: config.errorMessages?.invalidToken || 'Invalid token',
  };

  // Initialize security monitor
  const securityMonitor = new SecurityMonitor(config.securityMonitor);

  // Initialize token cleanup job
  let tokenCleanupJob: TokenCleanupJob | null = null;
  if (config.tokenCleanup?.enabled !== false) {
    tokenCleanupJob = new TokenCleanupJob(refreshTokenRepository, config.tokenCleanup);
    tokenCleanupJob.start();
  }

  // Helper to get IP address
  const getClientIP = (req: Request): string => {
    return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
      || req.ip
      || req.connection?.remoteAddress
      || 'unknown';
  };

  // Helper to get user agent
  const getUserAgent = (req: Request): string | undefined => {
    return req.headers['user-agent'];
  };

  /**
   * POST /auth/register
   */
  router.post('/register', async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password, roles } = req.body;

      // Validasyon
      if (!email || !password) {
        res.status(400).json({ error: 'Email and password are required' });
        return;
      }

      // Email formatı kontrolü
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        res.status(400).json({ error: 'Invalid email format' });
        return;
      }

      // Password güçlülük kontrolü
      if (config.passwordRules) {
        const validation = passwordService.validatePasswordStrength(password, config.passwordRules);
        if (!validation.valid) {
          res.status(400).json({ error: 'Password too weak', details: validation.errors });
          return;
        }
      }

      // Email kullanımda mı?
      const existingUser = await userRepository.findByEmail(email);
      if (existingUser) {
        // Güvenlik: Aynı email kullanımda ama bunu belli etmemeliyiz
        // Sadece generic bir hata dönelim
        res.status(400).json({ error: 'Registration failed' });
        return;
      }

      // Password hash'le
      const passwordHash = await passwordService.hashPassword(password);

      // Kullanıcı oluştur
      const user = await userRepository.createUser({
        email,
        passwordHash,
        roles: roles || ['user'],
      });

      // Response'ta passwordHash dönmeyelim
      const { passwordHash: _, ...userWithoutPassword } = user;

      res.status(201).json({
        message: 'User registered successfully',
        user: userWithoutPassword,
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /auth/login
   */
  router.post('/login', async (req: Request, res: Response): Promise<void> => {
    const ip = getClientIP(req);
    const userAgent = getUserAgent(req);

    try {
      // Check if IP is blocked
      if (securityMonitor.isBlocked(ip)) {
        const blockedUntil = securityMonitor.getBlockedIPs().find(b => b.ip === ip)?.blockedUntil;
        res.status(403).json({
          error: 'Access denied',
          message: 'Too many failed login attempts. Please try again later.',
          blockedUntil,
        });
        return;
      }

      const { email, password } = req.body;

      // Validasyon
      if (!email || !password) {
        res.status(400).json({ error: 'Email and password are required' });
        return;
      }

      // Kullanıcıyı bul
      const user = await userRepository.findByEmail(email);

      // Kullanıcı yoksa veya şifre yanlışsa aynı hatayı dön
      // Güvenlik: hangisinin yanlış olduğunu belli etmeyelim
      if (!user) {
        // Record failed attempt
        securityMonitor.recordFailedAttempt(ip, email, userAgent);
        res.status(401).json({ error: errorMessages.invalidCredentials });
        return;
      }

      // Hesap aktif mi?
      if (user.isActive === false) {
        // Record failed attempt
        securityMonitor.recordFailedAttempt(ip, email, userAgent);
        res.status(401).json({ error: errorMessages.invalidCredentials });
        return;
      }

      // Şifreyi doğrula
      const isPasswordValid = await passwordService.verifyPassword(password, user.passwordHash);
      if (!isPasswordValid) {
        // Record failed attempt
        securityMonitor.recordFailedAttempt(ip, email, userAgent);
        res.status(401).json({ error: errorMessages.invalidCredentials });
        return;
      }

      // Record successful login
      securityMonitor.recordSuccessfulLogin(user.id, ip, userAgent);

      // Token üret - roller ve permission'lar JWT'ye eklenir
      const tokens = jwtService.generateTokenPair({
        sub: user.id,
        email: user.email,
        roles: getRoles(user),
        permissions: getPermissions(user),
      });

      // Refresh token'ı DB'ye kaydet
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7); // 7 gün

      await refreshTokenRepository.saveToken({
        token: tokens.refreshToken,
        userId: user.id,
        expiresAt,
        createdAt: new Date(),
      });

      // Cookie ayarları (opsiyonel)
      if (config.cookie) {
        res.cookie('refreshToken', tokens.refreshToken, {
          httpOnly: config.cookie.httpOnly ?? true,
          secure: config.cookie.secure ?? process.env.NODE_ENV === 'production',
          sameSite: config.cookie.sameSite ?? 'strict',
          domain: config.cookie.domain,
          path: config.cookie.path ?? '/auth/refresh',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 gün
        });
      }

      // Response
      const { passwordHash: _, ...userWithoutPassword } = user;

      const result: LoginResult = {
        user: userWithoutPassword,
        tokens,
      };

      res.json(result);
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /auth/refresh
   * Refresh token ile yeni access token al
   */
  router.post('/refresh', async (req: Request, res: Response): Promise<void> => {
    try {
      // Cookie veya body'den refresh token al
      const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

      if (!refreshToken) {
        res.status(401).json({ error: errorMessages.invalidToken });
        return;
      }

      // Refresh token'ı doğrula
      let payload;
      try {
        payload = jwtService.verifyRefreshToken(refreshToken);
      } catch {
        res.status(401).json({ error: errorMessages.invalidToken });
        return;
      }

      // Token DB'de kayıtlı mı ve revoke edilmemiş mi?
      const storedToken = await refreshTokenRepository.findToken(refreshToken);
      if (!storedToken || storedToken.revokedAt) {
        res.status(401).json({ error: errorMessages.invalidToken });
        return;
      }

      // Süresi dolmuş mu?
      if (new Date() > storedToken.expiresAt) {
        res.status(401).json({ error: errorMessages.invalidToken });
        return;
      }

      // Kullanıcıyı bul
      const user = await userRepository.findById(payload.sub);
      if (!user || user.isActive === false) {
        res.status(401).json({ error: errorMessages.unauthorized });
        return;
      }

      // Eski refresh token'ı revoke et (token rotation)
      await refreshTokenRepository.revokeToken(refreshToken);

      // Yeni token çifti üret - güncel roller ve permission'lar
      const tokens = jwtService.generateTokenPair({
        sub: user.id,
        email: user.email,
        roles: getRoles(user),
        permissions: getPermissions(user),
      });

      // Yeni refresh token'ı kaydet
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await refreshTokenRepository.saveToken({
        token: tokens.refreshToken,
        userId: user.id,
        expiresAt,
        createdAt: new Date(),
      });

      // Cookie güncelle
      if (config.cookie) {
        res.cookie('refreshToken', tokens.refreshToken, {
          httpOnly: config.cookie.httpOnly ?? true,
          secure: config.cookie.secure ?? process.env.NODE_ENV === 'production',
          sameSite: config.cookie.sameSite ?? 'strict',
          domain: config.cookie.domain,
          path: config.cookie.path ?? '/auth/refresh',
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
      }

      const result: RefreshResult = {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
      };

      res.json(result);
    } catch (error) {
      console.error('Refresh error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /auth/logout
   */
  router.post('/logout', createAuthMiddleware(jwtService, {
    errorMessages: config.errorMessages,
    userRepository: loadUserOnRequest ? userRepository : undefined,
    authorization: config.authorization,
  }), async (req: Request, res: Response): Promise<void> => {
    const user = (req as AuthenticatedRequest).user;
    const ip = getClientIP(req);

    try {
      const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

      if (refreshToken) {
        // Token'ı revoke et
        await refreshTokenRepository.revokeToken(refreshToken);
      }

      // Record logout
      if (user) {
        securityMonitor.recordLogout(user.sub, ip);
      }

      // Cookie'yi temizle
      if (config.cookie) {
        res.clearCookie('refreshToken', {
          httpOnly: config.cookie.httpOnly ?? true,
          secure: config.cookie.secure ?? process.env.NODE_ENV === 'production',
          sameSite: config.cookie.sameSite ?? 'strict',
          domain: config.cookie.domain,
          path: config.cookie.path ?? '/auth/refresh',
        });
      }

      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /auth/logout-all
   * Tüm cihazlardan çıkış yap (refresh token'ları revoke et)
   */
  router.post('/logout-all', createAuthMiddleware(jwtService, {
    errorMessages: config.errorMessages,
    userRepository: loadUserOnRequest ? userRepository : undefined,
    authorization: config.authorization,
  }), async (req: Request, res: Response): Promise<void> => {
    try {
      const user = (req as AuthenticatedRequest).user;
      
      if (!user) {
        res.status(401).json({ error: errorMessages.unauthorized });
        return;
      }

      // Kullanıcının tüm refresh token'larını revoke et
      await refreshTokenRepository.revokeAllUserTokens(user.sub);

      // Cookie'yi temizle
      if (config.cookie) {
        res.clearCookie('refreshToken', {
          httpOnly: config.cookie.httpOnly ?? true,
          secure: config.cookie.secure ?? process.env.NODE_ENV === 'production',
          sameSite: config.cookie.sameSite ?? 'strict',
          domain: config.cookie.domain,
          path: config.cookie.path ?? '/auth/refresh',
        });
      }

      res.json({ message: 'Logged out from all devices' });
    } catch (error) {
      console.error('Logout all error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * GET /auth/me
   * Mevcut kullanıcı bilgisi
   */
  router.get('/me', createAuthMiddleware(jwtService, {
    errorMessages: config.errorMessages,
    userRepository: loadUserOnRequest ? userRepository : undefined,
    authorization: config.authorization,
  }), async (req: Request, res: Response): Promise<void> => {
    try {
      const user = (req as AuthenticatedRequest).user;
      
      if (!user) {
        res.status(401).json({ error: errorMessages.unauthorized });
        return;
      }

      // Kullanıcı detaylarını getir
      const userDetails = await userRepository.findById(user.sub);
      
      if (!userDetails) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      // Password hash'i hariç tut
      const { passwordHash: _, ...userWithoutPassword } = userDetails;

      res.json({ user: userWithoutPassword });
    } catch (error) {
      console.error('Get user error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * GET /auth/security/stats (Admin only)
   * Security monitoring statistics
   */
  router.get('/security/stats', createAuthMiddleware(jwtService, {
    errorMessages: config.errorMessages,
    userRepository: loadUserOnRequest ? userRepository : undefined,
    authorization: config.authorization,
  }), async (req: Request, res: Response): Promise<void> => {
    try {
      const user = (req as AuthenticatedRequest).user;

      if (!user || !user.roles?.includes('admin')) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }

      const stats = securityMonitor.getStats();
      const blockedIPs = securityMonitor.getBlockedIPs();
      const cleanupStats = tokenCleanupJob?.getStats();

      res.json({
        security: {
          ...stats,
          blockedIPs,
        },
        tokenCleanup: cleanupStats,
      });
    } catch (error) {
      console.error('Security stats error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Attach security monitor and cleanup job to router for external access
  (router as any).securityMonitor = securityMonitor;
  (router as any).tokenCleanupJob = tokenCleanupJob;

  return router;
}

export default createAuthRouter;
