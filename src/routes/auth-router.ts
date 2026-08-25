import { createHash } from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import {
  JWTService, PasswordService, SecurityMonitor, TokenCleanupJob,
  RateLimitService, createAuthRateLimiter,
  CSRFService, createCSRFService,
  MFAService, createMFAService,
  PasswordResetService, createPasswordResetService,
} from '../services';
import {
  AuthConfig, LoginResult, RefreshResult, AuthenticatedRequest, AuthUser, TokenPair,
  MfaChallengeResult, MfaSetupResult, MfaEnableResult, PublicAuthUser,
} from '../types';
import { createAuthMiddleware } from '../middleware';

const SENSITIVE_USER_FIELDS = [
  'passwordHash',
  'mfaSecret',
  'mfaBackupCodeHashes',
  'passwordResetTokenHash',
  'passwordResetExpiresAt',
] as const;

/**
 * Strip secrets/hashes before putting a user object in an API response or host callback.
 */
function toPublicUser(user: AuthUser): PublicAuthUser {
  const publicUser = { ...user } as Record<string, unknown>;
  for (const field of SENSITIVE_USER_FIELDS) {
    delete publicUser[field];
  }
  return publicUser as PublicAuthUser;
}

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
  const getRoles = config.authorization?.getRoles || ((user: AuthUser) => user.roles || []);
  const getPermissions = config.authorization?.getPermissions || ((user: AuthUser) => user.permissions || []);
  const loadUserOnRequest = config.authorization?.loadUserOnRequest || false;
  const hashRefreshTokens = config.hashRefreshTokens !== false;
  const refreshTokenExpiresInSeconds = jwtService.getRefreshTokenExpiresInSeconds();
  const refreshTokenMaxAgeMs = refreshTokenExpiresInSeconds * 1000;

  const getRefreshTokenStorageValue = (token: string): string => {
    if (!hashRefreshTokens) return token;
    return createHash('sha256').update(token).digest('hex');
  };

  const getRefreshTokenExpiresAt = (): Date => {
    return new Date(Date.now() + refreshTokenMaxAgeMs);
  };

  // Error messages (güvenlik için genel mesajlar)
  const errorMessages = {
    invalidCredentials: config.errorMessages?.invalidCredentials || 'Invalid email or password',
    unauthorized: config.errorMessages?.unauthorized || 'Unauthorized',
    invalidToken: config.errorMessages?.invalidToken || 'Invalid token',
  };

  // Initialize security monitor
  const securityMonitor = new SecurityMonitor(config.securityMonitor);

  // Initialize rate limiter for auth endpoints (on by default)
  const authRateLimiter: RateLimitService | null = config.rateLimit?.enabled !== false
    ? createAuthRateLimiter(config.rateLimit?.auth)
    : null;
  const rateLimitMiddleware = authRateLimiter
    ? authRateLimiter.middleware.bind(authRateLimiter)
    : (_req: Request, _res: Response, next: NextFunction): void => next();

  // Per-user MFA challenge limiter (in addition to IP-based auth rate limit).
  // Prevents distributed brute-force against a stolen challengeToken.
  const mfaVerifyRateLimiter: RateLimitService | null = config.rateLimit?.enabled !== false
    ? createAuthRateLimiter(config.rateLimit?.auth)
    : null;

  // Initialize CSRF protection (double-submit cookie; on by default for cookie flows)
  const csrfService: CSRFService | null = config.cookie && config.csrf?.enabled !== false
    ? createCSRFService(config.csrf)
    : null;

  // CSRF is only enforced when the refresh token arrives via cookie (ambient
  // authority). Body-based clients don't carry the CSRF attack vector.
  const csrfGuard = (req: Request, res: Response, next: NextFunction): void => {
    if (!csrfService || !(req as Request & { cookies?: Record<string, string> }).cookies?.refreshToken) {
      next();
      return;
    }
    csrfService.middleware(req, res, next);
  };

  // Issue a fresh CSRF token cookie alongside the refresh token cookie.
  // Must NOT be httpOnly: the client reads it and echoes it in the CSRF header.
  const issueCsrfToken = (res: Response): string | undefined => {
    if (!csrfService || !config.cookie) return undefined;
    const token = csrfService.generateToken();
    res.cookie(csrfService.getCookieName(), token, {
      httpOnly: false,
      secure: config.cookie.secure ?? process.env.NODE_ENV === 'production',
      sameSite: config.cookie.sameSite ?? 'strict',
      domain: config.cookie.domain,
      path: '/',
      maxAge: refreshTokenMaxAgeMs,
    });
    return token;
  };

  const clearCsrfCookie = (res: Response): void => {
    if (!csrfService || !config.cookie) return;
    res.clearCookie(csrfService.getCookieName(), {
      httpOnly: false,
      secure: config.cookie.secure ?? process.env.NODE_ENV === 'production',
      sameSite: config.cookie.sameSite ?? 'strict',
      domain: config.cookie.domain,
      path: '/',
    });
  };

  // Initialize token cleanup job
  let tokenCleanupJob: TokenCleanupJob | null = null;
  if (config.tokenCleanup?.enabled !== false) {
    tokenCleanupJob = new TokenCleanupJob(refreshTokenRepository, config.tokenCleanup);
    tokenCleanupJob.start();
  }

  // Initialize MFA + password reset services (no background jobs, cheap to always create)
  const mfaService: MFAService = createMFAService(config.mfa);
  const passwordResetService: PasswordResetService = createPasswordResetService(config.passwordReset);

  // Parola sıfırlama ve MFA, repository'nin opsiyonel `updateUser` metoduna
  // dayanır. İmplemente edilmediyse bu özelliklerin route'ları hiç eklenmez.
  const supportsUserUpdate = typeof userRepository.updateUser === 'function';
  const supportsPasswordReset = supportsUserUpdate && typeof userRepository.findByPasswordResetToken === 'function';

  // Login/mfa-verify sonrası ortak token üretim + cookie/CSRF akışı
  const issueAuthTokens = async (user: AuthUser, res: Response): Promise<{ tokens: TokenPair; csrfToken?: string }> => {
    const tokens = jwtService.generateTokenPair({
      sub: user.id,
      email: user.email,
      roles: getRoles(user),
      permissions: getPermissions(user),
    });

    await refreshTokenRepository.saveToken({
      token: getRefreshTokenStorageValue(tokens.refreshToken),
      userId: user.id,
      expiresAt: getRefreshTokenExpiresAt(),
      createdAt: new Date(),
    });

    let csrfToken: string | undefined;
    if (config.cookie) {
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: config.cookie.httpOnly ?? true,
        secure: config.cookie.secure ?? process.env.NODE_ENV === 'production',
        sameSite: config.cookie.sameSite ?? 'strict',
        domain: config.cookie.domain,
        path: config.cookie.path ?? '/auth/refresh',
        maxAge: refreshTokenMaxAgeMs,
      });
      csrfToken = issueCsrfToken(res);
    }

    return { tokens, csrfToken };
  };

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
  router.post('/register', rateLimitMiddleware, async (req: Request, res: Response): Promise<void> => {
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
      const defaultRoles = config.registration?.defaultRoles || ['user'];
      const assignedRoles = config.registration?.allowRolesFromRequest
        ? roles || defaultRoles
        : defaultRoles;

      const user = await userRepository.createUser({
        email,
        passwordHash,
        roles: assignedRoles,
      });

      // Response'ta secret alanları dönmeyelim
      const userWithoutPassword = toPublicUser(user);

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
  router.post('/login', rateLimitMiddleware, async (req: Request, res: Response): Promise<void> => {
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

      // MFA aktifse tam token yerine kısa ömürlü bir challenge döndür
      if (user.mfaEnabled) {
        const challengeToken = jwtService.generateMfaChallengeToken({ sub: user.id });
        const challenge: MfaChallengeResult = { mfaRequired: true, challengeToken };
        res.json(challenge);
        return;
      }

      const { tokens, csrfToken } = await issueAuthTokens(user, res);

      // Response
      const userWithoutPassword = toPublicUser(user);

      const result: LoginResult = {
        user: userWithoutPassword,
        tokens,
        csrfToken,
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
  router.post('/refresh', rateLimitMiddleware, csrfGuard, async (req: Request, res: Response): Promise<void> => {
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
      const storedRefreshToken = getRefreshTokenStorageValue(refreshToken);
      const storedToken = refreshTokenRepository.consumeToken
        ? await refreshTokenRepository.consumeToken(storedRefreshToken)
        : await refreshTokenRepository.findToken(storedRefreshToken);

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
      if (!refreshTokenRepository.consumeToken) {
        await refreshTokenRepository.revokeToken(storedRefreshToken);
      }

      // Yeni token çifti üret (rotation) - roller/permission'lar güncel, cookie/CSRF dahil
      const { tokens, csrfToken } = await issueAuthTokens(user, res);

      const result: RefreshResult = {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: tokens.expiresIn,
        csrfToken,
      };

      res.json(result);
    } catch (error) {
      console.error('Refresh error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // MFA route'ları sadece repository `updateUser`'ı implemente ettiyse eklenir
  // (secret/backup code/enabled durumu kalıcı olarak saklanamıyorsa bu
  // özellik hiçbir zaman gerçekten çalışamaz).
  if (supportsUserUpdate) {
    const updateUser = userRepository.updateUser!.bind(userRepository);

    /**
     * POST /auth/mfa/setup
     * Yeni bir TOTP secret üret (henüz etkinleştirilmedi).
     * MFA zaten açıksa erişim reddedilir — aksi halde çalınmış access token ile MFA kapatılabilir.
     */
    router.post('/mfa/setup', createAuthMiddleware(jwtService, {
      errorMessages: config.errorMessages,
      userRepository: loadUserOnRequest ? userRepository : undefined,
      authorization: config.authorization,
    }), async (req: Request, res: Response): Promise<void> => {
      try {
        const authUser = (req as AuthenticatedRequest).user;
        if (!authUser) {
          res.status(401).json({ error: errorMessages.unauthorized });
          return;
        }

        const user = await userRepository.findById(authUser.sub);
        if (!user) {
          res.status(404).json({ error: 'User not found' });
          return;
        }

        if (user.mfaEnabled) {
          res.status(409).json({
            error: 'MFA is already enabled. Disable MFA before starting a new setup.',
          });
          return;
        }

        const secret = mfaService.generateSecret();
        await updateUser(user.id, { mfaSecret: secret, mfaEnabled: false });

        const result: MfaSetupResult = {
          secret,
          otpauthUrl: mfaService.getOtpAuthUrl(user.email, secret),
        };

        res.json(result);
      } catch (error) {
        console.error('MFA setup error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    /**
     * POST /auth/mfa/enable
     * /mfa/setup ile üretilen secret'ı bir TOTP koduyla doğrulayıp MFA'yı etkinleştir
     */
    router.post('/mfa/enable', createAuthMiddleware(jwtService, {
      errorMessages: config.errorMessages,
      userRepository: loadUserOnRequest ? userRepository : undefined,
      authorization: config.authorization,
    }), async (req: Request, res: Response): Promise<void> => {
      try {
        const authUser = (req as AuthenticatedRequest).user;
        if (!authUser) {
          res.status(401).json({ error: errorMessages.unauthorized });
          return;
        }

        const { code } = req.body;
        if (!code) {
          res.status(400).json({ error: 'code is required' });
          return;
        }

        const user = await userRepository.findById(authUser.sub);
        if (!user || !user.mfaSecret) {
          res.status(400).json({ error: 'MFA setup has not been started. Call /mfa/setup first.' });
          return;
        }

        if (user.mfaEnabled) {
          res.status(409).json({ error: 'MFA is already enabled' });
          return;
        }

        const isValid = await mfaService.verifyToken(code, user.mfaSecret);
        if (!isValid) {
          res.status(401).json({ error: 'Invalid MFA code' });
          return;
        }

        // Yedek kodlar SADECE burada, tek seferlik, düz metin olarak dönülür
        const backupCodes = mfaService.generateBackupCodes();
        const mfaBackupCodeHashes = backupCodes.map(c => mfaService.hashBackupCode(c));

        await updateUser(user.id, { mfaEnabled: true, mfaBackupCodeHashes });
        // MFA zorunlu hale geldi — mevcut oturumlar MFA'sız kalmasın
        await refreshTokenRepository.revokeAllUserTokens(user.id);

        const result: MfaEnableResult = { backupCodes };
        res.json(result);
      } catch (error) {
        console.error('MFA enable error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    /**
     * POST /auth/mfa/disable
     * MFA'yı kapat (yeniden kimlik doğrulama için parola gerekir)
     */
    router.post('/mfa/disable', createAuthMiddleware(jwtService, {
      errorMessages: config.errorMessages,
      userRepository: loadUserOnRequest ? userRepository : undefined,
      authorization: config.authorization,
    }), async (req: Request, res: Response): Promise<void> => {
      try {
        const authUser = (req as AuthenticatedRequest).user;
        if (!authUser) {
          res.status(401).json({ error: errorMessages.unauthorized });
          return;
        }

        const { password } = req.body;
        if (!password) {
          res.status(400).json({ error: 'password is required to disable MFA' });
          return;
        }

        const user = await userRepository.findById(authUser.sub);
        if (!user) {
          res.status(404).json({ error: 'User not found' });
          return;
        }

        const isPasswordValid = await passwordService.verifyPassword(password, user.passwordHash);
        if (!isPasswordValid) {
          res.status(401).json({ error: errorMessages.invalidCredentials });
          return;
        }

        await updateUser(user.id, {
          mfaEnabled: false,
          mfaSecret: undefined,
          mfaBackupCodeHashes: undefined,
        });
        await refreshTokenRepository.revokeAllUserTokens(user.id);

        res.json({ message: 'MFA disabled' });
      } catch (error) {
        console.error('MFA disable error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    /**
     * POST /auth/mfa/verify
     * MFA challenge'ı bir TOTP kodu veya yedek kodla tamamla, tam token çiftini al
     */
    router.post('/mfa/verify', rateLimitMiddleware, async (req: Request, res: Response): Promise<void> => {
      const ip = getClientIP(req);
      const userAgent = getUserAgent(req);

      try {
        const { challengeToken, code } = req.body;

        if (!challengeToken || !code) {
          res.status(400).json({ error: 'challengeToken and code are required' });
          return;
        }

        let payload: { sub: string };
        try {
          payload = jwtService.verifyMfaChallengeToken(challengeToken);
        } catch {
          res.status(401).json({ error: errorMessages.invalidToken });
          return;
        }

        // Per-user limit after challenge is validated (in addition to IP middleware)
        if (mfaVerifyRateLimiter) {
          const mfaLimit = mfaVerifyRateLimiter.checkLimit(`mfa:${payload.sub}`);
          if (!mfaLimit.allowed) {
            res.setHeader('Retry-After', String(mfaLimit.retryAfter ?? 60));
            res.status(429).json({
              error: 'Too many requests',
              message: 'Too many MFA attempts. Please try again later.',
              retryAfter: mfaLimit.retryAfter,
            });
            return;
          }
        }

        const user = await userRepository.findById(payload.sub);
        if (!user || user.isActive === false || !user.mfaEnabled || !user.mfaSecret) {
          res.status(401).json({ error: errorMessages.unauthorized });
          return;
        }

        const isValidTotp = await mfaService.verifyToken(code, user.mfaSecret);

        if (!isValidTotp) {
          const backupResult = mfaService.verifyBackupCode(code, user.mfaBackupCodeHashes || []);
          if (!backupResult.valid || !backupResult.matchedHash) {
            securityMonitor.recordFailedAttempt(ip, user.email, userAgent);
            res.status(401).json({ error: 'Invalid MFA code' });
            return;
          }

          // Atomik tüketim tercih edilir; yoksa read-modify-write fallback
          let consumed = false;
          if (typeof userRepository.consumeMfaBackupCode === 'function') {
            consumed = await userRepository.consumeMfaBackupCode(user.id, backupResult.matchedHash);
          } else {
            const remaining = (user.mfaBackupCodeHashes || []).filter(h => h !== backupResult.matchedHash);
            await updateUser(user.id, { mfaBackupCodeHashes: remaining });
            consumed = true;
          }

          if (!consumed) {
            securityMonitor.recordFailedAttempt(ip, user.email, userAgent);
            res.status(401).json({ error: 'Invalid MFA code' });
            return;
          }
        }

        mfaVerifyRateLimiter?.reset(`mfa:${payload.sub}`);
        securityMonitor.recordSuccessfulLogin(user.id, ip, userAgent);

        const { tokens, csrfToken } = await issueAuthTokens(user, res);
        const userWithoutPassword = toPublicUser(user);

        const result: LoginResult = {
          user: userWithoutPassword,
          tokens,
          csrfToken,
        };

        res.json(result);
      } catch (error) {
        console.error('MFA verify error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  }

  // Parola sıfırlama route'ları sadece repository `updateUser` VE
  // `findByPasswordResetToken`'ı implemente ettiyse eklenir.
  if (supportsPasswordReset) {
    const updateUser = userRepository.updateUser!.bind(userRepository);
    const findByPasswordResetToken = userRepository.findByPasswordResetToken!.bind(userRepository);

    /**
     * POST /auth/forgot-password
     * Reset token üret, host uygulamanın onRequest callback'i ile e-posta gönderimini tetikle
     */
    router.post('/forgot-password', rateLimitMiddleware, async (req: Request, res: Response): Promise<void> => {
      try {
        const { email } = req.body;
        if (!email) {
          res.status(400).json({ error: 'email is required' });
          return;
        }

        // Güvenlik: kullanıcı var/yok fark etmeksizin her zaman aynı generic yanıt (enumeration önleme)
        const genericMessage = { message: 'If an account with that email exists, a password reset link has been sent.' };

        const user = await userRepository.findByEmail(email);
        if (user && user.isActive !== false) {
          const token = passwordResetService.generateToken();
          const tokenHash = passwordResetService.hashToken(token);
          const expiresAt = passwordResetService.getExpiresAt();

          await updateUser(user.id, {
            passwordResetTokenHash: tokenHash,
            passwordResetExpiresAt: expiresAt,
          });

          if (config.passwordReset?.onRequest) {
            await config.passwordReset.onRequest(toPublicUser(user), token);
          }
        }

        res.json(genericMessage);
      } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    /**
     * POST /auth/reset-password
     * Reset token'ı doğrula, parolayı güncelle, tüm cihazlardan çıkış yaptır
     */
    router.post('/reset-password', rateLimitMiddleware, async (req: Request, res: Response): Promise<void> => {
      try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) {
          res.status(400).json({ error: 'token and newPassword are required' });
          return;
        }

        if (config.passwordRules) {
          const validation = passwordService.validatePasswordStrength(newPassword, config.passwordRules);
          if (!validation.valid) {
            res.status(400).json({ error: 'Password too weak', details: validation.errors });
            return;
          }
        }

        const tokenHash = passwordResetService.hashToken(token);
        const user = await findByPasswordResetToken(tokenHash);

        if (!user || !user.passwordResetExpiresAt || new Date() > user.passwordResetExpiresAt) {
          res.status(400).json({ error: 'Invalid or expired reset token' });
          return;
        }

        const newPasswordHash = await passwordService.hashPassword(newPassword);

        await updateUser(user.id, {
          passwordHash: newPasswordHash,
          passwordResetTokenHash: undefined,
          passwordResetExpiresAt: undefined,
        });

        // Güvenlik: parola değiştiğinde tüm cihazlardan çıkış yaptır
        await refreshTokenRepository.revokeAllUserTokens(user.id);

        res.json({ message: 'Password has been reset successfully' });
      } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  }

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
        await refreshTokenRepository.revokeToken(getRefreshTokenStorageValue(refreshToken));
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
        clearCsrfCookie(res);
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
        clearCsrfCookie(res);
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

      // Secret alanları hariç tut
      const userWithoutPassword = toPublicUser(userDetails);

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
  (router as any).rateLimiter = authRateLimiter;
  (router as any).mfaRateLimiter = mfaVerifyRateLimiter;

  return router;
}

export default createAuthRouter;
