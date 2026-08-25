declare const describe: (name: string, fn: () => void) => void;
declare const it: (name: string, fn: () => Promise<void> | void) => void;
declare const expect: any;

import express from 'express';
import cookieParser from 'cookie-parser';
import { authenticator } from 'otplib';
import { AddressInfo } from 'net';
import { createAuthRouter } from './routes';
import { createAuthMiddleware } from './middleware';
import { JWTService } from './services';
import { AuthConfig } from './types';
import { createMemoryRepositories, MemoryUserRepository } from './adapters';

const jwtSecret = 'f9a8c7e6b5d4a3f2e1c0b9a8d7e6f5c4b3a2d1e0f9c8b7a6d5e4f3a2b1c0d9e8';
const refreshTokenSecret = 'a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9';

async function withServer(
  config: AuthConfig,
  callback: (baseUrl: string) => Promise<void>
): Promise<void> {
  const app = express();
  const authRouter = createAuthRouter(config);
  app.use(express.json());
  app.use(cookieParser());
  app.use('/auth', authRouter);

  const server = app.listen(0);
  await new Promise<void>(resolve => server.once('listening', resolve));

  try {
    const { port } = server.address() as AddressInfo;
    await callback(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
    const routerWithJobs = authRouter as typeof authRouter & {
      securityMonitor?: { stopCleanupJob(): void };
      tokenCleanupJob?: { stop(): void } | null;
      rateLimiter?: { stopCleanupJob(): void } | null;
      mfaRateLimiter?: { stopCleanupJob(): void } | null;
    };
    routerWithJobs.securityMonitor?.stopCleanupJob();
    routerWithJobs.tokenCleanupJob?.stop();
    routerWithJobs.rateLimiter?.stopCleanupJob();
    routerWithJobs.mfaRateLimiter?.stopCleanupJob();
  }
}

async function postJson(
  baseUrl: string,
  path: string,
  body: unknown,
  headers: Record<string, string> = {}
) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });

  return {
    status: response.status,
    body: await response.json() as Record<string, any>,
  };
}

async function getJson(
  baseUrl: string,
  path: string,
  headers: Record<string, string> = {}
) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'GET',
    headers,
  });

  return {
    status: response.status,
    body: await response.json() as Record<string, any>,
  };
}

describe('critical auth behavior', () => {
  it('does not allow public registration to assign privileged roles', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      const response = await postJson(baseUrl, '/auth/register', {
        email: 'role-test@example.com',
        password: 'Password123!',
        roles: ['admin'],
      });

      expect(response.status).toBe(201);

      const user = await repositories.userRepository.findByEmail('role-test@example.com');
      expect(user?.roles).toEqual(['user']);
    });
  });

  it('stores hashed refresh tokens and uses configured refresh expiry', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      refreshTokenExpiresIn: '2h',
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'expiry-test@example.com',
        password: 'Password123!',
      });

      const response = await postJson(baseUrl, '/auth/login', {
        email: 'expiry-test@example.com',
        password: 'Password123!',
      });

      expect(response.status).toBe(200);

      const rawRefreshToken = response.body.tokens.refreshToken;
      const [storedToken] = repositories.refreshTokenRepository.getAll();
      const expiresInSeconds = Math.round((storedToken.expiresAt.getTime() - Date.now()) / 1000);

      expect(storedToken.token).not.toBe(rawRefreshToken);
      expect(storedToken.token).toHaveLength(64);
      expect(expiresInSeconds).toBeGreaterThan(7100);
      expect(expiresInSeconds).toBeLessThanOrEqual(7200);
    });
  });

  it('consumes refresh tokens once during rotation', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'rotation-test@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'rotation-test@example.com',
        password: 'Password123!',
      });

      const refreshToken = login.body.tokens.refreshToken;
      const firstRefresh = await postJson(baseUrl, '/auth/refresh', { refreshToken });
      const secondRefresh = await postJson(baseUrl, '/auth/refresh', { refreshToken });

      expect(firstRefresh.status).toBe(200);
      expect(secondRefresh.status).toBe(401);
    });
  });

  it('rejects inactive users when loadUserOnRequest is enabled', async () => {
    const repositories = createMemoryRepositories();
    const userRepository = repositories.userRepository as MemoryUserRepository;
    const user = await userRepository.createUser({
      email: 'inactive@example.com',
      passwordHash: 'hash',
      roles: ['user'],
    });

    const jwtService = new JWTService({ jwtSecret, refreshTokenSecret });
    const tokens = jwtService.generateTokenPair({
      sub: user.id,
      email: user.email,
      roles: ['user'],
    });

    user.isActive = false;

    const middleware = createAuthMiddleware(jwtService, {
      userRepository,
      authorization: { loadUserOnRequest: true },
    });

    const req = {
      headers: { authorization: `Bearer ${tokens.accessToken}` },
    } as express.Request;
    const res = {
      statusCode: 200,
      body: undefined as unknown,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json(body: unknown) {
        this.body = body;
        return this;
      },
    } as express.Response & { statusCode: number; body: unknown };
    let nextCalled = false;

    await middleware(req, res, () => {
      nextCalled = true;
    });

    expect(res.statusCode).toBe(401);
    expect(nextCalled).toBe(false);
  });

  it('rate limits /login by default once the configured request count is exceeded', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { auth: { maxRequests: 2, windowMs: 60_000 } },
    }, async baseUrl => {
      const credentials = { email: 'rate-limit-test@example.com', password: 'wrong-password' };

      const first = await postJson(baseUrl, '/auth/login', credentials);
      const second = await postJson(baseUrl, '/auth/login', credentials);
      const third = await postJson(baseUrl, '/auth/login', credentials);

      expect(first.status).toBe(401);
      expect(second.status).toBe(401);
      expect(third.status).toBe(429);
    });
  });

  it('rejects cookie-based refresh without a CSRF token by default', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      cookie: {},
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'csrf-missing@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'csrf-missing@example.com',
        password: 'Password123!',
      });

      expect(login.status).toBe(200);
      expect(typeof login.body.csrfToken).toBe('string');

      const refreshToken = login.body.tokens.refreshToken;
      const response = await postJson(baseUrl, '/auth/refresh', {}, {
        cookie: `refreshToken=${refreshToken}`,
      });

      expect(response.status).toBe(403);
      expect(response.body.error).toBe('Invalid CSRF token');
    });
  });

  it('accepts cookie-based refresh with a matching CSRF token and rotates it', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      cookie: {},
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'csrf-valid@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'csrf-valid@example.com',
        password: 'Password123!',
      });

      const refreshToken = login.body.tokens.refreshToken;
      const csrfToken = login.body.csrfToken;

      const response = await postJson(baseUrl, '/auth/refresh', {}, {
        cookie: `refreshToken=${refreshToken}; csrfToken=${csrfToken}`,
        'x-csrf-token': csrfToken,
      });

      expect(response.status).toBe(200);
      expect(typeof response.body.csrfToken).toBe('string');
      expect(response.body.csrfToken).not.toBe(csrfToken);

      const mismatched = await postJson(baseUrl, '/auth/refresh', {}, {
        cookie: `refreshToken=${response.body.refreshToken}; csrfToken=${response.body.csrfToken}`,
        'x-csrf-token': 'a'.repeat(64),
      });

      expect(mismatched.status).toBe(403);
    });
  });

  it('allows disabling CSRF protection via csrf.enabled', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      cookie: {},
      csrf: { enabled: false },
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'csrf-disabled@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'csrf-disabled@example.com',
        password: 'Password123!',
      });

      expect(login.body.csrfToken).toBeUndefined();

      const response = await postJson(baseUrl, '/auth/refresh', {}, {
        cookie: `refreshToken=${login.body.tokens.refreshToken}`,
      });

      expect(response.status).toBe(200);
    });
  });

  it('supports the full MFA setup -> enable -> challenge -> verify flow, including backup codes', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'mfa-user@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-user@example.com',
        password: 'Password123!',
      });
      expect(login.body.mfaRequired).toBeUndefined();
      const accessToken = login.body.tokens.accessToken;

      // 1) Setup: get a secret
      const setup = await postJson(baseUrl, '/auth/mfa/setup', {}, {
        Authorization: `Bearer ${accessToken}`,
      });
      expect(setup.status).toBe(200);
      expect(typeof setup.body.secret).toBe('string');
      expect(setup.body.otpauthUrl).toContain('otpauth://totp/');

      // 2) Enable: confirm with a valid TOTP code
      const validCode = authenticator.generate(setup.body.secret);
      const enable = await postJson(baseUrl, '/auth/mfa/enable', { code: validCode }, {
        Authorization: `Bearer ${accessToken}`,
      });
      expect(enable.status).toBe(200);
      expect(Array.isArray(enable.body.backupCodes)).toBe(true);
      expect(enable.body.backupCodes.length).toBe(10);

      // 3) Next login should now return a challenge, not tokens
      const loginAgain = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-user@example.com',
        password: 'Password123!',
      });
      expect(loginAgain.body.mfaRequired).toBe(true);
      expect(typeof loginAgain.body.challengeToken).toBe('string');
      expect(loginAgain.body.tokens).toBeUndefined();

      // 4) Verify with a fresh TOTP code completes login
      const freshCode = authenticator.generate(setup.body.secret);
      const verify = await postJson(baseUrl, '/auth/mfa/verify', {
        challengeToken: loginAgain.body.challengeToken,
        code: freshCode,
      });
      expect(verify.status).toBe(200);
      expect(typeof verify.body.tokens.accessToken).toBe('string');

      // 5) Backup code works once, then is rejected on reuse
      const loginForBackup = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-user@example.com',
        password: 'Password123!',
      });
      const backupCode = enable.body.backupCodes[0];

      const verifyWithBackup = await postJson(baseUrl, '/auth/mfa/verify', {
        challengeToken: loginForBackup.body.challengeToken,
        code: backupCode,
      });
      expect(verifyWithBackup.status).toBe(200);

      const loginAgainForReuse = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-user@example.com',
        password: 'Password123!',
      });
      const reuseBackup = await postJson(baseUrl, '/auth/mfa/verify', {
        challengeToken: loginAgainForReuse.body.challengeToken,
        code: backupCode,
      });
      expect(reuseBackup.status).toBe(401);
    });
  });

  it('rejects /mfa/setup when MFA is already enabled (no access-token MFA bypass)', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'mfa-bypass@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-bypass@example.com',
        password: 'Password123!',
      });
      const accessToken = login.body.tokens.accessToken;

      const setup = await postJson(baseUrl, '/auth/mfa/setup', {}, {
        Authorization: `Bearer ${accessToken}`,
      });
      const code = authenticator.generate(setup.body.secret);
      await postJson(baseUrl, '/auth/mfa/enable', { code }, {
        Authorization: `Bearer ${accessToken}`,
      });

      const reSetup = await postJson(baseUrl, '/auth/mfa/setup', {}, {
        Authorization: `Bearer ${accessToken}`,
      });
      expect(reSetup.status).toBe(409);

      const user = await repositories.userRepository.findByEmail('mfa-bypass@example.com');
      expect(user?.mfaEnabled).toBe(true);
    });
  });

  it('does not leak mfaSecret or other sensitive fields from /auth/me or login responses', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'mfa-leak@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-leak@example.com',
        password: 'Password123!',
      });
      const accessToken = login.body.tokens.accessToken;

      expect(login.body.user.passwordHash).toBeUndefined();
      expect(login.body.user.mfaSecret).toBeUndefined();
      expect(login.body.user.mfaBackupCodeHashes).toBeUndefined();

      const setup = await postJson(baseUrl, '/auth/mfa/setup', {}, {
        Authorization: `Bearer ${accessToken}`,
      });
      const code = authenticator.generate(setup.body.secret);
      await postJson(baseUrl, '/auth/mfa/enable', { code }, {
        Authorization: `Bearer ${accessToken}`,
      });

      // Re-login + MFA verify to get a post-MFA session
      const loginAgain = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-leak@example.com',
        password: 'Password123!',
      });
      const freshCode = authenticator.generate(setup.body.secret);
      const verify = await postJson(baseUrl, '/auth/mfa/verify', {
        challengeToken: loginAgain.body.challengeToken,
        code: freshCode,
      });

      expect(verify.body.user.mfaSecret).toBeUndefined();
      expect(verify.body.user.mfaBackupCodeHashes).toBeUndefined();
      expect(verify.body.user.passwordHash).toBeUndefined();
      expect(verify.body.user.mfaEnabled).toBe(true);

      const me = await getJson(baseUrl, '/auth/me', {
        Authorization: `Bearer ${verify.body.tokens.accessToken}`,
      });
      expect(me.status).toBe(200);
      expect(me.body.user.mfaSecret).toBeUndefined();
      expect(me.body.user.mfaBackupCodeHashes).toBeUndefined();
      expect(me.body.user.passwordHash).toBeUndefined();
      expect(me.body.user.passwordResetTokenHash).toBeUndefined();
      expect(me.body.user.mfaEnabled).toBe(true);

      // Secret must still exist server-side
      const stored = await repositories.userRepository.findByEmail('mfa-leak@example.com');
      expect(typeof stored?.mfaSecret).toBe('string');
    });
  });

  it('revokes refresh tokens when MFA is enabled or disabled', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'mfa-revoke@example.com',
        password: 'Password123!',
      });

      const login = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-revoke@example.com',
        password: 'Password123!',
      });
      const accessToken = login.body.tokens.accessToken;
      const refreshBeforeEnable = login.body.tokens.refreshToken;

      const setup = await postJson(baseUrl, '/auth/mfa/setup', {}, {
        Authorization: `Bearer ${accessToken}`,
      });
      const code = authenticator.generate(setup.body.secret);
      await postJson(baseUrl, '/auth/mfa/enable', { code }, {
        Authorization: `Bearer ${accessToken}`,
      });

      const refreshAfterEnable = await postJson(baseUrl, '/auth/refresh', {
        refreshToken: refreshBeforeEnable,
      });
      expect(refreshAfterEnable.status).toBe(401);

      // Complete MFA login to get tokens, then disable
      const loginAgain = await postJson(baseUrl, '/auth/login', {
        email: 'mfa-revoke@example.com',
        password: 'Password123!',
      });
      const freshCode = authenticator.generate(setup.body.secret);
      const verify = await postJson(baseUrl, '/auth/mfa/verify', {
        challengeToken: loginAgain.body.challengeToken,
        code: freshCode,
      });
      const refreshBeforeDisable = verify.body.tokens.refreshToken;
      const accessAfterMfa = verify.body.tokens.accessToken;

      const disable = await postJson(baseUrl, '/auth/mfa/disable', {
        password: 'Password123!',
      }, {
        Authorization: `Bearer ${accessAfterMfa}`,
      });
      expect(disable.status).toBe(200);

      const refreshAfterDisable = await postJson(baseUrl, '/auth/refresh', {
        refreshToken: refreshBeforeDisable,
      });
      expect(refreshAfterDisable.status).toBe(401);
    });
  });

  it('consumes MFA backup codes atomically in MemoryUserRepository', async () => {
    const repo = new MemoryUserRepository();
    const user = await repo.createUser({
      email: 'backup-atomic@example.com',
      passwordHash: 'hash',
    });
    const hash = 'abc123hash';
    await repo.updateUser!(user.id, {
      mfaEnabled: true,
      mfaBackupCodeHashes: [hash, 'other'],
    });

    const first = await repo.consumeMfaBackupCode!(user.id, hash);
    const second = await repo.consumeMfaBackupCode!(user.id, hash);

    expect(first).toBe(true);
    expect(second).toBe(false);

    const updated = await repo.findById(user.id);
    expect(updated?.mfaBackupCodeHashes).toEqual(['other']);
  });

  it('supports the forgot-password -> reset-password flow and revokes existing sessions', async () => {
    const repositories = createMemoryRepositories();
    let capturedToken: string | undefined;

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
      passwordReset: {
        onRequest: (_user, token) => {
          capturedToken = token;
        },
      },
    }, async baseUrl => {
      await postJson(baseUrl, '/auth/register', {
        email: 'reset-user@example.com',
        password: 'OldPassword123!',
      });

      const oldLogin = await postJson(baseUrl, '/auth/login', {
        email: 'reset-user@example.com',
        password: 'OldPassword123!',
      });
      const oldRefreshToken = oldLogin.body.tokens.refreshToken;

      const forgot = await postJson(baseUrl, '/auth/forgot-password', {
        email: 'reset-user@example.com',
      });
      expect(forgot.status).toBe(200);
      expect(capturedToken).toBeDefined();

      const reset = await postJson(baseUrl, '/auth/reset-password', {
        token: capturedToken,
        newPassword: 'NewPassword456!',
      });
      expect(reset.status).toBe(200);

      // Old password no longer works
      const oldPasswordLogin = await postJson(baseUrl, '/auth/login', {
        email: 'reset-user@example.com',
        password: 'OldPassword123!',
      });
      expect(oldPasswordLogin.status).toBe(401);

      // New password works
      const newPasswordLogin = await postJson(baseUrl, '/auth/login', {
        email: 'reset-user@example.com',
        password: 'NewPassword456!',
      });
      expect(newPasswordLogin.status).toBe(200);

      // Old refresh token was revoked by the reset
      const oldRefresh = await postJson(baseUrl, '/auth/refresh', { refreshToken: oldRefreshToken });
      expect(oldRefresh.status).toBe(401);
    });
  });

  it('rejects an unknown forgot-password email with the same generic response (no enumeration)', async () => {
    const repositories = createMemoryRepositories();

    await withServer({
      jwtSecret,
      refreshTokenSecret,
      repositories,
      tokenCleanup: { enabled: false },
      rateLimit: { enabled: false },
      passwordReset: {},
    }, async baseUrl => {
      const response = await postJson(baseUrl, '/auth/forgot-password', {
        email: 'nobody@example.com',
      });

      expect(response.status).toBe(200);
      expect(response.body.message).toMatch(/if an account/i);
    });
  });
});
