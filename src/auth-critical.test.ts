declare const describe: (name: string, fn: () => void) => void;
declare const it: (name: string, fn: () => Promise<void> | void) => void;
declare const expect: any;

import express from 'express';
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
    };
    routerWithJobs.securityMonitor?.stopCleanupJob();
    routerWithJobs.tokenCleanupJob?.stop();
  }
}

async function postJson(baseUrl: string, path: string, body: unknown) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
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
});
