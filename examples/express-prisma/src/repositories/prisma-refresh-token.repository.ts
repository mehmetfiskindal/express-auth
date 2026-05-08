import { PrismaClient } from '@prisma/client';
import { RefreshTokenRepository, RefreshTokenRecord } from '@developersailor/express-auth';

/**
 * Prisma Refresh Token Repository
 * RefreshTokenRepository interface'ini Prisma ile implemente eder
 */
export class PrismaRefreshTokenRepository implements RefreshTokenRepository {
  constructor(private prisma: PrismaClient) {}

  async saveToken(record: RefreshTokenRecord): Promise<void> {
    await this.prisma.refreshToken.create({
      data: {
        token: record.token,
        userId: record.userId,
        expiresAt: record.expiresAt,
        createdAt: record.createdAt,
      },
    });
  }

  async findToken(token: string): Promise<RefreshTokenRecord | null> {
    const record = await this.prisma.refreshToken.findUnique({
      where: { token },
    });

    if (!record) return null;

    return {
      token: record.token,
      userId: record.userId,
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
      revokedAt: record.revokedAt || undefined,
    };
  }

  async revokeToken(token: string): Promise<void> {
    await this.prisma.refreshToken.update({
      where: { token },
      data: { revokedAt: new Date() },
    });
  }

  async consumeToken(token: string): Promise<RefreshTokenRecord | null> {
    const result = await this.prisma.refreshToken.updateMany({
      where: {
        token,
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    });

    if (result.count === 0) return null;

    const record = await this.prisma.refreshToken.findUnique({
      where: { token },
    });

    if (!record) return null;

    return {
      token: record.token,
      userId: record.userId,
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
    };
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    });
  }

  async cleanupExpiredTokens(): Promise<void> {
    await this.prisma.refreshToken.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });
  }
}
