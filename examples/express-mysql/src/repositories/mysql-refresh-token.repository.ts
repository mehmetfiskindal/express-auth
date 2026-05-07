import { Repository, LessThan } from 'typeorm';
import { RefreshTokenRepository, RefreshTokenRecord } from '@developersailor/express-auth';
import { RefreshToken } from '../entities';

/**
 * MySQL Refresh Token Repository using TypeORM
 */
export class MySQLRefreshTokenRepository implements RefreshTokenRepository {
  constructor(private tokenRepo: Repository<RefreshToken>) {}

  async saveToken(record: RefreshTokenRecord): Promise<void> {
    const token = this.tokenRepo.create({
      token: record.token,
      userId: record.userId,
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
      revokedAt: null,
    });

    await this.tokenRepo.save(token);
  }

  async findToken(token: string): Promise<RefreshTokenRecord | null> {
    const record = await this.tokenRepo.findOne({
      where: { token }
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
    await this.tokenRepo.update(
      { token },
      { revokedAt: new Date() }
    );
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.tokenRepo.update(
      { userId, revokedAt: null },
      { revokedAt: new Date() }
    );
  }

  async cleanupExpiredTokens(): Promise<void> {
    await this.tokenRepo.delete({
      expiresAt: LessThan(new Date())
    });
  }
}
