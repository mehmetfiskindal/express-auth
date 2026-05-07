import { RefreshTokenRepository, RefreshTokenRecord } from '@developersailor/express-auth';
import { RefreshTokenModel } from '../models';

/**
 * MongoDB Refresh Token Repository
 * Implements RefreshTokenRepository interface using Mongoose
 */
export class MongoRefreshTokenRepository implements RefreshTokenRepository {
  async saveToken(record: RefreshTokenRecord): Promise<void> {
    await RefreshTokenModel.create({
      token: record.token,
      userId: record.userId,
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
    });
  }

  async findToken(token: string): Promise<RefreshTokenRecord | null> {
    const record = await RefreshTokenModel.findOne({ 
      token 
    }).lean();

    if (!record) return null;

    return {
      token: record.token,
      userId: record.userId.toString(),
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
      revokedAt: record.revokedAt || undefined,
    };
  }

  async revokeToken(token: string): Promise<void> {
    await RefreshTokenModel.updateOne(
      { token },
      { $set: { revokedAt: new Date() } }
    );
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await RefreshTokenModel.updateMany(
      { 
        userId,
        revokedAt: null 
      },
      { $set: { revokedAt: new Date() } }
    );
  }

  async cleanupExpiredTokens(): Promise<void> {
    // TTL index handles this automatically
    // But we can force cleanup if needed
    await RefreshTokenModel.deleteMany({
      expiresAt: { $lt: new Date() }
    });
  }

  /**
   * Get active tokens count for a user (useful for monitoring)
   */
  async getActiveTokensCount(userId: string): Promise<number> {
    return RefreshTokenModel.countDocuments({
      userId,
      revokedAt: null,
      expiresAt: { $gt: new Date() }
    });
  }
}
