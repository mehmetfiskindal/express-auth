import { Op } from 'sequelize';
import { RefreshTokenRepository, RefreshTokenRecord } from '@developersailor/express-auth';
import { RefreshToken } from '../models';

/**
 * MSSQL Refresh Token Repository using Sequelize
 */
export class MSSQLRefreshTokenRepository implements RefreshTokenRepository {
  constructor(private tokenModel: typeof RefreshToken) {}

  async saveToken(record: RefreshTokenRecord): Promise<void> {
    await this.tokenModel.create({
      token: record.token,
      userId: record.userId,
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
      revokedAt: null,
    });
  }

  async findToken(token: string): Promise<RefreshTokenRecord | null> {
    const record = await this.tokenModel.findOne({
      where: { token }
    });

    if (!record) return null;

    return {
      token: record.token,
      userId: record.userId,
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
      revokedAt: record.revokedAt,
    };
  }

  async revokeToken(token: string): Promise<void> {
    await this.tokenModel.update(
      { revokedAt: new Date() },
      { where: { token } }
    );
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.tokenModel.update(
      { revokedAt: new Date() },
      { 
        where: { 
          userId,
          revokedAt: null
        } 
      }
    );
  }

  async cleanupExpiredTokens(): Promise<void> {
    await this.tokenModel.destroy({
      where: {
        expiresAt: { [Op.lt]: new Date() }
      }
    });
  }
}
