import { AuthUser, UserRepository } from '@developersailor/express-auth';
import { User } from '../models';

/**
 * MSSQL User Repository using Sequelize
 */
export class MSSQLUserRepository implements UserRepository {
  constructor(private userModel: typeof User) {}

  async findByEmail(email: string): Promise<AuthUser | null> {
    const user = await this.userModel.findOne({
      where: { email: email.toLowerCase() }
    });

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async findById(id: string): Promise<AuthUser | null> {
    const user = await this.userModel.findByPk(id);

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser> {
    const user = await this.userModel.create({
      email: data.email.toLowerCase(),
      passwordHash: data.passwordHash,
      roles: (data.roles || ['user']).join(','),
      isActive: true,
    });

    return this.toAuthUser(user);
  }

  async updatePassword(userId: string, newPasswordHash: string): Promise<void> {
    await this.userModel.update(
      { passwordHash: newPasswordHash },
      { where: { id: userId } }
    );
  }

  /**
   * Convert Sequelize User to AuthUser
   */
  private toAuthUser(user: User): AuthUser {
    return {
      id: user.id,
      email: user.email,
      passwordHash: user.passwordHash,
      roles: user.roles.split(',').map(r => r.trim()),
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
