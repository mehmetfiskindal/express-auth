import { Repository } from 'typeorm';
import { AuthUser, UserRepository } from '@developersailor/express-auth';
import { User } from '../entities';

/**
 * MySQL User Repository using TypeORM
 */
export class MySQLUserRepository implements UserRepository {
  constructor(private userRepo: Repository<User>) {}

  async findByEmail(email: string): Promise<AuthUser | null> {
    const user = await this.userRepo.findOne({
      where: { email: email.toLowerCase() }
    });

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async findById(id: string): Promise<AuthUser | null> {
    const user = await this.userRepo.findOne({
      where: { id }
    });

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser> {
    const user = this.userRepo.create({
      email: data.email.toLowerCase(),
      passwordHash: data.passwordHash,
      roles: (data.roles || ['user']).join(','),
      isActive: true,
    });

    await this.userRepo.save(user);

    return this.toAuthUser(user);
  }

  async updatePassword(userId: string, newPasswordHash: string): Promise<void> {
    await this.userRepo.update(userId, {
      passwordHash: newPasswordHash,
    });
  }

  /**
   * Convert TypeORM User to AuthUser
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
