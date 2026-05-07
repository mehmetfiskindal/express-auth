import { PrismaClient } from '@prisma/client';
import { AuthUser, UserRepository } from '@developersailor/express-auth';

/**
 * Prisma User Repository
 * UserRepository interface'ini Prisma ile implemente eder
 */
export class PrismaUserRepository implements UserRepository {
  constructor(private prisma: PrismaClient) {}

  async findByEmail(email: string): Promise<AuthUser | null> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async findById(id: string): Promise<AuthUser | null> {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser> {
    const user = await this.prisma.user.create({
      data: {
        email: data.email.toLowerCase(),
        passwordHash: data.passwordHash,
        roles: data.roles?.join(',') || 'user',
      },
    });

    return this.toAuthUser(user);
  }

  async updatePassword(userId: string, newPasswordHash: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash: newPasswordHash },
    });
  }

  /**
   * Prisma User -> AuthUser dönüşümü
   */
  private toAuthUser(user: {
    id: string;
    email: string;
    passwordHash: string;
    roles: string;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
  }): AuthUser {
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
