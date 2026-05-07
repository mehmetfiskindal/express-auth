import { AuthUser, UserRepository } from '@developersailor/express-auth';
import { UserModel, IUser } from '../models';

/**
 * MongoDB User Repository
 * Implements UserRepository interface using Mongoose
 */
export class MongoUserRepository implements UserRepository {
  async findByEmail(email: string): Promise<AuthUser | null> {
    const user = await UserModel.findOne({ 
      email: email.toLowerCase() 
    }).lean();

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async findById(id: string): Promise<AuthUser | null> {
    const user = await UserModel.findById(id).lean();

    if (!user) return null;

    return this.toAuthUser(user);
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    roles?: string[];
  }): Promise<AuthUser> {
    const user = await UserModel.create({
      email: data.email.toLowerCase(),
      passwordHash: data.passwordHash,
      roles: data.roles || ['user'],
      isActive: true,
    });

    return this.toAuthUser(user.toObject());
  }

  async updatePassword(userId: string, newPasswordHash: string): Promise<void> {
    await UserModel.findByIdAndUpdate(userId, {
      passwordHash: newPasswordHash,
    });
  }

  async updateUser(userId: string, data: Partial<AuthUser>): Promise<AuthUser | null> {
    const user = await UserModel.findByIdAndUpdate(
      userId,
      { $set: data },
      { new: true }
    ).lean();

    if (!user) return null;

    return this.toAuthUser(user);
  }

  /**
   * Convert MongoDB user to AuthUser
   */
  private toAuthUser(user: IUser | Record<string, any>): AuthUser {
    return {
      id: user._id.toString(),
      email: user.email,
      passwordHash: user.passwordHash,
      roles: user.roles || ['user'],
      isActive: user.isActive ?? true,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
