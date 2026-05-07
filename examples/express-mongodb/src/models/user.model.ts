import mongoose, { Schema, Document } from 'mongoose';

/**
 * User Document Interface
 */
export interface IUser extends Document {
  email: string;
  passwordHash: string;
  roles: string[];
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * User Schema
 */
const UserSchema: Schema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    roles: {
      type: [String],
      default: ['user'],
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
    collection: 'users',
  }
);

// Index for faster queries
UserSchema.index({ email: 1 });

export const UserModel = mongoose.model<IUser>('User', UserSchema);
