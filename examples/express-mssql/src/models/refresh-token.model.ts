import { Sequelize, DataTypes, Model, Optional } from 'sequelize';
import { User } from './user.model';

/**
 * Refresh Token Model Attributes
 */
interface RefreshTokenAttributes {
  id: string;
  token: string;
  userId: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date;
}

interface RefreshTokenCreationAttributes extends Optional<RefreshTokenAttributes, 'id' | 'createdAt' | 'revokedAt'> {}

/**
 * Refresh Token Model for Sequelize
 */
export class RefreshToken extends Model<RefreshTokenAttributes, RefreshTokenCreationAttributes> implements RefreshTokenAttributes {
  public id!: string;
  public token!: string;
  public userId!: string;
  public expiresAt!: Date;
  public readonly createdAt!: Date;
  public revokedAt?: Date;
}

/**
 * Initialize Refresh Token Model
 */
export function initRefreshTokenModel(sequelize: Sequelize): typeof RefreshToken {
  RefreshToken.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      token: {
        type: DataTypes.TEXT,
        allowNull: false,
        unique: true,
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false,
        field: 'user_id',
        references: {
          model: 'users',
          key: 'id',
        },
        onDelete: 'CASCADE',
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
        field: 'expires_at',
      },
      createdAt: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW,
        field: 'created_at',
      },
      revokedAt: {
        type: DataTypes.DATE,
        allowNull: true,
        field: 'revoked_at',
      },
    },
    {
      sequelize,
      tableName: 'refresh_tokens',
      timestamps: true,
      underscored: true,
      updatedAt: false,
      indexes: [
        { unique: true, fields: ['token'] },
        { fields: ['user_id'] },
        { fields: ['expires_at'] },
      ],
    }
  );

  // Define associations
  RefreshToken.belongsTo(User, { foreignKey: 'userId', as: 'user' });

  return RefreshToken;
}
