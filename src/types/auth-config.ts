import { Request } from 'express';
import { AuthRepositories, AuthUser } from './repository';
import { RateLimitConfig } from '../services/rate-limit-service';
import { SecurityMonitorConfig } from '../services/security-monitor';
import { CORSConfig } from '../services/cors-service';
import { HTTPSConfig } from '../services/https-service';
import { CleanupConfig } from '../services/token-cleanup-job';

/**
 * Permission format - hem flat hem hierarchical destekler
 * Flat: ["user.read", "user.write"]
 * Hierarchical: { user: { read: true, write: true }, order: { read: true } }
 */
export type Permission = string | Record<string, boolean | Record<string, boolean>>;

/**
 * Permission array type
 */
export type PermissionsArray = Permission[];

/**
 * Authorization yapılandırması
 */
export interface AuthorizationConfig {
  /**
   * Kullanıcının rollerini nasıl okuyacağız
   * Varsayılan: (user) => user.roles || []
   */
  getRoles?: (user: AuthUser) => string[];
  
  /**
   * Kullanıcının permission'larını nasıl okuyacağız
   * Varsayılan: (user) => user.permissions || []
   */
  getPermissions?: (user: AuthUser) => Permission[];
  
  /**
   * Her request'te kullanıcıyı DB'den çekip güncel rol/permission kontrolü yap
   * Güvenli ama yavaş (her request'te DB sorgusu)
   * Varsayılan: false (JWT payload'dan okur - hızlı ama güncel olmayabilir)
   */
  loadUserOnRequest?: boolean;
  
  /**
   * Kullanıcı cache süresi (saniye) - sadece loadUserOnRequest=true ise geçerli
   * Varsayılan: 60 (1 dakika)
   */
  userCacheTTL?: number;
  
  /**
   * Ownership kontrolünde bypass edilecek roller
   * Örnek: ['admin', 'superuser'] - bu roller her kaynağa erişebilir
   * Varsayılan: ['admin']
   */
  ownershipBypassRoles?: string[];
  
  /**
   * Hierarchical permission format kullanılıyor mu?
   * true: { user: { read: true } } formatı
   * false: ["user.read"] formatı
   * Varsayılan: false (flat format)
   */
  hierarchicalPermissions?: boolean;
}

/**
 * Auth yapılandırma seçenekleri
 * TÜM secret'lar ve hassas bilgiler buradan gelir
 */
export interface AuthConfig {
  /**
   * JWT Secret - Çok güçlü bir secret olmalı
   * Örnek: process.env.JWT_SECRET
   */
  jwtSecret: string;

  /**
   * Refresh Token Secret - JWT'den farklı olmalı
   * Örnek: process.env.REFRESH_TOKEN_SECRET
   */
  refreshTokenSecret: string;

  /**
   * Access token süresi (ms veya string)
   * Varsayılan: 15m
   */
  accessTokenExpiresIn?: number | string;

  /**
   * Refresh token süresi (ms veya string)
   * Varsayılan: 7d
   */
  refreshTokenExpiresIn?: number | string;

  /**
   * Repository'ler - Kullanıcı tarafından sağlanır
   */
  repositories: AuthRepositories;

  /**
   * Authorization yapılandırması
   */
  authorization?: AuthorizationConfig;

  /**
   * Cookie ayarları (opsiyonel)
   */
  cookie?: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    path?: string;
  };

  /**
   * Password validasyon kuralları
   */
  passwordRules?: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecialChars?: boolean;
  };

  /**
   * Hata mesajları - güvenlik için genel mesajlar önerilir
   */
  errorMessages?: {
    invalidCredentials?: string;
    unauthorized?: string;
    forbidden?: string;
    tokenExpired?: string;
    invalidToken?: string;
  };

  /**
   * Rate limiting yapılandırması
   */
  rateLimit?: {
    /** Enable rate limiting (default: true) */
    enabled?: boolean;
    /** General API rate limit config */
    general?: Partial<RateLimitConfig>;
    /** Auth endpoints (login/register) rate limit config - stricter */
    auth?: Partial<RateLimitConfig>;
    /** Strict rate limit for sensitive operations */
    strict?: Partial<RateLimitConfig>;
  };

  /**
   * CORS yapılandırması
   */
  cors?: Partial<CORSConfig>;

  /**
   * HTTPS enforcement yapılandırması
   */
  https?: Partial<HTTPSConfig>;

  /**
   * Security monitoring yapılandırması
   */
  securityMonitor?: Partial<SecurityMonitorConfig>;

  /**
   * Token cleanup job yapılandırması
   */
  tokenCleanup?: Partial<CleanupConfig>;
}

/**
 * JWT Payload
 */
export interface JWTPayload {
  sub: string; // user id
  email: string;
  roles: string[];
  permissions?: Permission[]; // Opsiyonel: kullanıcı permission'ları
  iat: number;
  exp: number;
  type: 'access' | 'refresh';
}

/**
 * Token çifti
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number; // saniye cinsinden
}

/**
 * Login sonucu
 */
export interface LoginResult {
  user: Omit<AuthUser, 'passwordHash'>;
  tokens: TokenPair;
}

/**
 * Express request'e auth bilgisi ekleme
 */
export interface AuthenticatedRequest extends Request {
  user?: JWTPayload;
}

/**
 * Token refresh sonucu
 */
export interface RefreshResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}
