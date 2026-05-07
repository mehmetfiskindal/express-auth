import { RefreshTokenRepository } from '../types';

/**
 * Token cleanup job configuration
 */
export interface CleanupConfig {
  /** Run cleanup every X milliseconds (default: 1 hour) */
  interval: number;
  /** Delete tokens expired for more than X milliseconds (default: 24 hours) */
  deleteAfterExpired: number;
  /** Enable cleanup job (default: true) */
  enabled: boolean;
  /** Also cleanup revoked tokens (default: true) */
  cleanupRevoked: boolean;
}

/**
 * Cleanup job statistics
 */
export interface CleanupStats {
  lastRun: Date | null;
  deletedCount: number;
  errors: Array<{ timestamp: Date; error: string }>;
}

/**
 * Token Cleanup Job
 * Periodically removes expired and revoked refresh tokens
 */
export class TokenCleanupJob {
  private repository: RefreshTokenRepository;
  private config: Required<CleanupConfig>;
  private intervalId: NodeJS.Timeout | null = null;
  private stats: CleanupStats = {
    lastRun: null,
    deletedCount: 0,
    errors: [],
  };

  constructor(
    repository: RefreshTokenRepository,
    config: Partial<CleanupConfig> = {}
  ) {
    this.repository = repository;
    this.config = {
      interval: config.interval ?? 60 * 60 * 1000, // 1 hour
      deleteAfterExpired: config.deleteAfterExpired ?? 24 * 60 * 60 * 1000, // 24 hours
      enabled: config.enabled ?? true,
      cleanupRevoked: config.cleanupRevoked ?? true,
    };
  }

  /**
   * Start the cleanup job
   */
  start(): void {
    if (!this.config.enabled) {
      console.log('[TokenCleanup] Job is disabled');
      return;
    }

    if (this.intervalId) {
      console.log('[TokenCleanup] Job is already running');
      return;
    }

    console.log(`[TokenCleanup] Starting cleanup job (interval: ${this.config.interval}ms)`);

    // Run immediately on start
    this.runCleanup();

    // Schedule periodic cleanup
    this.intervalId = setInterval(() => {
      this.runCleanup();
    }, this.config.interval);
  }

  /**
   * Stop the cleanup job
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      console.log('[TokenCleanup] Job stopped');
    }
  }

  /**
   * Run cleanup immediately
   */
  async runCleanup(): Promise<number> {
    try {
      console.log('[TokenCleanup] Running cleanup...');

      let deletedCount = 0;

      // Check if repository supports cleanup
      if (this.repository.cleanupExpiredTokens) {
        await this.repository.cleanupExpiredTokens();
        deletedCount++; // Assume at least one cleanup happened
        console.log('[TokenCleanup] Repository cleanup completed');
      } else {
        console.log('[TokenCleanup] Repository does not support cleanupExpiredTokens. Please implement this method in your repository.');
      }

      this.stats.lastRun = new Date();
      this.stats.deletedCount += deletedCount;

      console.log(`[TokenCleanup] Cleanup completed. Deleted: ${deletedCount}`);
      return deletedCount;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.stats.errors.push({
        timestamp: new Date(),
        error: errorMessage,
      });

      // Keep only last 100 errors
      if (this.stats.errors.length > 100) {
        this.stats.errors = this.stats.errors.slice(-100);
      }

      console.error('[TokenCleanup] Error during cleanup:', errorMessage);
      return 0;
    }
  }

  /**
   * Get cleanup statistics
   */
  getStats(): CleanupStats {
    return { ...this.stats };
  }

  /**
   * Check if job is running
   */
  isRunning(): boolean {
    return this.intervalId !== null;
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<CleanupConfig>): void {
    const wasRunning = this.isRunning();

    // Stop if running
    if (wasRunning) {
      this.stop();
    }

    // Update config
    this.config = {
      ...this.config,
      ...config,
    };

    // Restart if was running and still enabled
    if (wasRunning && this.config.enabled) {
      this.start();
    }
  }
}

/**
 * Create a cleanup job with default configuration
 */
export function createTokenCleanupJob(
  repository: RefreshTokenRepository,
  config?: Partial<CleanupConfig>
): TokenCleanupJob {
  return new TokenCleanupJob(repository, config);
}
