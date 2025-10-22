/**
 * Scheduler Core Module
 * Handles cron jobs and scheduled tasks
 */

import { Logger } from './Logger.js';
import { Config } from '../config/environment.js';

const logger = Logger.getInstance();

export class Scheduler {
  static instance = null;
  jobs = new Map();
  intervals = new Map();

  constructor() {
    if (Scheduler.instance) {
      return Scheduler.instance;
    }
    Scheduler.instance = this;
  }

  /**
   * Get Scheduler singleton instance
   */
  static getInstance() {
    if (!Scheduler.instance) {
      Scheduler.instance = new Scheduler();
    }
    return Scheduler.instance;
  }

  /**
   * Initialize scheduler
   */
  async initialize() {
    logger.info('✅ Scheduler initialized');
    
    // Register default jobs
    this.registerDefaultJobs();
  }

  /**
   * Register default system jobs
   */
  registerDefaultJobs() {
    // Clean up expired sessions (every hour)
    this.scheduleJob('cleanup_sessions', '0 * * * *', async () => {
      logger.info('🧹 Running session cleanup...');
      // TODO: Implement session cleanup
    });

    // Database backup (daily at 2 AM)
    if (Config.backup.enabled) {
      this.scheduleJob('database_backup', Config.backup.schedule, async () => {
        logger.info('💾 Running database backup...');
        // TODO: Implement backup
      });
    }

    // Clean old logs (weekly)
    this.scheduleJob('cleanup_logs', '0 0 * * 0', async () => {
      logger.info('🧹 Cleaning old logs...');
      // TODO: Implement log cleanup
    });

    // Demo mode reset (if enabled)
    if (Config.demo.enabled) {
      const intervalHours = Config.demo.resetInterval;
      this.scheduleInterval('demo_reset', intervalHours * 60 * 60 * 1000, async () => {
        logger.info('🔄 Resetting demo data...');
        // TODO: Implement demo reset
      });
    }
  }

  /**
   * Schedule a cron job
   */
  scheduleJob(name, cronExpression, callback) {
    try {
      // For simplicity, using setInterval with calculated delay
      // In production, use node-cron or similar library
      const interval = this.parseCronToInterval(cronExpression);
      
      const job = {
        name,
        cronExpression,
        callback,
        interval,
        lastRun: null,
        nextRun: new Date(Date.now() + interval),
        enabled: true
      };

      this.jobs.set(name, job);
      
      // Schedule execution
      const timerId = setInterval(async () => {
        if (job.enabled) {
          try {
            job.lastRun = new Date();
            await callback();
            job.nextRun = new Date(Date.now() + interval);
          } catch (error) {
            logger.error(`Job ${name} failed:`, error);
          }
        }
      }, interval);

      this.intervals.set(name, timerId);
      
      logger.info(`✓ Job scheduled: ${name} (${cronExpression})`);
      
      return job;
    } catch (error) {
      logger.error(`Failed to schedule job ${name}:`, error);
      return null;
    }
  }

  /**
   * Schedule a recurring interval job
   */
  scheduleInterval(name, intervalMs, callback) {
    const job = {
      name,
      interval: intervalMs,
      callback,
      lastRun: null,
      nextRun: new Date(Date.now() + intervalMs),
      enabled: true
    };

    this.jobs.set(name, job);
    
    const timerId = setInterval(async () => {
      if (job.enabled) {
        try {
          job.lastRun = new Date();
          await callback();
          job.nextRun = new Date(Date.now() + intervalMs);
        } catch (error) {
          logger.error(`Job ${name} failed:`, error);
        }
      }
    }, intervalMs);

    this.intervals.set(name, timerId);
    
    logger.info(`✓ Interval job scheduled: ${name} (every ${intervalMs}ms)`);
    
    return job;
  }

  /**
   * Schedule a one-time delayed job
   */
  scheduleOnce(name, delay, callback) {
    const job = {
      name,
      delay,
      callback,
      scheduledFor: new Date(Date.now() + delay),
      type: 'once'
    };

    const timerId = setTimeout(async () => {
      try {
        await callback();
        this.jobs.delete(name);
        this.intervals.delete(name);
        logger.info(`✓ One-time job completed: ${name}`);
      } catch (error) {
        logger.error(`One-time job ${name} failed:`, error);
      }
    }, delay);

    this.jobs.set(name, job);
    this.intervals.set(name, timerId);
    
    logger.info(`✓ One-time job scheduled: ${name} (in ${delay}ms)`);
    
    return job;
  }

  /**
   * Cancel a scheduled job
   */
  cancelJob(name) {
    if (this.intervals.has(name)) {
      clearInterval(this.intervals.get(name));
      this.intervals.delete(name);
    }

    if (this.jobs.has(name)) {
      this.jobs.delete(name);
      logger.info(`✓ Job cancelled: ${name}`);
      return true;
    }

    return false;
  }

  /**
   * Enable a job
   */
  enableJob(name) {
    const job = this.jobs.get(name);
    if (job) {
      job.enabled = true;
      logger.info(`✓ Job enabled: ${name}`);
      return true;
    }
    return false;
  }

  /**
   * Disable a job
   */
  disableJob(name) {
    const job = this.jobs.get(name);
    if (job) {
      job.enabled = false;
      logger.info(`✓ Job disabled: ${name}`);
      return true;
    }
    return false;
  }

  /**
   * Run a job immediately
   */
  async runJob(name) {
    const job = this.jobs.get(name);
    if (job && job.callback) {
      try {
        logger.info(`▶️  Running job: ${name}`);
        job.lastRun = new Date();
        await job.callback();
        logger.info(`✓ Job completed: ${name}`);
        return true;
      } catch (error) {
        logger.error(`Job ${name} failed:`, error);
        return false;
      }
    }
    return false;
  }

  /**
   * Get all jobs
   */
  getJobs() {
    return Array.from(this.jobs.values());
  }

  /**
   * Get job by name
   */
  getJob(name) {
    return this.jobs.get(name);
  }

  /**
   * Get job status
   */
  getJobStatus(name) {
    const job = this.jobs.get(name);
    if (!job) return null;

    return {
      name: job.name,
      enabled: job.enabled,
      lastRun: job.lastRun,
      nextRun: job.nextRun,
      interval: job.interval || job.delay,
      type: job.type || 'recurring'
    };
  }

  /**
   * Stop all jobs
   */
  stopAll() {
    for (const [name, timerId] of this.intervals) {
      clearInterval(timerId);
      logger.debug(`Stopped job: ${name}`);
    }

    this.jobs.clear();
    this.intervals.clear();
    
    logger.info('✓ All scheduled jobs stopped');
  }

  /**
   * Parse simple cron expression to interval (milliseconds)
   * This is a simplified parser - use node-cron for production
   */
  parseCronToInterval(cronExpression) {
    // Default to 1 hour for complex expressions
    // In production, use proper cron parser
    const parts = cronExpression.split(' ');
    
    // Try to detect simple patterns
    if (cronExpression === '* * * * *') return 60 * 1000; // Every minute
    if (cronExpression.startsWith('0 * * * *')) return 60 * 60 * 1000; // Every hour
    if (cronExpression.startsWith('0 0 * * *')) return 24 * 60 * 60 * 1000; // Daily
    if (cronExpression.startsWith('0 0 * * 0')) return 7 * 24 * 60 * 60 * 1000; // Weekly
    
    // Default: 1 hour
    return 60 * 60 * 1000;
  }

  /**
   * Get scheduler statistics
   */
  getStats() {
    const jobs = Array.from(this.jobs.values());
    
    return {
      totalJobs: jobs.length,
      enabledJobs: jobs.filter(j => j.enabled).length,
      disabledJobs: jobs.filter(j => j.enabled === false).length,
      jobs: jobs.map(j => ({
        name: j.name,
        enabled: j.enabled,
        lastRun: j.lastRun,
        nextRun: j.nextRun
      }))
    };
  }
}

export default Scheduler;
