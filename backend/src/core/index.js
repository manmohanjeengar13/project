/**
 * Core Module Exports
 * Central export point for all core system modules
 */

// Core classes
export { Server } from './Server.js';
export { Database } from './Database.js';
export { Logger } from './Logger.js';
export { Router, RouteBuilder } from './Router.js';
export { Cache, CacheKeyBuilder } from './Cache.js';
export { Email } from './Email.js';
export { WebSocket } from './WebSocket.js';
export { Scheduler } from './Scheduler.js';

/**
 * Initialize all core systems
 */
export async function initializeCore(app, httpServer) {
  const { Logger } = await import('./Logger.js');
  const { Database } = await import('./Database.js');
  const { Cache } = await import('./Cache.js');
  const { Email } = await import('./Email.js');
  const { WebSocket } = await import('./WebSocket.js');
  const { Scheduler } = await import('./Scheduler.js');

  const logger = Logger.getInstance();
  
  logger.info('🚀 Initializing core systems...\n');

  try {
    // 1. Logger (already initialized)
    logger.info('✓ Logger ready');

    // 2. Database
    logger.info('💾 Connecting to database...');
    const database = Database.getInstance();
    await database.connect();
    await database.testConnection();
    logger.info('✓ Database connected\n');

    // 3. Cache
    if (require('../config/environment.js').Config.cache.enabled) {
      logger.info('📦 Initializing cache...');
      const cache = Cache.getInstance();
      await cache.initialize();
      logger.info('✓ Cache ready\n');
    }

    // 4. Email
    if (require('../config/environment.js').Config.email.enabled) {
      logger.info('📧 Initializing email service...');
      const email = Email.getInstance();
      await email.initialize();
      logger.info('✓ Email service ready\n');
    }

    // 5. WebSocket
    if (require('../config/environment.js').Config.notifications.websocketEnabled && httpServer) {
      logger.info('🔌 Initializing WebSocket...');
      const ws = WebSocket.getInstance();
      ws.initialize(httpServer);
      logger.info('✓ WebSocket ready\n');
    }

    // 6. Scheduler
    logger.info('⏰ Initializing scheduler...');
    const scheduler = Scheduler.getInstance();
    await scheduler.initialize();
    logger.info('✓ Scheduler ready\n');

    logger.info('✅ All core systems initialized successfully\n');

    return {
      logger,
      database,
      cache: Cache.getInstance(),
      email: Email.getInstance(),
      websocket: WebSocket.getInstance(),
      scheduler: Scheduler.getInstance()
    };
  } catch (error) {
    logger.error('❌ Core initialization failed:', error);
    throw error;
  }
}

/**
 * Shutdown all core systems gracefully
 */
export async function shutdownCore() {
  const { Logger } = await import('./Logger.js');
  const { Database } = await import('./Database.js');
  const { Cache } = await import('./Cache.js');
  const { WebSocket } = await import('./WebSocket.js');
  const { Scheduler } = await import('./Scheduler.js');

  const logger = Logger.getInstance();
  
  logger.info('\n🛑 Shutting down core systems...\n');

  try {
    // 1. Stop scheduler
    const scheduler = Scheduler.getInstance();
    scheduler.stopAll();
    logger.info('✓ Scheduler stopped');

    // 2. Close WebSocket
    const ws = WebSocket.getInstance();
    if (ws.io) {
      await ws.close();
      logger.info('✓ WebSocket closed');
    }

    // 3. Disconnect cache
    const cache = Cache.getInstance();
    if (cache.cache || cache.redisClient) {
      await cache.disconnect();
      logger.info('✓ Cache disconnected');
    }

    // 4. Close database
    const database = Database.getInstance();
    if (database.isConnected()) {
      await database.disconnect();
      logger.info('✓ Database disconnected');
    }

    logger.info('\n✅ All core systems shut down gracefully\n');
  } catch (error) {
    logger.error('❌ Shutdown error:', error);
    throw error;
  }
}

/**
 * Get health status of all core systems
 */
export async function getCoreHealth() {
  const { Database } = await import('./Database.js');
  const { Cache } = await import('./Cache.js');
  const { WebSocket } = await import('./WebSocket.js');
  const { Scheduler } = await import('./Scheduler.js');
  const { Email } = await import('./Email.js');

  const database = Database.getInstance();
  const cache = Cache.getInstance();
  const ws = WebSocket.getInstance();
  const scheduler = Scheduler.getInstance();
  const email = Email.getInstance();

  return {
    database: {
      connected: database.isConnected(),
      stats: database.getPoolStats()
    },
    cache: {
      enabled: cache.cache !== null || cache.redisClient !== null,
      stats: cache.getStats()
    },
    websocket: {
      enabled: ws.io !== null,
      stats: ws.getStats()
    },
    scheduler: {
      stats: scheduler.getStats()
    },
    email: {
      stats: email.getStats()
    }
  };
}

export default {
  Server,
  Database,
  Logger,
  Router,
  RouteBuilder,
  Cache,
  CacheKeyBuilder,
  Email,
  WebSocket,
  Scheduler,
  initializeCore,
  shutdownCore,
  getCoreHealth
};
