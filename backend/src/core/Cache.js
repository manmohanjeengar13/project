/**
 * Cache Core Module
 * Unified caching interface supporting both Redis and in-memory storage
 */

import NodeCache from 'node-cache';
import { Config } from '../config/environment.js';
import { Logger } from './Logger.js';
import { CACHE_KEYS, CACHE_TTL } from '../config/constants.js';

const logger = Logger.getInstance();

export class Cache {
  static instance = null;
  cache = null;
  redisClient = null;
  stats = {
    hits: 0,
    misses: 0,
    sets: 0,
    deletes: 0
  };

  constructor() {
    if (Cache.instance) {
      return Cache.instance;
    }
    Cache.instance = this;
  }

  /**
   * Get Cache singleton instance
   */
  static getInstance() {
    if (!Cache.instance) {
      Cache.instance = new Cache();
    }
    return Cache.instance;
  }

  /**
   * Initialize cache (Redis or Memory)
   */
  async initialize() {
    try {
      if (Config.redis.enabled && Config.cache.store === 'redis') {
        await this.initializeRedis();
      } else {
        this.initializeMemory();
      }
      
      logger.info(`✅ Cache initialized (${Config.cache.store})`);
    } catch (error) {
      logger.error('❌ Cache initialization failed:', error);
      // Fallback to memory cache
      this.initializeMemory();
      logger.warn('⚠️  Falling back to memory cache');
    }
  }

  /**
   * Initialize Redis cache
   */
  async initializeRedis() {
    const redis = await import('redis');
    
    this.redisClient = redis.createClient({
      socket: {
        host: Config.redis.host,
        port: Config.redis.port
      },
      password: Config.redis.password,
      database: Config.redis.db
    });

    this.redisClient.on('error', (err) => {
      logger.error('Redis Client Error:', err);
    });

    this.redisClient.on('connect', () => {
      logger.info('✓ Redis connected');
    });

    await this.redisClient.connect();
  }

  /**
   * Initialize in-memory cache
   */
  initializeMemory() {
    this.cache = new NodeCache({
      stdTTL: Config.cache.ttl,
      checkperiod: 120, // Check for expired keys every 2 minutes
      useClones: false,
      maxKeys: Config.cache.maxSize
    });

    // Listen to cache events
    this.cache.on('set', (key, value) => {
      logger.debug(`Cache SET: ${key}`);
    });

    this.cache.on('del', (key) => {
      logger.debug(`Cache DELETE: ${key}`);
    });

    this.cache.on('expired', (key) => {
      logger.debug(`Cache EXPIRED: ${key}`);
    });
  }

  /**
   * Get value from cache
   */
  async get(key) {
    try {
      let value;

      if (this.redisClient) {
        value = await this.redisClient.get(this.prefixKey(key));
        if (value) {
          value = JSON.parse(value);
          this.stats.hits++;
        } else {
          this.stats.misses++;
        }
      } else if (this.cache) {
        value = this.cache.get(key);
        if (value !== undefined) {
          this.stats.hits++;
        } else {
          this.stats.misses++;
        }
      }

      return value || null;
    } catch (error) {
      logger.error(`Cache GET error for key ${key}:`, error);
      this.stats.misses++;
      return null;
    }
  }

  /**
   * Set value in cache
   */
  async set(key, value, ttl = Config.cache.ttl) {
    try {
      if (this.redisClient) {
        await this.redisClient.setEx(
          this.prefixKey(key),
          ttl,
          JSON.stringify(value)
        );
      } else if (this.cache) {
        this.cache.set(key, value, ttl);
      }

      this.stats.sets++;
      return true;
    } catch (error) {
      logger.error(`Cache SET error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Delete value from cache
   */
  async delete(key) {
    try {
      if (this.redisClient) {
        await this.redisClient.del(this.prefixKey(key));
      } else if (this.cache) {
        this.cache.del(key);
      }

      this.stats.deletes++;
      return true;
    } catch (error) {
      logger.error(`Cache DELETE error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Check if key exists
   */
  async has(key) {
    try {
      if (this.redisClient) {
        const exists = await this.redisClient.exists(this.prefixKey(key));
        return exists === 1;
      } else if (this.cache) {
        return this.cache.has(key);
      }
      return false;
    } catch (error) {
      logger.error(`Cache HAS error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Clear all cache
   */
  async clear() {
    try {
      if (this.redisClient) {
        await this.redisClient.flushDb();
      } else if (this.cache) {
        this.cache.flushAll();
      }

      logger.info('✓ Cache cleared');
      return true;
    } catch (error) {
      logger.error('Cache CLEAR error:', error);
      return false;
    }
  }

  /**
   * Get or set pattern (cache-aside)
   */
  async getOrSet(key, callback, ttl = Config.cache.ttl) {
    // Try to get from cache
    const cached = await this.get(key);
    if (cached !== null) {
      return cached;
    }

    // If not in cache, execute callback
    try {
      const value = await callback();
      
      // Store in cache
      await this.set(key, value, ttl);
      
      return value;
    } catch (error) {
      logger.error(`getOrSet error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Remember value in cache (Laravel-style)
   */
  async remember(key, ttl, callback) {
    return this.getOrSet(key, callback, ttl);
  }

  /**
   * Cache multiple keys at once
   */
  async setMany(items, ttl = Config.cache.ttl) {
    const promises = Object.entries(items).map(([key, value]) =>
      this.set(key, value, ttl)
    );
    return Promise.all(promises);
  }

  /**
   * Get multiple keys at once
   */
  async getMany(keys) {
    const promises = keys.map(key => this.get(key));
    const values = await Promise.all(promises);
    
    return keys.reduce((acc, key, index) => {
      acc[key] = values[index];
      return acc;
    }, {});
  }

  /**
   * Delete multiple keys at once
   */
  async deleteMany(keys) {
    const promises = keys.map(key => this.delete(key));
    return Promise.all(promises);
  }

  /**
   * Delete keys by pattern
   */
  async deleteByPattern(pattern) {
    try {
      if (this.redisClient) {
        const keys = await this.redisClient.keys(`${Config.redis.prefix}${pattern}`);
        if (keys.length > 0) {
          await this.redisClient.del(keys);
        }
        return keys.length;
      } else if (this.cache) {
        const keys = this.cache.keys().filter(key => 
          new RegExp(pattern).test(key)
        );
        this.cache.del(keys);
        return keys.length;
      }
      return 0;
    } catch (error) {
      logger.error(`deleteByPattern error for pattern ${pattern}:`, error);
      return 0;
    }
  }

  /**
   * Increment numeric value
   */
  async increment(key, amount = 1) {
    try {
      if (this.redisClient) {
        return await this.redisClient.incrBy(this.prefixKey(key), amount);
      } else if (this.cache) {
        const current = (await this.get(key)) || 0;
        const newValue = current + amount;
        await this.set(key, newValue);
        return newValue;
      }
      return null;
    } catch (error) {
      logger.error(`Cache INCREMENT error for key ${key}:`, error);
      return null;
    }
  }

  /**
   * Decrement numeric value
   */
  async decrement(key, amount = 1) {
    return this.increment(key, -amount);
  }

  /**
   * Set expiration time for key
   */
  async expire(key, ttl) {
    try {
      if (this.redisClient) {
        await this.redisClient.expire(this.prefixKey(key), ttl);
      } else if (this.cache) {
        this.cache.ttl(key, ttl);
      }
      return true;
    } catch (error) {
      logger.error(`Cache EXPIRE error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Get time-to-live for key
   */
  async ttl(key) {
    try {
      if (this.redisClient) {
        return await this.redisClient.ttl(this.prefixKey(key));
      } else if (this.cache) {
        return this.cache.getTtl(key);
      }
      return null;
    } catch (error) {
      logger.error(`Cache TTL error for key ${key}:`, error);
      return null;
    }
  }

  /**
   * Add key prefix (for Redis)
   */
  prefixKey(key) {
    return `${Config.redis.prefix}${key}`;
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const baseStats = {
      ...this.stats,
      hitRate: this.stats.hits / (this.stats.hits + this.stats.misses) || 0,
      enabled: Config.cache.enabled,
      store: Config.cache.store
    };

    if (this.cache) {
      return {
        ...baseStats,
        keys: this.cache.keys().length,
        size: this.cache.getStats()
      };
    }

    return baseStats;
  }

  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0
    };
  }

  /**
   * Disconnect cache
   */
  async disconnect() {
    try {
      if (this.redisClient) {
        await this.redisClient.quit();
        logger.info('✓ Redis disconnected');
      }
      if (this.cache) {
        this.cache.close();
        logger.info('✓ Memory cache closed');
      }
    } catch (error) {
      logger.error('Cache disconnect error:', error);
    }
  }

  /**
   * Cache warming (preload common data)
   */
  async warm(dataLoader) {
    try {
      logger.info('🔥 Warming up cache...');
      const data = await dataLoader();
      
      for (const [key, value] of Object.entries(data)) {
        await this.set(key, value);
      }
      
      logger.info(`✅ Cache warmed with ${Object.keys(data).length} entries`);
    } catch (error) {
      logger.error('Cache warming failed:', error);
    }
  }
}

/**
 * Cache Key Builder Helper
 */
export class CacheKeyBuilder {
  static user(userId) {
    return `${CACHE_KEYS.USER}${userId}`;
  }

  static product(productId) {
    return `${CACHE_KEYS.PRODUCT}${productId}`;
  }

  static category(categoryId) {
    return `${CACHE_KEYS.CATEGORY}${categoryId}`;
  }

  static order(orderId) {
    return `${CACHE_KEYS.ORDER}${orderId}`;
  }

  static session(sessionId) {
    return `${CACHE_KEYS.SESSION}${sessionId}`;
  }

  static rateLimit(identifier, action) {
    return `${CACHE_KEYS.RATE_LIMIT}${identifier}:${action}`;
  }

  static token(token) {
    return `${CACHE_KEYS.TOKEN}${token}`;
  }

  static custom(prefix, ...parts) {
    return `${prefix}${parts.join(':')}`;
  }
}

export default Cache;
