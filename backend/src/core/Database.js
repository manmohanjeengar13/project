/**
 * Database Core Module
 * Singleton pattern for database connection management
 */

import mysql from 'mysql2/promise';
import { Config } from '../config/environment.js';
import { Logger } from './Logger.js';

const logger = Logger.getInstance();

export class Database {
  static instance = null;
  pool = null;
  
  constructor() {
    if (Database.instance) {
      return Database.instance;
    }
    Database.instance = this;
  }

  /**
   * Get Database singleton instance
   */
  static getInstance() {
    if (!Database.instance) {
      Database.instance = new Database();
    }
    return Database.instance;
  }

  /**
   * Create database connection pool
   */
  async connect() {
    try {
      const config = {
        host: Config.database.host,
        port: Config.database.port,
        user: Config.database.user,
        password: Config.database.password,
        database: Config.database.name,
        charset: Config.database.charset,
        timezone: Config.database.timezone,
        waitForConnections: Config.database.waitForConnections,
        connectionLimit: Config.database.connectionLimit,
        queueLimit: Config.database.queueLimit,
        enableKeepAlive: Config.database.enableKeepAlive,
        keepAliveInitialDelay: Config.database.keepAliveInitialDelay,
        dateStrings: true,
        supportBigNumbers: true,
        bigNumberStrings: true,
        multipleStatements: false // Security: prevent multiple queries
      };

      // Add SSL if enabled
      if (Config.database.ssl.enabled) {
        config.ssl = {
          ca: Config.database.ssl.ca,
          cert: Config.database.ssl.cert,
          key: Config.database.ssl.key,
          rejectUnauthorized: true
        };
      }

      this.pool = mysql.createPool(config);
      
      logger.info('✅ Database pool created');
      return this.pool;
    } catch (error) {
      logger.error('❌ Failed to create database pool:', error);
      throw error;
    }
  }

  /**
   * Test database connection
   */
  async testConnection() {
    try {
      const connection = await this.pool.getConnection();
      await connection.ping();
      connection.release();
      logger.info('✅ Database connection test successful');
      return true;
    } catch (error) {
      logger.error('❌ Database connection test failed:', error);
      throw error;
    }
  }

  /**
   * Execute parameterized query (secure)
   */
  async execute(sql, params = []) {
    try {
      const [rows] = await this.pool.execute(sql, params);
      return rows;
    } catch (error) {
      logger.error('Database execute error:', error);
      throw error;
    }
  }

  /**
   * Execute raw query (vulnerable - only in vulnerable mode)
   */
  async query(sql, params = []) {
    try {
      if (Config.security.mode !== 'vulnerable') {
        throw new Error('Raw queries are not allowed in secure mode');
      }
      const [rows] = await this.pool.query(sql, params);
      return rows;
    } catch (error) {
      logger.error('Database query error:', error);
      throw error;
    }
  }

  /**
   * Begin transaction
   */
  async beginTransaction() {
    const connection = await this.pool.getConnection();
    await connection.beginTransaction();
    return connection;
  }

  /**
   * Commit transaction
   */
  async commit(connection) {
    await connection.commit();
    connection.release();
  }

  /**
   * Rollback transaction
   */
  async rollback(connection) {
    await connection.rollback();
    connection.release();
  }

  /**
   * Execute query with transaction
   */
  async transaction(callback) {
    const connection = await this.beginTransaction();
    try {
      const result = await callback(connection);
      await this.commit(connection);
      return result;
    } catch (error) {
      await this.rollback(connection);
      throw error;
    }
  }

  /**
   * Get pool statistics
   */
  getPoolStats() {
    if (!this.pool) return null;
    
    return {
      totalConnections: this.pool._allConnections?.length || 0,
      freeConnections: this.pool._freeConnections?.length || 0,
      queueLength: this.pool._connectionQueue?.length || 0
    };
  }

  /**
   * Close database connections
   */
  async disconnect() {
    try {
      if (this.pool) {
        await this.pool.end();
        this.pool = null;
        logger.info('✅ Database connections closed');
      }
    } catch (error) {
      logger.error('❌ Error closing database connections:', error);
      throw error;
    }
  }

  /**
   * Check if connected
   */
  isConnected() {
    return this.pool !== null;
  }
}

export default Database;
