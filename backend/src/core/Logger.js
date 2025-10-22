/**
 * Logger Core Module
 * Winston-based advanced logging system
 */

import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { Config } from '../config/environment.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class Logger {
  static instance = null;
  logger = null;

  constructor() {
    if (Logger.instance) {
      return Logger.instance;
    }
    
    this.logger = this.createLogger();
    Logger.instance = this;
  }

  /**
   * Get Logger singleton instance
   */
  static getInstance() {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  /**
   * Create Winston logger
   */
  createLogger() {
    const transports = [];

    // Console transport
    if (Config.logging.consoleEnabled) {
      transports.push(
        new winston.transports.Console({
          level: Config.logging.consoleLevel,
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            winston.format.printf(({ timestamp, level, message, ...meta }) => {
              let msg = `${timestamp} [${level}]: ${message}`;
              if (Object.keys(meta).length > 0) {
                msg += ` ${JSON.stringify(meta)}`;
              }
              return msg;
            })
          )
        })
      );
    }

    // File transport - General logs
    if (Config.logging.fileEnabled) {
      transports.push(
        new DailyRotateFile({
          level: Config.logging.fileLevel,
          filename: path.join(Config.logging.directory, 'app-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: Config.logging.maxSize,
          maxFiles: Config.logging.maxFiles,
          compress: Config.logging.compress,
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
          )
        })
      );

      // Error logs
      transports.push(
        new DailyRotateFile({
          level: 'error',
          filename: path.join(Config.logging.directory, 'error-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: Config.logging.maxSize,
          maxFiles: Config.logging.maxFiles,
          compress: Config.logging.compress,
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
          )
        })
      );

      // Attack logs
      if (Config.logging.attacksEnabled) {
        transports.push(
          new DailyRotateFile({
            level: Config.logging.attackLevel,
            filename: path.join(Config.logging.directory, 'attack-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: Config.logging.maxSize,
            maxFiles: Config.logging.maxFiles,
            compress: Config.logging.compress,
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json()
            )
          })
        );
      }

      // Audit logs
      if (Config.logging.auditEnabled) {
        transports.push(
          new DailyRotateFile({
            level: Config.logging.auditLevel,
            filename: path.join(Config.logging.directory, 'audit-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: Config.logging.maxSize,
            maxFiles: Config.logging.maxFiles,
            compress: Config.logging.compress,
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json()
            )
          })
        );
      }
    }

    return winston.createLogger({
      level: Config.logging.level,
      format: winston.format.combine(
        winston.format.errors({ stack: true }),
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: { 
        service: Config.app.name,
        version: Config.app.version,
        environment: Config.app.env
      },
      transports
    });
  }

  /**
   * Log methods
   */
  error(message, meta = {}) {
    this.logger.error(message, meta);
  }

  warn(message, meta = {}) {
    this.logger.warn(message, meta);
  }

  info(message, meta = {}) {
    this.logger.info(message, meta);
  }

  http(message, meta = {}) {
    this.logger.http(message, meta);
  }

  verbose(message, meta = {}) {
    this.logger.verbose(message, meta);
  }

  debug(message, meta = {}) {
    this.logger.debug(message, meta);
  }

  /**
   * Log attack detection
   */
  attack(type, details = {}) {
    this.logger.warn(`🚨 Attack Detected: ${type}`, {
      attackType: type,
      ...details,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Log security event
   */
  security(event, details = {}) {
    this.logger.info(`🔐 Security Event: ${event}`, {
      event,
      ...details,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Log audit trail
   */
  audit(action, user, details = {}) {
    this.logger.info(`📝 Audit: ${action}`, {
      action,
      user,
      ...details,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Log database query (only in debug mode)
   */
  query(sql, params = [], duration = null) {
    if (Config.app.debug) {
      this.logger.debug('Database Query', {
        sql,
        params,
        duration: duration ? `${duration}ms` : null
      });
    }
  }

  /**
   * Log API request
   */
  request(req, res, duration) {
    this.logger.http('API Request', {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });
  }
}

export default Logger;
