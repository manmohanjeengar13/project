/**
 * Server Core Module
 * Handles HTTP server initialization and middleware configuration
 */

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import morgan from 'morgan';
import { Config } from '../config/environment.js';
import { Logger } from './Logger.js';
import { setupRoutes } from '../routes/index.js';
import { errorHandler } from '../middleware/errorHandler.js';
import { attackDetectionMiddleware } from '../middleware/attackDetection.js';
import { rateLimitMiddleware } from '../middleware/rateLimit.js';
import { securityHeadersMiddleware } from '../middleware/securityHeaders.js';
import { modeSwitchMiddleware } from '../middleware/modeSwitch.js';
import { sanitizationMiddleware } from '../middleware/sanitization.js';
import { csrfMiddleware } from '../middleware/csrf.js';

const logger = Logger.getInstance();

export class Server {
  constructor(app) {
    this.app = app;
    this.isVulnerable = Config.security.mode === 'vulnerable';
  }

  /**
   * Initialize server with all middleware and routes
   */
  async initialize() {
    try {
      // Set app metadata
      this.app.set('trust proxy', 1);
      this.app.set('x-powered-by', false);
      
      // Core middleware (always enabled)
      this.setupCoreMiddleware();
      
      // Security middleware (mode-dependent)
      this.setupSecurityMiddleware();
      
      // Attack detection (mode-dependent)
      this.setupAttackDetection();
      
      // Routes
      this.setupRoutes();
      
      // Error handling
      this.setupErrorHandling();
      
      logger.info('✅ Server initialized successfully');
    } catch (error) {
      logger.error('❌ Server initialization failed:', error);
      throw error;
    }
  }

  /**
   * Setup core middleware (always enabled)
   */
  setupCoreMiddleware() {
    // Body parsing
    this.app.use(express.json({ 
      limit: this.isVulnerable ? '50mb' : '1mb',
      strict: !this.isVulnerable
    }));
    
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: this.isVulnerable ? '50mb' : '1mb'
    }));
    
    // Cookie parsing
    this.app.use(cookieParser(Config.session.secret));
    
    // Compression
    if (Config.performance.compression) {
      this.app.use(compression({
        level: Config.performance.compressionLevel,
        threshold: Config.performance.compressionThreshold
      }));
    }
    
    // HTTP logging
    if (Config.logging.enabled) {
      const morganFormat = this.isVulnerable ? 'dev' : 'combined';
      this.app.use(morgan(morganFormat, {
        stream: {
          write: (message) => logger.http(message.trim())
        }
      }));
    }
    
    // Session management
    this.setupSession();
    
    logger.info('✅ Core middleware configured');
  }

  /**
   * Setup session middleware
   */
  setupSession() {
    const sessionConfig = {
      name: Config.session.name,
      secret: Config.session.secret,
      resave: Config.session.resave,
      saveUninitialized: Config.session.saveUninitialized,
      rolling: Config.session.rolling,
      cookie: {
        httpOnly: this.isVulnerable ? false : Config.session.cookie.httpOnly,
        secure: Config.session.cookie.secure,
        sameSite: this.isVulnerable ? 'none' : Config.session.cookie.sameSite,
        maxAge: this.isVulnerable ? 7 * 24 * 60 * 60 * 1000 : Config.session.cookie.maxAge
      }
    };
    
    // Use Redis store if enabled
    if (Config.redis.enabled && Config.session.store === 'redis') {
      const RedisStore = require('connect-redis').default;
      const { createClient } = require('redis');
      
      const redisClient = createClient({
        host: Config.redis.host,
        port: Config.redis.port,
        password: Config.redis.password,
        db: Config.redis.db
      });
      
      redisClient.connect().catch(console.error);
      
      sessionConfig.store = new RedisStore({ 
        client: redisClient,
        prefix: `${Config.redis.prefix}session:`
      });
    }
    
    this.app.use(session(sessionConfig));
  }

  /**
   * Setup security middleware (mode-dependent)
   */
  setupSecurityMiddleware() {
    // CORS
    const corsOptions = {
      origin: this.isVulnerable ? true : Config.cors.origin.split(','),
      credentials: Config.cors.credentials,
      methods: Config.cors.methods.split(','),
      allowedHeaders: Config.cors.allowedHeaders.split(',')
    };
    this.app.use(cors(corsOptions));
    
    // Helmet security headers (disabled in vulnerable mode)
    if (!this.isVulnerable && Config.helmet.enabled) {
      this.app.use(helmet({
        contentSecurityPolicy: Config.csp.enabled ? {
          directives: this.parseCSPDirectives(Config.csp.directives)
        } : false,
        hsts: {
          maxAge: Config.hsts.maxAge,
          includeSubDomains: Config.hsts.includeSubdomains,
          preload: Config.hsts.preload
        },
        noSniff: true,
        xssFilter: true,
        frameguard: { action: 'deny' }
      }));
    } else {
      logger.warn('⚠️  Security headers DISABLED (vulnerable mode)');
    }
    
    // Additional security headers
    this.app.use(securityHeadersMiddleware);
    
    // Rate limiting (disabled in vulnerable mode)
    if (!this.isVulnerable && Config.rateLimit.enabled) {
      this.app.use(rateLimitMiddleware);
      logger.info('✅ Rate limiting enabled');
    } else {
      logger.warn('⚠️  Rate limiting DISABLED (vulnerable mode)');
    }
    
    // CSRF protection (disabled in vulnerable mode)
    if (!this.isVulnerable && Config.security.enableCSRF) {
      this.app.use(csrfMiddleware);
      logger.info('✅ CSRF protection enabled');
    } else {
      logger.warn('⚠️  CSRF protection DISABLED (vulnerable mode)');
    }
    
    // Input sanitization (disabled in vulnerable mode)
    if (!this.isVulnerable) {
      this.app.use(sanitizationMiddleware);
      logger.info('✅ Input sanitization enabled');
    } else {
      logger.warn('⚠️  Input sanitization DISABLED (vulnerable mode)');
    }
    
    logger.info('✅ Security middleware configured');
  }

  /**
   * Setup attack detection middleware
   */
  setupAttackDetection() {
    if (Config.security.idsEnabled) {
      this.app.use(attackDetectionMiddleware);
      logger.info('✅ Attack detection enabled');
    }
    
    // Mode switch middleware
    this.app.use(modeSwitchMiddleware);
  }

  /**
   * Setup application routes
   */
  setupRoutes() {
    // Health check (always available)
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        mode: Config.security.mode,
        version: Config.app.version,
        environment: Config.app.env
      });
    });
    
    // Metrics endpoint
    if (Config.monitoring.metricsEnabled) {
      this.app.get('/metrics', (req, res) => {
        res.json({
          memory: process.memoryUsage(),
          cpu: process.cpuUsage(),
          uptime: process.uptime(),
          timestamp: Date.now()
        });
      });
    }
    
    // API Routes
    setupRoutes(this.app);
    
    // 404 handler
    this.app.use((req, res) => {
      res.status(404).json({
        success: false,
        error: 'Route not found',
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString()
      });
    });
    
    logger.info('✅ Routes configured');
  }

  /**
   * Setup error handling middleware
   */
  setupErrorHandling() {
    this.app.use(errorHandler);
    logger.info('✅ Error handling configured');
  }

  /**
   * Parse CSP directives from string
   */
  parseCSPDirectives(directivesString) {
    const directives = {};
    directivesString.split(';').forEach(directive => {
      const [key, ...values] = directive.trim().split(' ');
      if (key) {
        directives[this.camelCase(key)] = values;
      }
    });
    return directives;
  }

  /**
   * Convert kebab-case to camelCase
   */
  camelCase(str) {
    return str.replace(/-([a-z])/g, (g) => g[1].toUpperCase());
  }
}

export default Server;
