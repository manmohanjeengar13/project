/**
 * Environment Configuration
 * Centralized configuration management
 */

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

/**
 * Parse boolean environment variable
 */
const parseBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null) return defaultValue;
  return value === 'true' || value === '1' || value === 'yes';
};

/**
 * Parse integer environment variable
 */
const parseInteger = (value, defaultValue = 0) => {
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
};

/**
 * Configuration Object
 */
export const Config = {
  // Application Settings
  app: {
    name: process.env.APP_NAME || 'SQLi Demo Platform',
    version: process.env.APP_VERSION || '3.0.0',
    env: process.env.NODE_ENV || 'development',
    url: process.env.APP_URL || 'http://localhost:4000',
    port: parseInteger(process.env.PORT, 4000),
    host: process.env.HOST || '0.0.0.0',
    debug: parseBoolean(process.env.DEBUG_ENABLED, false)
  },

  // Security Settings
  security: {
    mode: process.env.SECURITY_MODE || 'vulnerable',
    enableSQLi: parseBoolean(process.env.ENABLE_SQLI, true),
    enableXSS: parseBoolean(process.env.ENABLE_XSS, true),
    enableCSRF: parseBoolean(process.env.ENABLE_CSRF, false),
    enableIDOR: parseBoolean(process.env.ENABLE_IDOR, true),
    enableCommandInjection: parseBoolean(process.env.ENABLE_COMMAND_INJECTION, true),
    enablePathTraversal: parseBoolean(process.env.ENABLE_PATH_TRAVERSAL, true),
    enableXXE: parseBoolean(process.env.ENABLE_XXE, true),
    enableSSRF: parseBoolean(process.env.ENABLE_SSRF, true),
    wafEnabled: parseBoolean(process.env.WAF_ENABLED, false),
    idsEnabled: parseBoolean(process.env.IDS_ENABLED, true),
    idsSensitivity: process.env.IDS_SENSITIVITY || 'medium',
    idsBlockThreshold: parseInteger(process.env.IDS_BLOCK_THRESHOLD, 10),
    idsBlockDuration: parseInteger(process.env.IDS_BLOCK_DURATION_MINUTES, 60),
    honeypotEnabled: parseBoolean(process.env.HONEYPOT_ENABLED, true),
    ipBlacklistEnabled: parseBoolean(process.env.IP_BLACKLIST_ENABLED, true)
  },

  // Database Configuration
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInteger(process.env.DB_PORT, 3306),
    user: process.env.DB_USER || 'sqli_user',
    password: process.env.DB_PASSWORD || '',
    name: process.env.DB_NAME || 'sqli_demo_platform',
    charset: process.env.DB_CHARSET || 'utf8mb4',
    timezone: process.env.DB_TIMEZONE || '+00:00',
    connectionLimit: parseInteger(process.env.DB_CONNECTION_LIMIT, 10),
    queueLimit: parseInteger(process.env.DB_QUEUE_LIMIT, 0),
    waitForConnections: parseBoolean(process.env.DB_WAIT_FOR_CONNECTIONS, true),
    enableKeepAlive: parseBoolean(process.env.DB_ENABLE_KEEP_ALIVE, true),
    keepAliveInitialDelay: parseInteger(process.env.DB_KEEP_ALIVE_INITIAL_DELAY, 0),
    ssl: {
      enabled: parseBoolean(process.env.DB_SSL_ENABLED, false),
      ca: process.env.DB_SSL_CA_PATH,
      cert: process.env.DB_SSL_CERT_PATH,
      key: process.env.DB_SSL_KEY_PATH
    }
  },

  // Redis Configuration
  redis: {
    enabled: parseBoolean(process.env.REDIS_ENABLED, false),
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInteger(process.env.REDIS_PORT, 6379),
    password: process.env.REDIS_PASSWORD || '',
    db: parseInteger(process.env.REDIS_DB, 0),
    prefix: process.env.REDIS_PREFIX || 'sqli_demo:',
    ttl: parseInteger(process.env.REDIS_TTL, 3600)
  },

  // Session Configuration
  session: {
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    name: process.env.SESSION_NAME || 'sqli_demo_session',
    resave: parseBoolean(process.env.SESSION_RESAVE, false),
    saveUninitialized: parseBoolean(process.env.SESSION_SAVE_UNINITIALIZED, false),
    rolling: parseBoolean(process.env.SESSION_ROLLING, true),
    store: process.env.SESSION_STORE || 'memory',
    cookie: {
      maxAge: parseInteger(process.env.SESSION_COOKIE_MAX_AGE, 86400000),
      secure: parseBoolean(process.env.SESSION_COOKIE_SECURE, false),
      httpOnly: parseBoolean(process.env.SESSION_COOKIE_HTTP_ONLY, true),
      sameSite: process.env.SESSION_COOKIE_SAME_SITE || 'lax'
    }
  },

  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'change-this-jwt-secret',
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'change-this-refresh-secret',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: process.env.JWT_ISSUER || 'sqli-demo-platform',
    audience: process.env.JWT_AUDIENCE || 'sqli-demo-users'
  },

  // Authentication
  auth: {
    passwordMinLength: parseInteger(process.env.PASSWORD_MIN_LENGTH, 8),
    passwordRequireUppercase: parseBoolean(process.env.PASSWORD_REQUIRE_UPPERCASE, true),
    passwordRequireLowercase: parseBoolean(process.env.PASSWORD_REQUIRE_LOWERCASE, true),
    passwordRequireNumbers: parseBoolean(process.env.PASSWORD_REQUIRE_NUMBERS, true),
    passwordRequireSpecial: parseBoolean(process.env.PASSWORD_REQUIRE_SPECIAL, true),
    maxLoginAttempts: parseInteger(process.env.MAX_LOGIN_ATTEMPTS, 5),
    lockoutDuration: parseInteger(process.env.LOCKOUT_DURATION_MINUTES, 30),
    enable2FA: parseBoolean(process.env.ENABLE_2FA, false),
    twoFactorIssuer: process.env['2FA_ISSUER'] || 'SQLi Demo Platform'
  },

  // Rate Limiting
  rateLimit: {
    enabled: parseBoolean(process.env.RATE_LIMIT_ENABLED, true),
    windowMs: parseInteger(process.env.RATE_LIMIT_WINDOW_MS, 900000),
    maxRequests: parseInteger(process.env.RATE_LIMIT_MAX_REQUESTS, 100),
    skipSuccessfulRequests: parseBoolean(process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS, false),
    api: {
      windowMs: parseInteger(process.env.API_RATE_LIMIT_WINDOW_MS, 60000),
      maxRequests: parseInteger(process.env.API_RATE_LIMIT_MAX_REQUESTS, 60)
    },
    login: {
      windowMs: parseInteger(process.env.LOGIN_RATE_LIMIT_WINDOW_MS, 900000),
      maxRequests: parseInteger(process.env.LOGIN_RATE_LIMIT_MAX_REQUESTS, 5)
    }
  },

  // CORS Configuration
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: parseBoolean(process.env.CORS_CREDENTIALS, true),
    methods: process.env.CORS_METHODS || 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    allowedHeaders: process.env.CORS_ALLOWED_HEADERS || 'Content-Type,Authorization,X-Requested-With,X-CSRF-Token'
  },

  // File Upload
  upload: {
    maxFileSize: parseInteger(process.env.UPLOAD_MAX_FILE_SIZE, 10485760),
    maxFiles: parseInteger(process.env.UPLOAD_MAX_FILES, 10),
    allowedTypes: (process.env.UPLOAD_ALLOWED_TYPES || 'image/jpeg,image/png,image/gif,application/pdf').split(','),
    destination: process.env.UPLOAD_DESTINATION || './uploads',
    enableVirusScan: parseBoolean(process.env.UPLOAD_ENABLE_VIRUS_SCAN, false),
    enableImageOptimization: parseBoolean(process.env.UPLOAD_ENABLE_IMAGE_OPTIMIZATION, true),
    image: {
      maxWidth: parseInteger(process.env.IMAGE_MAX_WIDTH, 2000),
      maxHeight: parseInteger(process.env.IMAGE_MAX_HEIGHT, 2000),
      quality: parseInteger(process.env.IMAGE_QUALITY, 80),
      thumbnailWidth: parseInteger(process.env.THUMBNAIL_WIDTH, 300),
      thumbnailHeight: parseInteger(process.env.THUMBNAIL_HEIGHT, 300)
    }
  },

  // Email Configuration
  email: {
    enabled: parseBoolean(process.env.MAIL_ENABLED, false),
    host: process.env.MAIL_HOST || 'smtp.mailtrap.io',
    port: parseInteger(process.env.MAIL_PORT, 2525),
    secure: parseBoolean(process.env.MAIL_SECURE, false),
    user: process.env.MAIL_USER || '',
    password: process.env.MAIL_PASSWORD || '',
    from: {
      name: process.env.MAIL_FROM_NAME || 'SQLi Demo Platform',
      email: process.env.MAIL_FROM_EMAIL || 'noreply@sqli-demo.com'
    }
  },

  // Logging Configuration
  logging: {
    enabled: parseBoolean(process.env.LOG_ENABLED, true),
    level: process.env.LOG_LEVEL || 'debug',
    format: process.env.LOG_FORMAT || 'combined',
    directory: process.env.LOG_DIRECTORY || './logs',
    maxFiles: process.env.LOG_MAX_FILES || '30d',
    maxSize: process.env.LOG_MAX_SIZE || '20m',
    compress: parseBoolean(process.env.LOG_COMPRESS, true),
    consoleEnabled: parseBoolean(process.env.LOG_CONSOLE_ENABLED, true),
    consoleLevel: process.env.LOG_CONSOLE_LEVEL || 'debug',
    fileEnabled: parseBoolean(process.env.LOG_FILE_ENABLED, true),
    fileLevel: process.env.LOG_FILE_LEVEL || 'info',
    attacksEnabled: parseBoolean(process.env.LOG_ATTACKS, true),
    attackLevel: process.env.LOG_ATTACK_LEVEL || 'warn',
    auditEnabled: parseBoolean(process.env.LOG_AUDIT, true),
    auditLevel: process.env.LOG_AUDIT_LEVEL || 'info'
  },

  // Security Headers
  helmet: {
    enabled: parseBoolean(process.env.HELMET_ENABLED, true)
  },

  hsts: {
    maxAge: parseInteger(process.env.HSTS_MAX_AGE, 31536000),
    includeSubdomains: parseBoolean(process.env.HSTS_INCLUDE_SUBDOMAINS, true),
    preload: parseBoolean(process.env.HSTS_PRELOAD, true)
  },

  csp: {
    enabled: parseBoolean(process.env.CSP_ENABLED, true),
    directives: process.env.CSP_DIRECTIVES || "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
  },

  // Analytics
  analytics: {
    enabled: parseBoolean(process.env.ANALYTICS_ENABLED, true),
    trackPageViews: parseBoolean(process.env.TRACK_PAGE_VIEWS, true),
    trackApiCalls: parseBoolean(process.env.TRACK_API_CALLS, true),
    trackErrors: parseBoolean(process.env.TRACK_ERRORS, true),
    sampleRate: parseFloat(process.env.ANALYTICS_SAMPLE_RATE) || 1.0
  },

  // Notifications
  notifications: {
    enabled: parseBoolean(process.env.NOTIFICATIONS_ENABLED, true),
    channels: (process.env.NOTIFICATION_CHANNELS || 'email,websocket').split(','),
    websocketEnabled: parseBoolean(process.env.WEBSOCKET_ENABLED, true),
    websocketPort: parseInteger(process.env.WEBSOCKET_PORT, 4001)
  },

  // Webhooks
  webhooks: {
    enabled: parseBoolean(process.env.WEBHOOKS_ENABLED, true),
    retryAttempts: parseInteger(process.env.WEBHOOK_RETRY_ATTEMPTS, 3),
    retryDelay: parseInteger(process.env.WEBHOOK_RETRY_DELAY_MS, 1000),
    timeout: parseInteger(process.env.WEBHOOK_TIMEOUT_MS, 30000)
  },

  // Caching
  cache: {
    enabled: parseBoolean(process.env.CACHE_ENABLED, true),
    store: process.env.CACHE_STORE || 'memory',
    ttl: parseInteger(process.env.CACHE_TTL, 3600),
    maxSize: parseInteger(process.env.CACHE_MAX_SIZE, 100)
  },

  // Performance
  performance: {
    compression: parseBoolean(process.env.COMPRESSION_ENABLED, true),
    compressionLevel: parseInteger(process.env.COMPRESSION_LEVEL, 6),
    compressionThreshold: parseInteger(process.env.COMPRESSION_THRESHOLD, 1024),
    slowRequestThreshold: parseInteger(process.env.SLOW_REQUEST_THRESHOLD, 3000)
  },

  // Backup
  backup: {
    enabled: parseBoolean(process.env.BACKUP_ENABLED, true),
    schedule: process.env.BACKUP_SCHEDULE || '0 2 * * *',
    retentionDays: parseInteger(process.env.BACKUP_RETENTION_DAYS, 30),
    directory: process.env.BACKUP_DIRECTORY || './backups'
  },

  // Monitoring
  monitoring: {
    healthCheckEnabled: parseBoolean(process.env.HEALTH_CHECK_ENABLED, true),
    healthCheckPath: process.env.HEALTH_CHECK_PATH || '/health',
    metricsEnabled: parseBoolean(process.env.METRICS_ENABLED, true),
    metricsPath: process.env.METRICS_PATH || '/metrics'
  },

  // Documentation
  docs: {
    enabled: parseBoolean(process.env.API_DOCS_ENABLED, true),
    path: process.env.API_DOCS_PATH || '/api/docs',
    swaggerEnabled: parseBoolean(process.env.SWAGGER_ENABLED, true),
    swaggerPath: process.env.SWAGGER_PATH || '/swagger'
  },

  // Demo Mode
  demo: {
    enabled: parseBoolean(process.env.DEMO_MODE, true),
    resetInterval: parseInteger(process.env.DEMO_RESET_INTERVAL_HOURS, 24),
    autoSeed: parseBoolean(process.env.AUTO_SEED_DATABASE, false),
    adminUsername: process.env.SEED_ADMIN_USERNAME || 'admin',
    adminEmail: process.env.SEED_ADMIN_EMAIL || 'admin@sqli-demo.com',
    adminPassword: process.env.SEED_ADMIN_PASSWORD || 'Admin@123456'
  },

  // Integrations
  integrations: {
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
      channel: process.env.SLACK_CHANNEL || '#security-alerts'
    },
    discord: {
      webhookUrl: process.env.DISCORD_WEBHOOK_URL || ''
    }
  },

  // Advanced Features
  advanced: {
    mlEnabled: parseBoolean(process.env.ML_ENABLED, false),
    mlModelPath: process.env.ML_MODEL_PATH || './models/threat-detection.model',
    threatIntelEnabled: parseBoolean(process.env.THREAT_INTEL_ENABLED, false),
    threatIntelApiKey: process.env.THREAT_INTEL_API_KEY || '',
    geoipEnabled: parseBoolean(process.env.GEOIP_ENABLED, false),
    geoipDatabasePath: process.env.GEOIP_DATABASE_PATH || './data/GeoLite2-City.mmdb'
  },

  // Experimental
  experimental: {
    enabled: parseBoolean(process.env.EXPERIMENTAL_FEATURES, false),
    betaFeatures: parseBoolean(process.env.BETA_FEATURES, false),
    graphqlEnabled: parseBoolean(process.env.GRAPHQL_ENABLED, false),
    graphqlPath: process.env.GRAPHQL_PATH || '/graphql',
    grpcEnabled: parseBoolean(process.env.GRPC_ENABLED, false),
    grpcPort: parseInteger(process.env.GRPC_PORT, 50051)
  }
};

/**
 * Validate critical configuration
 */
export const validateConfig = () => {
  const errors = [];

  // Check database credentials
  if (!Config.database.user || !Config.database.password) {
    errors.push('Database credentials are not configured');
  }

  // Check session secret
  if (Config.session.secret === 'change-this-secret') {
    errors.push('Session secret is using default value - change it in production!');
  }

  // Check JWT secret
  if (Config.jwt.secret === 'change-this-jwt-secret') {
    errors.push('JWT secret is using default value - change it in production!');
  }

  // Check mode
  if (!['vulnerable', 'secure'].includes(Config.security.mode)) {
    errors.push('Invalid security mode. Must be "vulnerable" or "secure"');
  }

  if (errors.length > 0) {
    console.error('⚠️  Configuration Warnings:');
    errors.forEach(error => console.error(`   - ${error}`));
  }

  return errors.length === 0;
};

export default Config;
