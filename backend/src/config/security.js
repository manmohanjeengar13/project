/**
 * Security Configuration Module
 * Centralized security settings for the application
 */

import { Config } from './environment.js';

/**
 * Security Mode Configuration
 */
export const securityMode = {
  current: Config.security.mode,
  isVulnerable: Config.security.mode === 'vulnerable',
  isSecure: Config.security.mode === 'secure',
  
  // Individual vulnerability toggles
  vulnerabilities: {
    sqli: Config.security.enableSQLi,
    xss: Config.security.enableXSS,
    csrf: Config.security.enableCSRF,
    idor: Config.security.enableIDOR,
    commandInjection: Config.security.enableCommandInjection,
    pathTraversal: Config.security.enablePathTraversal,
    xxe: Config.security.enableXXE,
    ssrf: Config.security.enableSSRF
  }
};

/**
 * Authentication Configuration
 */
export const authConfig = {
  // Password Policy
  password: {
    minLength: Config.auth.passwordMinLength,
    requireUppercase: Config.auth.passwordRequireUppercase,
    requireLowercase: Config.auth.passwordRequireLowercase,
    requireNumbers: Config.auth.passwordRequireNumbers,
    requireSpecial: Config.auth.passwordRequireSpecial,
    
    // Password strength regex
    strongRegex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    mediumRegex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$/,
    
    // Bcrypt rounds (higher = more secure but slower)
    bcryptRounds: securityMode.isVulnerable ? 10 : 12,
    
    // Password history (prevent reuse)
    historyCount: securityMode.isSecure ? 5 : 0,
    
    // Password expiration (days)
    expirationDays: securityMode.isSecure ? 90 : 0
  },

  // Account Lockout
  lockout: {
    enabled: securityMode.isSecure,
    maxAttempts: Config.auth.maxLoginAttempts,
    durationMinutes: Config.auth.lockoutDuration,
    resetOnSuccess: true
  },

  // Two-Factor Authentication
  twoFactor: {
    enabled: Config.auth.enable2FA,
    issuer: Config.auth.twoFactorIssuer,
    window: 2, // Time window for TOTP validation
    algorithm: 'SHA1',
    digits: 6,
    period: 30
  },

  // Session Configuration
  session: {
    name: Config.session.name,
    secret: Config.session.secret,
    maxAge: Config.session.cookie.maxAge,
    secure: Config.session.cookie.secure,
    httpOnly: securityMode.isSecure ? Config.session.cookie.httpOnly : false,
    sameSite: securityMode.isSecure ? Config.session.cookie.sameSite : 'none',
    
    // Session regeneration
    regenerateOnLogin: securityMode.isSecure,
    regenerateInterval: securityMode.isSecure ? 15 * 60 * 1000 : 0, // 15 minutes
    
    // Concurrent sessions
    maxConcurrentSessions: securityMode.isVulnerable ? 999 : 3
  },

  // JWT Configuration
  jwt: {
    secret: Config.jwt.secret,
    expiresIn: Config.jwt.expiresIn,
    algorithm: 'HS256',
    issuer: Config.jwt.issuer,
    audience: Config.jwt.audience,
    
    // Refresh tokens
    refresh: {
      enabled: true,
      secret: Config.jwt.refreshSecret,
      expiresIn: Config.jwt.refreshExpiresIn
    },
    
    // Token rotation
    rotateOnRefresh: securityMode.isSecure,
    
    // Blacklist for revoked tokens
    blacklistEnabled: securityMode.isSecure
  }
};

/**
 * Rate Limiting Configuration
 */
export const rateLimitConfig = {
  enabled: securityMode.isSecure && Config.rateLimit.enabled,
  
  // Global rate limit
  global: {
    windowMs: Config.rateLimit.windowMs,
    max: securityMode.isVulnerable ? 10000 : Config.rateLimit.maxRequests,
    message: 'Too many requests from this IP, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: Config.rateLimit.skipSuccessfulRequests,
    skipFailedRequests: false
  },

  // API rate limit
  api: {
    windowMs: Config.rateLimit.api.windowMs,
    max: securityMode.isVulnerable ? 10000 : Config.rateLimit.api.maxRequests,
    message: 'API rate limit exceeded'
  },

  // Login rate limit (stricter)
  login: {
    windowMs: Config.rateLimit.login.windowMs,
    max: securityMode.isVulnerable ? 10000 : Config.rateLimit.login.maxRequests,
    message: 'Too many login attempts, please try again later',
    skipSuccessfulRequests: false
  },

  // Registration rate limit
  register: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: securityMode.isVulnerable ? 10000 : 5,
    message: 'Too many registration attempts'
  },

  // Password reset rate limit
  passwordReset: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: securityMode.isVulnerable ? 10000 : 3,
    message: 'Too many password reset attempts'
  }
};

/**
 * CORS Configuration
 */
export const corsConfig = {
  origin: securityMode.isVulnerable ? true : Config.cors.origin.split(','),
  credentials: Config.cors.credentials,
  methods: Config.cors.methods.split(','),
  allowedHeaders: Config.cors.allowedHeaders.split(','),
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 204
};

/**
 * Helmet Security Headers Configuration
 */
export const helmetConfig = {
  enabled: securityMode.isSecure && Config.helmet.enabled,
  
  // Content Security Policy
  contentSecurityPolicy: Config.csp.enabled ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: []
    }
  } : false,

  // HTTP Strict Transport Security
  hsts: {
    maxAge: Config.hsts.maxAge,
    includeSubDomains: Config.hsts.includeSubdomains,
    preload: Config.hsts.preload
  },

  // Other security headers
  noSniff: true, // X-Content-Type-Options: nosniff
  frameguard: { action: 'deny' }, // X-Frame-Options: DENY
  xssFilter: true, // X-XSS-Protection: 1; mode=block
  ieNoOpen: true, // X-Download-Options: noopen
  hidePoweredBy: true, // Remove X-Powered-By
  dnsPrefetchControl: { allow: false }, // X-DNS-Prefetch-Control: off
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
};

/**
 * Input Validation Configuration
 */
export const validationConfig = {
  enabled: securityMode.isSecure,
  
  // Sanitization rules
  sanitization: {
    stripTags: true,
    trim: true,
    escape: true,
    normalizeEmail: true
  },

  // Maximum input lengths
  maxLengths: {
    username: 50,
    email: 100,
    password: 255,
    name: 100,
    description: 5000,
    comment: 2000,
    address: 500,
    phone: 20,
    zipCode: 10
  },

  // Allowed characters patterns
  patterns: {
    username: /^[a-zA-Z0-9_-]{3,50}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    phone: /^\+?[\d\s\-()]+$/,
    alphanumeric: /^[a-zA-Z0-9]+$/,
    alphanumericWithSpaces: /^[a-zA-Z0-9\s]+$/
  }
};

/**
 * CSRF Protection Configuration
 */
export const csrfConfig = {
  enabled: securityMode.isSecure && Config.security.enableCSRF,
  cookie: {
    key: '_csrf',
    path: '/',
    httpOnly: true,
    secure: Config.session.cookie.secure,
    sameSite: 'strict'
  },
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  value: (req) => req.headers['x-csrf-token'] || req.body._csrf || req.query._csrf
};

/**
 * Attack Detection Configuration
 */
export const attackDetectionConfig = {
  // Intrusion Detection System
  ids: {
    enabled: Config.security.idsEnabled,
    sensitivity: Config.security.idsSensitivity, // low, medium, high
    blockThreshold: Config.security.idsBlockThreshold,
    blockDuration: Config.security.idsBlockDuration * 60 * 1000, // Convert to ms
    
    // Detection patterns
    patterns: {
      sqli: [
        /(\bor\b|\band\b).*?['"]\s*=\s*['"]/i,
        /union.*select/i,
        /\/\*.*?\*\//,
        /--/,
        /;.*?(drop|delete|insert|update)/i,
        /sleep\s*\(/i,
        /benchmark\s*\(/i,
        /waitfor\s+delay/i,
        /'.*?or.*?'.*?=/i,
        /\bexec\b.*?\(/i,
        /\bxp_\w+/i
      ],
      xss: [
        /<script.*?>.*?<\/script>/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /<iframe/i,
        /<img.*?onerror/i,
        /<svg.*?onload/i,
        /<object/i,
        /<embed/i,
        /data:text\/html/i
      ],
      commandInjection: [
        /[;&|`$()]/,
        /\bcat\b|\bls\b|\bpwd\b|\bwhoami\b/i,
        /\bcurl\b|\bwget\b/i,
        /\brm\b|\bmv\b|\bcp\b/i
      ],
      pathTraversal: [
        /\.\./,
        /%2e%2e/i,
        /\.\.%2f/i,
        /%2e%2e%2f/i
      ]
    }
  },

  // Web Application Firewall
  waf: {
    enabled: Config.security.wafEnabled,
    mode: securityMode.isVulnerable ? 'monitor' : 'block', // monitor or block
    rules: [
      {
        id: 'WAF-001',
        name: 'SQL Injection Protection',
        enabled: true,
        action: 'block'
      },
      {
        id: 'WAF-002',
        name: 'XSS Protection',
        enabled: true,
        action: 'block'
      },
      {
        id: 'WAF-003',
        name: 'Command Injection Protection',
        enabled: true,
        action: 'block'
      },
      {
        id: 'WAF-004',
        name: 'Path Traversal Protection',
        enabled: true,
        action: 'block'
      }
    ]
  },

  // Honeypot
  honeypot: {
    enabled: Config.security.honeypotEnabled,
    fields: ['website', 'url', 'homepage'], // Hidden fields that bots fill
    redirectUrl: '/robots.txt' // Where to redirect bots
  },

  // IP Blacklist
  ipBlacklist: {
    enabled: Config.security.ipBlacklistEnabled,
    checkProxies: true,
    autoBlock: securityMode.isSecure,
    blockDuration: 24 * 60 * 60 * 1000, // 24 hours
    whitelist: ['127.0.0.1', '::1'] // Always allow localhost
  }
};

/**
 * File Upload Security Configuration
 */
export const fileUploadConfig = {
  // Maximum sizes
  maxFileSize: securityMode.isVulnerable ? 100 * 1024 * 1024 : Config.upload.maxFileSize, // 100MB vuln, 10MB secure
  maxFiles: Config.upload.maxFiles,

  // Allowed MIME types
  allowedMimeTypes: securityMode.isVulnerable ? [] : Config.upload.allowedTypes,

  // Allowed extensions
  allowedExtensions: securityMode.isVulnerable 
    ? [] 
    : ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.doc', '.docx'],

  // Blocked extensions (always blocked)
  blockedExtensions: securityMode.isSecure 
    ? ['.exe', '.sh', '.bat', '.cmd', '.php', '.jsp', '.asp', '.aspx', '.js', '.html', '.htm']
    : [],

  // Virus scanning
  virusScan: {
    enabled: Config.upload.enableVirusScan && securityMode.isSecure,
    onInfection: 'delete' // delete, quarantine, or reject
  },

  // File validation
  validation: {
    checkMagicBytes: securityMode.isSecure, // Verify file type by content, not extension
    preventDoubleExtension: securityMode.isSecure, // Prevent file.jpg.php
    sanitizeFilename: securityMode.isSecure
  },

  // Storage
  destination: Config.upload.destination,
  generateUniqueFilename: securityMode.isSecure
};

/**
 * Encryption Configuration
 */
export const encryptionConfig = {
  // Algorithm
  algorithm: 'aes-256-gcm',
  
  // Key derivation
  keyDerivation: {
    algorithm: 'pbkdf2',
    iterations: 100000,
    keyLength: 32,
    digest: 'sha256'
  },

  // Token generation
  token: {
    length: 32,
    encoding: 'hex'
  }
};

/**
 * Audit Logging Configuration
 */
export const auditConfig = {
  enabled: Config.logging.auditEnabled,
  
  // Events to audit
  events: {
    authentication: true,
    authorization: true,
    dataAccess: true,
    dataModification: true,
    adminActions: true,
    securityEvents: true,
    configurationChanges: true
  },

  // Sensitive fields to mask
  sensitiveFields: ['password', 'token', 'secret', 'apiKey', 'creditCard', 'ssn'],

  // Retention period (days)
  retentionDays: 365
};

export default {
  securityMode,
  authConfig,
  rateLimitConfig,
  corsConfig,
  helmetConfig,
  validationConfig,
  csrfConfig,
  attackDetectionConfig,
  fileUploadConfig,
  encryptionConfig,
  auditConfig
};
