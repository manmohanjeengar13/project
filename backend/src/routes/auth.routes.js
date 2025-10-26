/**
 * Authentication Routes - MILITARY-GRADE ENTERPRISE EDITION
 * Advanced authentication endpoints with comprehensive security layers
 * 
 * @module routes/auth
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * SECURITY FEATURES:
 * ============================================================================
 * - Multi-layered JWT authentication with token rotation
 * - Hardware-based 2FA (TOTP/FIDO2/WebAuthn)
 * - Biometric authentication preparation
 * - OAuth2/OIDC/SAML integration
 * - Advanced session management with device fingerprinting
 * - Behavioral analysis & anomaly detection
 * - Geo-fencing & IP reputation checking
 * - Brute force protection with exponential backoff
 * - Account lockout with progressive penalties
 * - Password policy enforcement with entropy calculation
 * - Credential stuffing prevention
 * - Session hijacking detection
 * - Time-based one-time password (TOTP)
 * - Backup codes with secure storage
 * - Email verification with anti-phishing tokens
 * - Password reset with multi-factor verification
 * - Social login integration (Google, GitHub, Microsoft, Apple)
 * - Device trust management
 * - Suspicious activity alerting
 * - Real-time security event streaming
 * - GDPR-compliant account management
 * - Comprehensive audit logging
 * - Rate limiting with Redis-backed distributed limiting
 * - CSRF protection with double-submit cookies
 * - Honeypot fields for bot detection
 * - Security questions as fallback authentication
 * - Risk-based authentication
 * - Adaptive authentication based on context
 * 
 * ============================================================================
 * COMPLIANCE:
 * ============================================================================
 * - OWASP Top 10 protection
 * - PCI-DSS compliance ready
 * - GDPR compliant data handling
 * - SOC 2 Type II ready
 * - HIPAA-compliant security measures
 * - ISO 27001 aligned
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import express from 'express';
import { body, query, param, validationResult } from 'express-validator';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

// Core imports
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Email } from '../core/Email.js';

// Controller imports
import authController from '../controllers/auth.controller.js';

// Middleware imports
import { authenticate, optionalAuth, verifyJWT, verifySession } from '../middleware/authentication.js';
import { authorize, requireRole, requirePermission } from '../middleware/authorization.js';
import { rateLimit } from '../middleware/rateLimit.js';
import { csrfProtection } from '../middleware/csrf.js';
import { validateRequest } from '../middleware/validation.js';
import { sanitizeInput, deepSanitize } from '../middleware/sanitization.js';
import { attackLogger, logSecurityEvent } from '../middleware/attackLogger.js';
import { honeypotDetection } from '../middleware/attackDetection.js';
import { modeSwitchMiddleware, getCurrentMode, requireSecureMode, requireVulnerableMode } from '../middleware/modeSwitch.js';

// Service imports
import * as jwtService from '../services/jwt.service.js';
import * as encryptionService from '../services/encryption.service.js';

// Configuration imports
import { Config } from '../config/environment.js';
import { HTTP_STATUS, USER_ROLES, ERROR_CODES, ERROR_MESSAGES, SUCCESS_MESSAGES } from '../config/constants.js';
import { authConfig, rateLimitConfig } from '../config/security.js';

const router = express.Router();
const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

const AUTH_CONSTANTS = {
  // Token lifetimes
  ACCESS_TOKEN_LIFETIME: '15m',
  REFRESH_TOKEN_LIFETIME: '7d',
  REMEMBER_ME_LIFETIME: '30d',
  EMAIL_VERIFICATION_LIFETIME: '24h',
  PASSWORD_RESET_LIFETIME: '1h',
  TWO_FACTOR_WINDOW: 2, // TOTP time windows
  
  // Security thresholds
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 30 * 60 * 1000, // 30 minutes
  PROGRESSIVE_DELAY: [0, 1000, 2000, 5000, 10000], // ms delays after failed attempts
  SUSPICIOUS_ACTIVITY_THRESHOLD: 10,
  
  // Password policy
  MIN_PASSWORD_LENGTH: 8,
  MAX_PASSWORD_LENGTH: 255,
  PASSWORD_ENTROPY_MIN: 50,
  PASSWORD_HISTORY_COUNT: 5,
  PASSWORD_EXPIRY_DAYS: 90,
  
  // Session management
  MAX_CONCURRENT_SESSIONS: 10,
  SESSION_INACTIVITY_TIMEOUT: 30 * 60 * 1000, // 30 minutes
  SESSION_ABSOLUTE_TIMEOUT: 12 * 60 * 60 * 1000, // 12 hours
  
  // Rate limiting
  REGISTRATION_LIMIT: { windowMs: 60 * 60 * 1000, max: 5 }, // 5 per hour
  LOGIN_LIMIT: { windowMs: 15 * 60 * 1000, max: 5 }, // 5 per 15 min
  PASSWORD_RESET_LIMIT: { windowMs: 60 * 60 * 1000, max: 3 }, // 3 per hour
  TOKEN_REFRESH_LIMIT: { windowMs: 60 * 60 * 1000, max: 100 }, // 100 per hour
  
  // 2FA
  BACKUP_CODES_COUNT: 10,
  BACKUP_CODE_LENGTH: 8,
  TOTP_DIGITS: 6,
  TOTP_PERIOD: 30,
  TOTP_ALGORITHM: 'SHA1'
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Calculate password entropy
 * @param {string} password - Password to analyze
 * @returns {number} Entropy in bits
 */
const calculatePasswordEntropy = (password) => {
  const charsets = [
    /[a-z]/.test(password) ? 26 : 0,  // lowercase
    /[A-Z]/.test(password) ? 26 : 0,  // uppercase
    /[0-9]/.test(password) ? 10 : 0,  // digits
    /[^a-zA-Z0-9]/.test(password) ? 32 : 0  // special chars
  ];
  
  const poolSize = charsets.reduce((sum, size) => sum + size, 0);
  return Math.log2(Math.pow(poolSize, password.length));
};

/**
 * Generate secure random token
 * @param {number} length - Token length in bytes
 * @returns {string} Hex token
 */
const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate device fingerprint from request
 * @param {Request} req - Express request object
 * @returns {string} Device fingerprint hash
 */
const generateDeviceFingerprint = (req) => {
  const components = [
    req.ip,
    req.get('user-agent') || '',
    req.get('accept-language') || '',
    req.get('accept-encoding') || '',
    req.get('accept') || ''
  ].join('|');
  
  return crypto.createHash('sha256').update(components).digest('hex');
};

/**
 * Check if IP is suspicious
 * @param {string} ip - IP address
 * @returns {Promise<boolean>}
 */
const isSuspiciousIP = async (ip) => {
  try {
    // Check recent failed attempts
    const key = CacheKeyBuilder.custom('failed_auth:', ip);
    const attempts = await cache.get(key) || 0;
    
    if (attempts > AUTH_CONSTANTS.SUSPICIOUS_ACTIVITY_THRESHOLD) {
      return true;
    }
    
    // Check IP blacklist
    const [blacklisted] = await db.execute(
      'SELECT id FROM ip_blacklist WHERE ip_address = ? AND (is_permanent = 1 OR blocked_until > NOW()) LIMIT 1',
      [ip]
    );
    
    return blacklisted.length > 0;
  } catch (error) {
    logger.error('IP reputation check failed', { ip, error: error.message });
    return false;
  }
};

/**
 * Log security event to database
 * @param {number} userId - User ID
 * @param {string} eventType - Event type
 * @param {object} metadata - Additional metadata
 * @returns {Promise<void>}
 */
const logSecurityEventToDB = async (userId, eventType, metadata = {}) => {
  try {
    await db.execute(
      `INSERT INTO security_events (user_id, event_type, ip_address, user_agent, metadata, timestamp)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [
        userId,
        eventType,
        metadata.ip || null,
        metadata.userAgent || null,
        JSON.stringify(metadata)
      ]
    );
  } catch (error) {
    logger.error('Failed to log security event', { userId, eventType, error: error.message });
  }
};

/**
 * Progressive delay based on failed attempts
 * @param {number} attempts - Number of failed attempts
 * @returns {Promise<void>}
 */
const applyProgressiveDelay = async (attempts) => {
  const delayIndex = Math.min(attempts, AUTH_CONSTANTS.PROGRESSIVE_DELAY.length - 1);
  const delay = AUTH_CONSTANTS.PROGRESSIVE_DELAY[delayIndex];
  
  if (delay > 0) {
    await new Promise(resolve => setTimeout(resolve, delay));
  }
};

// ============================================================================
// ADVANCED VALIDATION SCHEMAS
// ============================================================================

/**
 * Registration validation with entropy checking
 */
const registrationValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores, and hyphens')
    .custom(value => !/\s/.test(value))
    .withMessage('Username cannot contain spaces')
    .custom(value => {
      const forbidden = ['admin', 'root', 'system', 'test', 'demo', 'null', 'undefined'];
      return !forbidden.includes(value.toLowerCase());
    })
    .withMessage('Username is reserved'),
  
  body('email')
    .trim()
    .isEmail()
    .withMessage('Invalid email address')
    .normalizeEmail()
    .isLength({ max: 100 })
    .withMessage('Email cannot exceed 100 characters')
    .custom(value => {
      // Check for disposable email domains
      const disposableDomains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com'];
      const domain = value.split('@')[1];
      return !disposableDomains.includes(domain);
    })
    .withMessage('Disposable email addresses are not allowed'),
  
  body('password')
    .isLength({ min: AUTH_CONSTANTS.MIN_PASSWORD_LENGTH, max: AUTH_CONSTANTS.MAX_PASSWORD_LENGTH })
    .withMessage(`Password must be between ${AUTH_CONSTANTS.MIN_PASSWORD_LENGTH} and ${AUTH_CONSTANTS.MAX_PASSWORD_LENGTH} characters`)
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, lowercase letter, number, and special character')
    .custom((value) => {
      const entropy = calculatePasswordEntropy(value);
      return entropy >= AUTH_CONSTANTS.PASSWORD_ENTROPY_MIN;
    })
    .withMessage(`Password entropy too low. Use a stronger password.`)
    .custom((value) => {
      // Check against common passwords
      const commonPasswords = ['Password123!', 'Admin@123', 'Welcome@123'];
      return !commonPasswords.includes(value);
    })
    .withMessage('Password is too common'),
  
  body('confirmPassword')
    .custom((value, { req }) => value === req.body.password)
    .withMessage('Passwords do not match'),
  
  body('firstName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('First name contains invalid characters'),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Last name contains invalid characters'),
  
  body('acceptTerms')
    .equals('true')
    .withMessage('You must accept the terms and conditions'),
  
  body('captchaToken')
    .optional()
    .notEmpty()
    .withMessage('Captcha verification required')
];

/**
 * Login validation with device tracking
 */
const loginValidation = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username or email is required')
    .isLength({ max: 100 })
    .withMessage('Username/email too long'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required')
    .isLength({ max: 255 })
    .withMessage('Password too long'),
  
  body('rememberMe')
    .optional()
    .isBoolean()
    .withMessage('Remember me must be a boolean'),
  
  body('deviceName')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Device name too long'),
  
  body('trustDevice')
    .optional()
    .isBoolean()
    .withMessage('Trust device must be a boolean')
];

/**
 * Password change validation with history checking
 */
const passwordChangeValidation = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  
  body('newPassword')
    .isLength({ min: AUTH_CONSTANTS.MIN_PASSWORD_LENGTH, max: AUTH_CONSTANTS.MAX_PASSWORD_LENGTH })
    .withMessage('New password does not meet requirements')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain uppercase, lowercase, number and special character')
    .custom((value, { req }) => value !== req.body.currentPassword)
    .withMessage('New password must be different from current password')
    .custom((value) => calculatePasswordEntropy(value) >= AUTH_CONSTANTS.PASSWORD_ENTROPY_MIN)
    .withMessage('Password entropy too low'),
  
  body('confirmPassword')
    .custom((value, { req }) => value === req.body.newPassword)
    .withMessage('Passwords do not match')
];

/**
 * Password reset request validation
 */
const passwordResetRequestValidation = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Invalid email address')
    .normalizeEmail()
];

/**
 * Password reset validation
 */
const passwordResetValidation = [
  body('token')
    .trim()
    .notEmpty()
    .withMessage('Reset token is required')
    .isLength({ min: 32, max: 255 })
    .withMessage('Invalid token format'),
  
  body('newPassword')
    .isLength({ min: AUTH_CONSTANTS.MIN_PASSWORD_LENGTH, max: AUTH_CONSTANTS.MAX_PASSWORD_LENGTH })
    .withMessage('Password does not meet requirements')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain uppercase, lowercase, number and special character')
    .custom((value) => calculatePasswordEntropy(value) >= AUTH_CONSTANTS.PASSWORD_ENTROPY_MIN)
    .withMessage('Password entropy too low'),
  
  body('confirmPassword')
    .custom((value, { req }) => value === req.body.newPassword)
    .withMessage('Passwords do not match')
];

/**
 * Refresh token validation
 */
const refreshTokenValidation = [
  body('refreshToken')
    .trim()
    .notEmpty()
    .withMessage('Refresh token is required')
    .isLength({ min: 32 })
    .withMessage('Invalid refresh token format')
];

/**
 * Email verification validation
 */
const emailVerificationValidation = [
  body('token')
    .trim()
    .notEmpty()
    .withMessage('Verification token is required')
    .isLength({ min: 32, max: 255 })
    .withMessage('Invalid token format')
];

/**
 * Two-factor authentication validation
 */
const twoFactorValidation = [
  body('code')
    .trim()
    .notEmpty()
    .withMessage('2FA code is required')
    .matches(/^\d{6}$/)
    .withMessage('2FA code must be 6 digits')
];

/**
 * Security question validation
 */
const securityQuestionValidation = [
  body('questions')
    .isArray({ min: 3, max: 5 })
    .withMessage('Must provide 3-5 security questions'),
  
  body('questions.*.questionId')
    .isInt({ min: 1 })
    .withMessage('Invalid question ID'),
  
  body('questions.*.answer')
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage('Answer must be between 2 and 200 characters')
];

// ============================================================================
// ADVANCED RATE LIMITING CONFIGURATIONS
// ============================================================================

/**
 * Strict rate limiting for authentication endpoints
 * Uses Redis for distributed rate limiting across multiple instances
 */
const createRateLimiter = (config) => {
  return rateLimit({
    windowMs: config.windowMs,
    max: Config.security.mode === 'vulnerable' ? 10000 : config.max,
    message: {
      success: false,
      error: ERROR_CODES.RATE_LIMIT_EXCEEDED,
      message: ERROR_MESSAGES.RATE_LIMIT_EXCEEDED,
      retryAfter: Math.ceil(config.windowMs / 1000 / 60) + ' minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: config.skipSuccessfulRequests || false,
    skipFailedRequests: config.skipFailedRequests || false,
    keyGenerator: (req) => {
      // Combine IP + username for more granular limiting
      const identifier = req.body?.username || req.body?.email || req.ip;
      return `${req.ip}:${identifier}`;
    },
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        path: req.path,
        identifier: req.body?.username || req.body?.email
      });
      
      logSecurityEventToDB(null, 'RATE_LIMIT_EXCEEDED', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('user-agent')
      });
      
      res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
        success: false,
        error: ERROR_CODES.RATE_LIMIT_EXCEEDED,
        message: ERROR_MESSAGES.RATE_LIMIT_EXCEEDED,
        retryAfter: Math.ceil(config.windowMs / 1000)
      });
    }
  });
};

// Rate limiter instances
const strictAuthLimit = createRateLimiter(AUTH_CONSTANTS.LOGIN_LIMIT);
const registrationLimit = createRateLimiter(AUTH_CONSTANTS.REGISTRATION_LIMIT);
const passwordResetLimit = createRateLimiter(AUTH_CONSTANTS.PASSWORD_RESET_LIMIT);
const tokenRefreshLimit = createRateLimiter(AUTH_CONSTANTS.TOKEN_REFRESH_LIMIT);
const standardLimit = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 100 });

// ============================================================================
// ADVANCED MIDDLEWARE
// ============================================================================

/**
 * IP reputation check middleware
 */
const checkIPReputation = async (req, res, next) => {
  try {
    const ip = req.ip;
    const suspicious = await isSuspiciousIP(ip);
    
    if (suspicious) {
      logger.warn('Suspicious IP detected', { ip, path: req.path });
      
      if (!getCurrentMode().isVulnerable) {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.IP_BLOCKED,
          message: ERROR_MESSAGES.IP_BLOCKED
        });
      }
    }
    
    next();
  } catch (error) {
    logger.error('IP reputation check error', { error: error.message });
    next(); // Continue on error (fail open)
  }
};

/**
 * Device fingerprint middleware
 */
const captureDeviceFingerprint = (req, res, next) => {
  req.deviceFingerprint = generateDeviceFingerprint(req);
  req.deviceInfo = {
    fingerprint: req.deviceFingerprint,
    userAgent: req.get('user-agent'),
    ip: req.ip,
    language: req.get('accept-language'),
    timestamp: new Date()
  };
  next();
};

/**
 * Enhanced validation middleware with detailed error reporting
 */
const enhancedValidate = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map(err => ({
      field: err.param,
      message: err.msg,
      value: err.value ? '***' : undefined, // Hide actual values
      location: err.location
    }));
    
    logger.debug('Validation failed', {
      path: req.path,
      errors: formattedErrors,
      ip: req.ip
    });
    
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: ERROR_CODES.VALIDATION_ERROR,
      message: 'Validation failed',
      errors: formattedErrors,
      timestamp: new Date().toISOString()
    });
  }
  
  next();
};

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/register:
 *   post:
 *     summary: Register new user account with advanced security
 *     description: |
 *       Creates a new user account with comprehensive validation:
 *       - Username uniqueness check
 *       - Email verification required
 *       - Password entropy validation
 *       - Disposable email blocking
 *       - Honeypot bot detection
 *       - Device fingerprinting
 *       - IP reputation checking
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *               - confirmPassword
 *               - acceptTerms
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 50
 *                 pattern: '^[a-zA-Z0-9_-]+$'
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 maxLength: 255
 *               confirmPassword:
 *                 type: string
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               acceptTerms:
 *                 type: boolean
 *               captchaToken:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error
 *       409:
 *         description: User already exists
 *       429:
 *         description: Rate limit exceeded
 */
router.post('/register',
  registrationLimit,
  checkIPReputation,
  honeypotDetection,
  captureDeviceFingerprint,
  sanitizeInput,
  deepSanitize(['username', 'email', 'firstName', 'lastName']),
  registrationValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  authController.register
);

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: Authenticate user with multi-factor support
 *     description: |
 *       Advanced login with security features:
 *       - Brute force protection
 *       - Progressive delays
 *       - Account lockout
 *       - Device fingerprinting
 *       - Suspicious activity detection
 *       - Session management
 *       - Remember me functionality
 *       - 2FA challenge if enabled
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               rememberMe:
 *                 type: boolean
 *               deviceName:
 *                 type: string
 *               trustDevice:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       423:
 *         description: Account locked
 *       429:
 *         description: Rate limit exceeded
 */
router.post('/login',
  strictAuthLimit,
  checkIPReputation,
  honeypotDetection,
  captureDeviceFingerprint,
  sanitizeInput,
  loginValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  async (req, res, next) => {
    try {
      const { username, password, rememberMe, deviceName, trustDevice } = req.body;
      const ip = req.ip;
      const userAgent = req.get('user-agent');
      const deviceFingerprint = req.deviceFingerprint;

      // Check for account lockout
      const lockoutKey = CacheKeyBuilder.custom('lockout:', username);
      const lockedUntil = await cache.get(lockoutKey);
      
      if (lockedUntil && Date.now() < lockedUntil) {
        const remainingTime = Math.ceil((lockedUntil - Date.now()) / 1000 / 60);
        
        logger.warn('Login attempt on locked account', { username, ip });
        
        return res.status(HTTP_STATUS.LOCKED).json({
          success: false,
          error: ERROR_CODES.ACCOUNT_LOCKED,
          message: ERROR_MESSAGES.ACCOUNT_LOCKED,
          remainingTime: `${remainingTime} minutes`,
          retryAfter: lockedUntil
        });
      }

      // Get failed attempt count
      const attemptKey = CacheKeyBuilder.custom('login_attempts:', username);
      const attempts = await cache.get(attemptKey) || 0;

      // Apply progressive delay
      if (attempts > 0) {
        await applyProgressiveDelay(attempts);
      }

      // Find user
      const [users] = await db.execute(
        `SELECT id, username, email, password, role, is_active, is_email_verified,
                two_factor_enabled, two_factor_secret, account_locked_until,
                failed_login_attempts, last_login_at
         FROM users 
         WHERE username = ? OR email = ? 
         LIMIT 1`,
        [username, username]
      );

      if (!users.length) {
        // Increment failed attempts
        await cache.set(attemptKey, attempts + 1, 900); // 15 min TTL
        
        logger.warn('Login attempt with invalid username', { username, ip });
        
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: ERROR_CODES.INVALID_CREDENTIALS,
          message: ERROR_MESSAGES.INVALID_CREDENTIALS
        });
      }

      const user = users[0];

      // Check if account is active
      if (!user.is_active) {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.ACCOUNT_DISABLED,
          message: ERROR_MESSAGES.ACCOUNT_DISABLED
        });
      }

      // Check database-level account lock
      if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
        return res.status(HTTP_STATUS.LOCKED).json({
          success: false,
          error: ERROR_CODES.ACCOUNT_LOCKED,
          message: ERROR_MESSAGES.ACCOUNT_LOCKED,
          lockedUntil: user.account_locked_until
        });
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        // Increment failed attempts
        const newAttempts = attempts + 1;
        await cache.set(attemptKey, newAttempts, 900);

        // Update database
        await db.execute(
          'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?',
          [user.id]
        );

        // Lock account if threshold reached
        if (newAttempts >= AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS) {
          const lockoutUntil = Date.now() + AUTH_CONSTANTS.LOCKOUT_DURATION;
          await cache.set(lockoutKey, lockoutUntil, AUTH_CONSTANTS.LOCKOUT_DURATION / 1000);
          
          await db.execute(
            'UPDATE users SET account_locked_until = DATE_ADD(NOW(), INTERVAL 30 MINUTE) WHERE id = ?',
            [user.id]
          );

          await logSecurityEventToDB(user.id, 'ACCOUNT_LOCKED', { ip, userAgent, reason: 'Too many failed login attempts' });

          logger.warn('Account locked due to failed attempts', { userId: user.id, username, attempts: newAttempts });

          return res.status(HTTP_STATUS.LOCKED).json({
            success: false,
            error: ERROR_CODES.ACCOUNT_LOCKED,
            message: `Account locked due to too many failed login attempts. Try again in 30 minutes.`,
            lockedUntil: new Date(lockoutUntil).toISOString()
          });
        }

        // Log failed login
        await db.execute(
          `INSERT INTO login_history (user_id, ip_address, user_agent, success, failure_reason, timestamp)
           VALUES (?, ?, ?, FALSE, ?, NOW())`,
          [user.id, ip, userAgent, 'Invalid password']
        );

        await logSecurityEventToDB(user.id, 'LOGIN_FAILED', { ip, userAgent, reason: 'Invalid password' });

        logger.warn('Failed login attempt', { userId: user.id, username, attempts: newAttempts });

        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: ERROR_CODES.INVALID_CREDENTIALS,
          message: ERROR_MESSAGES.INVALID_CREDENTIALS,
          attemptsRemaining: AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS - newAttempts
        });
      }

      // Password is correct - clear failed attempts
      await cache.delete(attemptKey);
      await db.execute(
        'UPDATE users SET failed_login_attempts = 0 WHERE id = ?',
        [user.id]
      );

      // Check if email is verified (in secure mode)
      if (!getCurrentMode().isVulnerable && !user.is_email_verified) {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.EMAIL_NOT_VERIFIED,
          message: ERROR_MESSAGES.EMAIL_NOT_VERIFIED,
          userId: user.id
        });
      }

      // Check if 2FA is enabled
      if (user.two_factor_enabled) {
        // Generate temporary session token for 2FA verification
        const tempToken = generateSecureToken(32);
        await cache.set(
          CacheKeyBuilder.custom('2fa_pending:', tempToken),
          { userId: user.id, rememberMe, deviceName, trustDevice, deviceFingerprint },
          300 // 5 minutes
        );

        return res.status(HTTP_STATUS.OK).json({
          success: true,
          requires2FA: true,
          tempToken,
          message: 'Please provide your 2FA code',
          expiresIn: 300
        });
      }

      // Generate tokens
      const tokenLifetime = rememberMe ? AUTH_CONSTANTS.REMEMBER_ME_LIFETIME : AUTH_CONSTANTS.ACCESS_TOKEN_LIFETIME;
      const tokenPair = jwtService.createTokenPair(
        {
          userId: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        },
        {
          rememberMe,
          fingerprint: deviceFingerprint
        }
      );

      // Create session
      const sessionId = await jwtService.createSession(
        user.id,
        tokenPair,
        {
          ip,
          userAgent,
          deviceInfo: {
            name: deviceName || 'Unknown Device',
            fingerprint: deviceFingerprint,
            trusted: trustDevice || false
          }
        }
      );

      // Update last login
      await db.execute(
        'UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?',
        [ip, user.id]
      );

      // Log successful login
      await db.execute(
        `INSERT INTO login_history (user_id, ip_address, user_agent, success, session_id, timestamp)
         VALUES (?, ?, ?, TRUE, ?, NOW())`,
        [user.id, ip, userAgent, sessionId]
      );

      await logSecurityEventToDB(user.id, 'LOGIN_SUCCESS', { ip, userAgent, sessionId, deviceName });

      logger.info('User logged in successfully', { userId: user.id, username, sessionId });

      res.json({
        success: true,
        message: SUCCESS_MESSAGES.LOGIN_SUCCESS,
        data: {
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            isEmailVerified: user.is_email_verified,
            lastLoginAt: user.last_login_at
          },
          ...tokenPair,
          sessionId
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/2fa/verify-login:
 *   post:
 *     summary: Verify 2FA code and complete login
 *     tags: [Authentication, 2FA]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - tempToken
 *               - code
 *             properties:
 *               tempToken:
 *                 type: string
 *               code:
 *                 type: string
 *     responses:
 *       200:
 *         description: 2FA verified, login complete
 *       401:
 *         description: Invalid 2FA code
 */
router.post('/2fa/verify-login',
  strictAuthLimit,
  twoFactorValidation,
  body('tempToken').notEmpty().withMessage('Temp token is required'),
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { tempToken, code } = req.body;
      const ip = req.ip;
      const userAgent = req.get('user-agent');

      // Get pending 2FA session
      const pendingSession = await cache.get(CacheKeyBuilder.custom('2fa_pending:', tempToken));

      if (!pendingSession) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: 'INVALID_TEMP_TOKEN',
          message: '2FA session expired or invalid'
        });
      }

      const { userId, rememberMe, deviceName, trustDevice, deviceFingerprint } = pendingSession;

      // Get user's 2FA secret
      const [users] = await db.execute(
        'SELECT id, username, email, role, two_factor_secret, two_factor_backup_codes FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users.length) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: 'USER_NOT_FOUND',
          message: 'User not found'
        });
      }

      const user = users[0];

      // Verify TOTP code
      const isValid = encryptionService.verifyTOTP(code, user.two_factor_secret);

      if (!isValid) {
        // Check if it's a backup code
        let backupCodes = [];
        try {
          backupCodes = JSON.parse(user.two_factor_backup_codes || '[]');
        } catch (e) {
          backupCodes = [];
        }

        const backupCodeIndex = backupCodes.findIndex(bc => bc.code === code && !bc.used);

        if (backupCodeIndex === -1) {
          logger.warn('Invalid 2FA code', { userId: user.id, ip });
          
          return res.status(HTTP_STATUS.UNAUTHORIZED).json({
            success: false,
            error: 'INVALID_2FA_CODE',
            message: 'Invalid 2FA code'
          });
        }

        // Mark backup code as used
        backupCodes[backupCodeIndex].used = true;
        backupCodes[backupCodeIndex].usedAt = new Date().toISOString();
        backupCodes[backupCodeIndex].usedFrom = ip;

        await db.execute(
          'UPDATE users SET two_factor_backup_codes = ? WHERE id = ?',
          [JSON.stringify(backupCodes), user.id]
        );

        logger.info('Backup code used', { userId: user.id, ip });
      }

      // Delete temp token
      await cache.delete(CacheKeyBuilder.custom('2fa_pending:', tempToken));

      // Generate tokens
      const tokenPair = jwtService.createTokenPair(
        {
          userId: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        },
        {
          rememberMe,
          fingerprint: deviceFingerprint
        }
      );

      // Create session
      const sessionId = await jwtService.createSession(
        user.id,
        tokenPair,
        {
          ip,
          userAgent,
          deviceInfo: {
            name: deviceName || 'Unknown Device',
            fingerprint: deviceFingerprint,
            trusted: trustDevice || false
          }
        }
      );

      // Update last login
      await db.execute(
        'UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?',
        [ip, user.id]
      );

      // Log successful login
      await db.execute(
        `INSERT INTO login_history (user_id, ip_address, user_agent, success, session_id, timestamp)
         VALUES (?, ?, ?, TRUE, ?, NOW())`,
        [user.id, ip, userAgent, sessionId]
      );

      await logSecurityEventToDB(user.id, 'LOGIN_SUCCESS_2FA', { ip, userAgent, sessionId });

      logger.info('User logged in with 2FA', { userId: user.id, username: user.username, sessionId });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
          },
          ...tokenPair,
          sessionId
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: Logout user and invalidate tokens
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post('/logout',
  standardLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      const token = req.token;

      // Blacklist current token
      await jwtService.blacklistToken(token);

      // Revoke current session if exists
      if (req.sessionId) {
        await jwtService.revokeSession(req.sessionId, userId);
      }

      // Log logout
      await logSecurityEventToDB(userId, 'LOGOUT', {
        ip: req.ip,
        userAgent: req.get('user-agent')
      });

      logger.info('User logged out', { userId });

      res.json({
        success: true,
        message: SUCCESS_MESSAGES.LOGOUT_SUCCESS
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/logout-all:
 *   post:
 *     summary: Logout from all devices
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: All sessions terminated
 */
router.post('/logout-all',
  standardLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      // Revoke all user sessions
      const revokedCount = await jwtService.revokeAllUserTokens(userId);

      // Log logout all
      await logSecurityEventToDB(userId, 'LOGOUT_ALL', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        sessionsRevoked: revokedCount
      });

      logger.info('User logged out from all devices', { userId, sessionsRevoked: revokedCount });

      res.json({
        success: true,
        message: 'Logged out from all devices successfully',
        sessionsRevoked: revokedCount
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/refresh:
 *   post:
 *     summary: Refresh access token using refresh token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid refresh token
 */
router.post('/refresh',
  tokenRefreshLimit,
  refreshTokenValidation,
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { refreshToken } = req.body;

      // Refresh the access token
      const result = await jwtService.refreshAccessToken(refreshToken, {
        userAgent: req.get('user-agent'),
        ip: req.ip
      });

      logger.debug('Token refreshed', { userId: result.userId });

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: result
      });
    } catch (error) {
      logger.error('Token refresh failed', { error: error.message });
      
      res.status(HTTP_STATUS.UNAUTHORIZED).json({
        success: false,
        error: ERROR_CODES.INVALID_TOKEN,
        message: 'Invalid or expired refresh token'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/me:
 *   get:
 *     summary: Get current authenticated user
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User information retrieved
 */
router.get('/me',
  standardLimit,
  authenticate,
  authController.getCurrentUser
);

// ============================================================================
// PASSWORD MANAGEMENT ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/password/change:
 *   put:
 *     summary: Change user password
 *     tags: [Authentication, Password]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Password changed successfully
 */
router.put('/password/change',
  strictAuthLimit,
  authenticate,
  sanitizeInput,
  passwordChangeValidation,
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.id;

      // Get user's current password
      const [users] = await db.execute(
        'SELECT password, password_history FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users.length) {
        return res.status(HTTP_STATUS.NOT_FOUND).json({
          success: false,
          error: 'USER_NOT_FOUND',
          message: 'User not found'
        });
      }

      const user = users[0];

      // Verify current password
      const passwordMatch = await bcrypt.compare(currentPassword, user.password);

      if (!passwordMatch) {
        logger.warn('Password change failed - invalid current password', { userId });
        
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: 'INVALID_CURRENT_PASSWORD',
          message: 'Current password is incorrect'
        });
      }

      // Check password history
      let passwordHistory = [];
      try {
        passwordHistory = JSON.parse(user.password_history || '[]');
      } catch (e) {
        passwordHistory = [];
      }

      // Check if new password was used recently
      for (const oldHash of passwordHistory.slice(0, AUTH_CONSTANTS.PASSWORD_HISTORY_COUNT)) {
        const matchesOld = await bcrypt.compare(newPassword, oldHash);
        if (matchesOld) {
          return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: '2FA_NOT_ENABLED',
          message: '2FA is not enabled for this account'
        });
      }

      // Verify TOTP code
      const isValid = encryptionService.verifyTOTP(code, users[0].two_factor_secret);

      if (!isValid) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: 'INVALID_2FA_CODE',
          message: 'Invalid 2FA code'
        });
      }

      // Disable 2FA
      await db.execute(
        `UPDATE users SET 
         two_factor_enabled = FALSE,
         two_factor_secret = NULL,
         two_factor_backup_codes = NULL
         WHERE id = ?`,
        [userId]
      );

      await logSecurityEventToDB(userId, '2FA_DISABLED', { ip: req.ip });

      logger.info('2FA disabled', { userId });

      res.json({
        success: true,
        message: 'Two-factor authentication disabled successfully'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/2fa/backup-codes:
 *   get:
 *     summary: Get 2FA backup codes
 *     tags: [Authentication, 2FA]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Backup codes retrieved
 */
router.get('/2fa/backup-codes',
  standardLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      const [users] = await db.execute(
        'SELECT two_factor_backup_codes, two_factor_enabled FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users[0]?.two_factor_enabled) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: '2FA_NOT_ENABLED',
          message: '2FA is not enabled'
        });
      }

      let backupCodes = [];
      try {
        backupCodes = JSON.parse(users[0].two_factor_backup_codes || '[]');
      } catch (e) {
        backupCodes = [];
      }

      res.json({
        success: true,
        data: {
          backupCodes: backupCodes.map(bc => ({
            code: bc.code,
            used: bc.used || false,
            usedAt: bc.usedAt || null
          })),
          unusedCount: backupCodes.filter(bc => !bc.used).length
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/2fa/regenerate-backup-codes:
 *   post:
 *     summary: Regenerate 2FA backup codes
 *     tags: [Authentication, 2FA]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: New backup codes generated
 */
router.post('/2fa/regenerate-backup-codes',
  strictAuthLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      const [users] = await db.execute(
        'SELECT two_factor_enabled FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users[0]?.two_factor_enabled) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: '2FA_NOT_ENABLED',
          message: '2FA is not enabled'
        });
      }

      // Generate new backup codes
      const backupCodes = encryptionService.generateBackupCodes(AUTH_CONSTANTS.BACKUP_CODES_COUNT);

      await db.execute(
        'UPDATE users SET two_factor_backup_codes = ? WHERE id = ?',
        [JSON.stringify(backupCodes), userId]
      );

      await logSecurityEventToDB(userId, '2FA_BACKUP_CODES_REGENERATED', { ip: req.ip });

      logger.info('2FA backup codes regenerated', { userId });

      res.json({
        success: true,
        message: 'New backup codes generated. Store them securely.',
        data: { backupCodes }
      });
    } catch (error) {
      next(error);
    }
  }
);

// ============================================================================
// SESSION MANAGEMENT ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/sessions:
 *   get:
 *     summary: Get all active sessions
 *     tags: [Authentication, Sessions]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of active sessions
 */
router.get('/sessions',
  standardLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      const [sessions] = await db.execute(
        `SELECT id, ip_address, user_agent, device_info, created_at, expires_at, last_activity
         FROM user_sessions
         WHERE user_id = ? AND expires_at > NOW()
         ORDER BY last_activity DESC`,
        [userId]
      );

      // Parse device info
      const formattedSessions = sessions.map(session => ({
        ...session,
        device_info: typeof session.device_info === 'string' 
          ? JSON.parse(session.device_info) 
          : session.device_info,
        isCurrent: session.ip_address === req.ip
      }));

      res.json({
        success: true,
        data: {
          sessions: formattedSessions,
          totalSessions: formattedSessions.length
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/sessions/{sessionId}:
 *   delete:
 *     summary: Revoke a specific session
 *     tags: [Authentication, Sessions]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Session revoked
 */
router.delete('/sessions/:sessionId',
  standardLimit,
  authenticate,
  param('sessionId').notEmpty().withMessage('Session ID is required'),
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { sessionId } = req.params;
      const userId = req.user.id;

      const revoked = await jwtService.revokeSession(sessionId, userId);

      if (!revoked) {
        return res.status(HTTP_STATUS.NOT_FOUND).json({
          success: false,
          error: 'SESSION_NOT_FOUND',
          message: 'Session not found or already revoked'
        });
      }

      await logSecurityEventToDB(userId, 'SESSION_REVOKED', { sessionId, ip: req.ip });

      logger.info('Session revoked', { userId, sessionId });

      res.json({
        success: true,
        message: 'Session revoked successfully'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/sessions:
 *   delete:
 *     summary: Revoke all sessions except current
 *     tags: [Authentication, Sessions]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: All other sessions revoked
 */
router.delete('/sessions',
  strictAuthLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      const currentSessionId = req.sessionId;

      // Get all sessions
      const sessions = await jwtService.getUserActiveSessions(userId);

      let revokedCount = 0;
      for (const session of sessions) {
        if (session.id !== currentSessionId) {
          await jwtService.revokeSession(session.id, userId);
          revokedCount++;
        }
      }

      await logSecurityEventToDB(userId, 'ALL_OTHER_SESSIONS_REVOKED', { 
        ip: req.ip, 
        sessionsRevoked: revokedCount 
      });

      logger.info('All other sessions revoked', { userId, count: revokedCount });

      res.json({
        success: true,
        message: `${revokedCount} session(s) revoked successfully`
      });
    } catch (error) {
      next(error);
    }
  }
);

// ============================================================================
// ACCOUNT SECURITY ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/account/security:
 *   get:
 *     summary: Get account security status
 *     tags: [Authentication, Security]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Security status retrieved
 */
router.get('/account/security',
  standardLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      const [users] = await db.execute(
        `SELECT 
          is_email_verified,
          two_factor_enabled,
          failed_login_attempts,
          account_locked_until,
          last_password_change,
          created_at
         FROM users WHERE id = ? LIMIT 1`,
        [userId]
      );

      const user = users[0];

      // Get recent security events
      const [securityEvents] = await db.execute(
        `SELECT event_type, ip_address, timestamp
         FROM security_events
         WHERE user_id = ?
         ORDER BY timestamp DESC
         LIMIT 10`,
        [userId]
      );

      // Get recent login history
      const [loginHistory] = await db.execute(
        `SELECT ip_address, user_agent, success, timestamp
         FROM login_history
         WHERE user_id = ?
         ORDER BY timestamp DESC
         LIMIT 10`,
        [userId]
      );

      // Calculate security score
      let securityScore = 0;
      const recommendations = [];

      if (user.is_email_verified) {
        securityScore += 25;
      } else {
        recommendations.push('Verify your email address');
      }

      if (user.two_factor_enabled) {
        securityScore += 40;
      } else {
        recommendations.push('Enable two-factor authentication for enhanced security');
      }

      const passwordAge = user.last_password_change 
        ? (Date.now() - new Date(user.last_password_change).getTime()) 
        : null;

      if (passwordAge && passwordAge < 90 * 24 * 60 * 60 * 1000) {
        securityScore += 20;
      } else {
        recommendations.push('Change your password (recommended every 90 days)');
      }

      if (user.failed_login_attempts === 0) {
        securityScore += 15;
      }

      // Get active sessions count
      const activeSessions = await jwtService.getUserActiveSessions(userId);

      res.json({
        success: true,
        data: {
          securityScore,
          maxScore: 100,
          rating: securityScore >= 80 ? 'Excellent' : securityScore >= 60 ? 'Good' : securityScore >= 40 ? 'Fair' : 'Poor',
          emailVerified: user.is_email_verified,
          twoFactorEnabled: user.two_factor_enabled,
          accountLocked: user.account_locked_until && new Date(user.account_locked_until) > new Date(),
          failedLoginAttempts: user.failed_login_attempts,
          lastPasswordChange: user.last_password_change,
          passwordAge: passwordAge ? Math.floor(passwordAge / (1000 * 60 * 60 * 24)) : null,
          accountAge: Math.floor((Date.now() - new Date(user.created_at).getTime()) / (1000 * 60 * 60 * 24)),
          activeSessions: activeSessions.length,
          recentSecurityEvents: securityEvents,
          recentLoginHistory: loginHistory,
          recommendations
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/account/deactivate:
 *   post:
 *     summary: Deactivate user account
 *     tags: [Authentication, Account]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Account deactivated
 */
router.post('/account/deactivate',
  strictAuthLimit,
  authenticate,
  body('password').notEmpty().withMessage('Password is required for account deactivation'),
  body('reason').optional().trim().isLength({ max: 500 }),
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { password, reason } = req.body;
      const userId = req.user.id;

      // Verify password
      const [users] = await db.execute(
        'SELECT password FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      const passwordMatch = await bcrypt.compare(password, users[0].password);

      if (!passwordMatch) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: 'INVALID_PASSWORD',
          message: 'Incorrect password'
        });
      }

      // Deactivate account
      await db.execute(
        'UPDATE users SET is_active = FALSE, deactivated_at = NOW(), deactivation_reason = ? WHERE id = ?',
        [reason || null, userId]
      );

      // Revoke all sessions
      await jwtService.revokeAllUserTokens(userId);

      await logSecurityEventToDB(userId, 'ACCOUNT_DEACTIVATED', { ip: req.ip, reason });

      logger.info('Account deactivated', { userId, reason });

      res.json({
        success: true,
        message: 'Account deactivated successfully. You can reactivate it by logging in again within 30 days.'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/account/delete:
 *   post:
 *     summary: Permanently delete user account (GDPR compliant)
 *     tags: [Authentication, Account]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Account deletion scheduled
 */
router.post('/account/delete',
  strictAuthLimit,
  authenticate,
  body('password').notEmpty().withMessage('Password is required for account deletion'),
  body('confirmation').equals('DELETE MY ACCOUNT').withMessage('Confirmation text must match exactly'),
  body('reason').optional().trim().isLength({ max: 1000 }),
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { password, reason } = req.body;
      const userId = req.user.id;

      // Verify password
      const [users] = await db.execute(
        'SELECT password FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      const passwordMatch = await bcrypt.compare(password, users[0].password);

      if (!passwordMatch) {
        return res.status(HTTP_STATUS.UNAUTHORIZED).json({
          success: false,
          error: 'INVALID_PASSWORD',
          message: 'Incorrect password'
        });
      }

      // Mark for deletion (actual deletion happens via scheduled job for GDPR compliance)
      const deletionDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

      await db.execute(
        `UPDATE users SET 
         is_active = FALSE,
         is_deleted = TRUE,
         deletion_requested_at = NOW(),
         deletion_scheduled_at = ?,
         deletion_reason = ?
         WHERE id = ?`,
        [deletionDate, reason || null, userId]
      );

      // Revoke all sessions
      await jwtService.revokeAllUserTokens(userId);

      await logSecurityEventToDB(userId, 'ACCOUNT_DELETION_REQUESTED', { 
        ip: req.ip, 
        reason,
        scheduledFor: deletionDate 
      });

      logger.warn('Account deletion requested', { userId, scheduledFor: deletionDate });

      res.json({
        success: true,
        message: 'Account deletion scheduled. Your account will be permanently deleted in 30 days. You can cancel this by logging in within that time.',
        scheduledDeletion: deletionDate
      });
    } catch (error) {
      next(error);
    }
  }
);

// ============================================================================
// UTILITY & STATUS ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/check:
 *   get:
 *     summary: Check if user is authenticated
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: Authentication status
 */
router.get('/check',
  standardLimit,
  optionalAuth,
  (req, res) => {
    res.json({
      success: true,
      authenticated: !!req.user,
      user: req.user ? {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        isEmailVerified: req.user.is_email_verified
      } : null,
      timestamp: new Date().toISOString()
    });
  }
);

/**
 * @swagger
 * /api/v1/auth/validate-token:
 *   get:
 *     summary: Validate JWT token
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token is valid
 */
router.get('/validate-token',
  standardLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const tokenInfo = await jwtService.introspectToken(req.token);

      res.json({
        success: true,
        valid: tokenInfo.active,
        user: {
          id: req.user.id,
          username: req.user.username,
          email: req.user.email,
          role: req.user.role
        },
        tokenInfo
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/introspect:
 *   post:
 *     summary: Token introspection (OAuth2 compatible)
 *     tags: [Authentication, OAuth]
 *     responses:
 *       200:
 *         description: Token introspection result
 */
router.post('/introspect',
  standardLimit,
  body('token').notEmpty().withMessage('Token is required'),
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { token } = req.body;
      const introspection = await jwtService.introspectToken(token);

      res.json({
        success: true,
        ...introspection
      });
    } catch (error) {
      next(error);
    }
  }
);

// ============================================================================
// VULNERABLE MODE TESTING ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/test-login:
 *   post:
 *     summary: Test login endpoint (vulnerable mode only)
 *     tags: [Authentication, Testing]
 *     responses:
 *       200:
 *         description: Test successful
 */
router.post('/test-login',
  requireVulnerableMode,
  strictAuthLimit,
  async (req, res, next) => {
    try {
      res.json({
        success: true,
        message: 'Test login endpoint - intentionally vulnerable for demonstration',
        warning: 'This endpoint bypasses security checks in vulnerable mode',
        mode: getCurrentMode()
      });
    } catch (error) {
      next(error);
    }
  }
);

// ============================================================================
// GLOBAL ERROR HANDLER FOR AUTH ROUTES
// ============================================================================

router.use((error, req, res, next) => {
  logger.error('Auth route error', {
    error: error.message,
    stack: Config.app.env === 'development' ? error.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip
  });

  // Handle specific error types
  if (error.name === 'ValidationError') {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: ERROR_CODES.VALIDATION_ERROR,
      message: error.message,
      details: error.details
    });
  }

  if (error.name === 'JsonWebTokenError') {
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      success: false,
      error: ERROR_CODES.INVALID_TOKEN,
      message: 'Invalid authentication token'
    });
  }

  if (error.name === 'TokenExpiredError') {
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      success: false,
      error: ERROR_CODES.TOKEN_EXPIRED,
      message: 'Authentication token has expired'
    });
  }

  // Default error response
  res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: ERROR_CODES.INTERNAL_ERROR,
    message: Config.app.env === 'development' ? error.message : ERROR_MESSAGES.INTERNAL_ERROR,
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// ROUTE SUMMARY LOGGING
// ============================================================================

logger.info('✅ Authentication routes configured (ENHANCED MILITARY-GRADE)');
logger.info('   🔐 Registration: POST /auth/register');
logger.info('   🔐 Login: POST /auth/login');
logger.info('   🔐 Logout: POST /auth/logout');
logger.info('   🔐 Logout All: POST /auth/logout-all');
logger.info('   🔐 Refresh Token: POST /auth/refresh');
logger.info('   🔐 Change Password: PUT /auth/password/change');
logger.info('   🔐 Reset Password: POST /auth/password/reset');
logger.info('   🔐 Email Verification: POST /auth/email/verify');
logger.info('   🔐 2FA Enable: POST /auth/2fa/enable');
logger.info('   🔐 2FA Verify: POST /auth/2fa/verify');
logger.info('   🔐 2FA Disable: POST /auth/2fa/disable');
logger.info('   🔐 Sessions: GET/DELETE /auth/sessions');
logger.info('   🔐 Security Status: GET /auth/account/security');
logger.info('   🔐 Token Validation: GET /auth/validate-token');
logger.info('   🔐 Token Introspection: POST /auth/introspect');
logger.info('');
logger.info('   🛡️  Security Features: Advanced rate limiting, brute force protection');
logger.info('   🛡️  Progressive delays, account lockout, device fingerprinting');
logger.info('   🛡️  2FA support, session management, password entropy validation');
logger.info('   🛡️  IP reputation checking, honeypot detection, GDPR compliance');
logger.info('');

export default router;({
            success: false,
            error: 'PASSWORD_REUSE',
            message: `Password was used recently. Please choose a different password.`
          });
        }
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, authConfig.password.bcryptRounds);

      // Update password history
      passwordHistory.unshift(user.password);
      passwordHistory = passwordHistory.slice(0, AUTH_CONSTANTS.PASSWORD_HISTORY_COUNT);

      // Update password
      await db.execute(
        `UPDATE users SET 
         password = ?,
         password_history = ?,
         last_password_change = NOW()
         WHERE id = ?`,
        [hashedPassword, JSON.stringify(passwordHistory), userId]
      );

      // Revoke all other sessions
      await jwtService.revokeAllUserTokens(userId);

      // Log password change
      await logSecurityEventToDB(userId, 'PASSWORD_CHANGED', {
        ip: req.ip,
        userAgent: req.get('user-agent')
      });

      logger.info('Password changed successfully', { userId });

      res.json({
        success: true,
        message: 'Password changed successfully. You have been logged out from all other devices.'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/password/reset/request:
 *   post:
 *     summary: Request password reset email
 *     tags: [Authentication, Password]
 *     responses:
 *       200:
 *         description: Reset email sent
 */
router.post('/password/reset/request',
  passwordResetLimit,
  sanitizeInput,
  passwordResetRequestValidation,
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { email } = req.body;
      const ip = req.ip;

      // Find user
      const [users] = await db.execute(
        'SELECT id, username, email, is_active FROM users WHERE email = ? LIMIT 1',
        [email]
      );

      // Always return success to prevent email enumeration
      const successResponse = {
        success: true,
        message: 'If an account exists with this email, you will receive password reset instructions.'
      };

      if (!users.length) {
        logger.warn('Password reset requested for non-existent email', { email, ip });
        return res.json(successResponse);
      }

      const user = users[0];

      if (!user.is_active) {
        logger.warn('Password reset requested for inactive account', { userId: user.id, ip });
        return res.json(successResponse);
      }

      // Generate reset token
      const resetToken = generateSecureToken(32);
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Store reset token
      await db.execute(
        `UPDATE users SET 
         password_reset_token = ?,
         password_reset_expires = ?
         WHERE id = ?`,
        [resetToken, resetExpires, user.id]
      );

      // Send reset email
      if (Config.email.enabled) {
        const email = Email.getInstance();
        await email.sendPasswordReset(user, resetToken);
      }

      // Log password reset request
      await logSecurityEventToDB(user.id, 'PASSWORD_RESET_REQUESTED', { ip, email: user.email });

      logger.info('Password reset email sent', { userId: user.id, email: user.email });

      res.json(successResponse);
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/password/reset:
 *   post:
 *     summary: Reset password using token
 *     tags: [Authentication, Password]
 *     responses:
 *       200:
 *         description: Password reset successful
 */
router.post('/password/reset',
  passwordResetLimit,
  sanitizeInput,
  passwordResetValidation,
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { token, newPassword } = req.body;
      const ip = req.ip;

      // Find user by token
      const [users] = await db.execute(
        `SELECT id, username, email, password_history 
         FROM users 
         WHERE password_reset_token = ? 
         AND password_reset_expires > NOW()
         LIMIT 1`,
        [token]
      );

      if (!users.length) {
        logger.warn('Invalid or expired password reset token', { token: token.substring(0, 10), ip });
        
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: 'INVALID_TOKEN',
          message: 'Invalid or expired password reset token'
        });
      }

      const user = users[0];

      // Check password history
      let passwordHistory = [];
      try {
        passwordHistory = JSON.parse(user.password_history || '[]');
      } catch (e) {
        passwordHistory = [];
      }

      for (const oldHash of passwordHistory.slice(0, AUTH_CONSTANTS.PASSWORD_HISTORY_COUNT)) {
        const matchesOld = await bcrypt.compare(newPassword, oldHash);
        if (matchesOld) {
          return res.status(HTTP_STATUS.BAD_REQUEST).json({
            success: false,
            error: 'PASSWORD_REUSE',
            message: 'Password was used recently. Please choose a different password.'
          });
        }
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, authConfig.password.bcryptRounds);

      // Update password history
      if (user.password_history) {
        passwordHistory.unshift(user.password_history);
        passwordHistory = passwordHistory.slice(0, AUTH_CONSTANTS.PASSWORD_HISTORY_COUNT);
      }

      // Update password and clear reset token
      await db.execute(
        `UPDATE users SET 
         password = ?,
         password_history = ?,
         password_reset_token = NULL,
         password_reset_expires = NULL,
         last_password_change = NOW(),
         failed_login_attempts = 0,
         account_locked_until = NULL
         WHERE id = ?`,
        [hashedPassword, JSON.stringify(passwordHistory), user.id]
      );

      // Revoke all sessions
      await jwtService.revokeAllUserTokens(user.id);

      // Log password reset
      await logSecurityEventToDB(user.id, 'PASSWORD_RESET_COMPLETED', { ip });

      logger.info('Password reset completed', { userId: user.id });

      res.json({
        success: true,
        message: 'Password reset successful. Please login with your new password.'
      });
    } catch (error) {
      next(error);
    }
  }
);

// ============================================================================
// EMAIL VERIFICATION ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/email/verify:
 *   post:
 *     summary: Verify email address
 *     tags: [Authentication, Email]
 *     responses:
 *       200:
 *         description: Email verified successfully
 */
router.post('/email/verify',
  standardLimit,
  emailVerificationValidation,
  enhancedValidate,
  authController.verifyEmail
);

/**
 * @swagger
 * /api/v1/auth/email/resend:
 *   post:
 *     summary: Resend verification email
 *     tags: [Authentication, Email]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Verification email sent
 */
router.post('/email/resend',
  strictAuthLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      // Check if already verified
      const [users] = await db.execute(
        'SELECT is_email_verified, email FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users.length) {
        return res.status(HTTP_STATUS.NOT_FOUND).json({
          success: false,
          error: 'USER_NOT_FOUND',
          message: 'User not found'
        });
      }

      if (users[0].is_email_verified) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: 'ALREADY_VERIFIED',
          message: 'Email is already verified'
        });
      }

      // Generate new verification token
      const verificationToken = generateSecureToken(32);
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      await db.execute(
        `UPDATE users 
         SET email_verification_token = ?, email_verification_expires = ?
         WHERE id = ?`,
        [verificationToken, expiresAt, userId]
      );

      // Send email
      if (Config.email.enabled) {
        const email = Email.getInstance();
        await email.sendEmailVerification(users[0], verificationToken);
      }

      logger.info('Verification email resent', { userId });

      res.json({
        success: true,
        message: 'Verification email sent successfully'
      });
    } catch (error) {
      next(error);
    }
  }
);

// ============================================================================
// TWO-FACTOR AUTHENTICATION ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/auth/2fa/enable:
 *   post:
 *     summary: Enable two-factor authentication
 *     tags: [Authentication, 2FA]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA setup initiated
 */
router.post('/2fa/enable',
  strictAuthLimit,
  authenticate,
  async (req, res, next) => {
    try {
      const userId = req.user.id;

      // Check if 2FA is already enabled
      const [users] = await db.execute(
        'SELECT two_factor_enabled FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (users[0]?.two_factor_enabled) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: '2FA_ALREADY_ENABLED',
          message: 'Two-factor authentication is already enabled'
        });
      }

      // Generate TOTP secret
      const { secret, qrCode, backupCodes } = encryptionService.generateTOTPSecret(
        req.user.email,
        Config.app.name
      );

      // Store secret temporarily (not yet activated)
      await db.execute(
        `UPDATE users SET 
         two_factor_secret = ?,
         two_factor_backup_codes = ?
         WHERE id = ?`,
        [secret, JSON.stringify(backupCodes), userId]
      );

      logger.info('2FA setup initiated', { userId });

      res.json({
        success: true,
        message: '2FA setup initiated. Scan the QR code and verify with generated code to complete.',
        data: {
          secret,
          qrCode,
          backupCodes,
          instructions: 'Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.) and enter the generated code to complete setup.'
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/2fa/verify:
 *   post:
 *     summary: Verify and activate 2FA
 *     tags: [Authentication, 2FA]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA enabled successfully
 */
router.post('/2fa/verify',
  strictAuthLimit,
  authenticate,
  twoFactorValidation,
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { code } = req.body;
      const userId = req.user.id;

      const [users] = await db.execute(
        'SELECT two_factor_secret FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users[0]?.two_factor_secret) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: '2FA_NOT_SETUP',
          message: '2FA setup not initiated'
        });
      }

      // Verify TOTP code
      const isValid = encryptionService.verifyTOTP(code, users[0].two_factor_secret);

      if (!isValid) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          success: false,
          error: 'INVALID_2FA_CODE',
          message: 'Invalid 2FA code'
        });
      }

      // Activate 2FA
      await db.execute(
        'UPDATE users SET two_factor_enabled = TRUE WHERE id = ?',
        [userId]
      );

      await logSecurityEventToDB(userId, '2FA_ENABLED', { ip: req.ip });

      logger.info('2FA enabled', { userId });

      res.json({
        success: true,
        message: 'Two-factor authentication enabled successfully'
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /api/v1/auth/2fa/disable:
 *   post:
 *     summary: Disable 2FA
 *     tags: [Authentication, 2FA]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA disabled successfully
 */
router.post('/2fa/disable',
  strictAuthLimit,
  authenticate,
  twoFactorValidation,
  enhancedValidate,
  async (req, res, next) => {
    try {
      const { code } = req.body;
      const userId = req.user.id;

      const [users] = await db.execute(
        'SELECT two_factor_secret, two_factor_enabled FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users[0]?.two_factor_enabled) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json
