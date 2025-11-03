/**
 * ============================================================================
 * BRUTE FORCE ATTACK VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Brute Force Demonstration Platform
 * Implements authentication brute force vulnerabilities and protections
 * 
 * @module vulnerabilities/auth/bruteForce
 * @category Security Training - OWASP A07:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates brute force attack vulnerabilities:
 * - Password brute forcing
 * - Username enumeration
 * - Credential stuffing
 * - Dictionary attacks
 * - Timing attacks
 * - Account lockout bypass
 * - Distributed brute force
 * - Reverse brute force
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to account compromise and service disruption
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Classic Brute Force - Try all combinations
 * 2. Dictionary Attack - Try common passwords
 * 3. Credential Stuffing - Use leaked credentials
 * 4. Password Spraying - One password, many users
 * 5. Reverse Brute Force - One user, many passwords
 * 6. Username Enumeration - Discover valid usernames
 * 7. Timing Attack - Exploit response time differences
 * 8. Account Lockout Bypass - Circumvent lockout mechanisms
 * 9. Distributed Attack - Multi-source brute force
 * 10. 2FA Bypass - Brute force OTP codes
 * 
 * @requires bcrypt
 * @requires Database
 * @requires Logger
 */

import bcrypt from 'bcrypt';
import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { 
  HTTP_STATUS, 
  ATTACK_TYPES,
  ATTACK_SEVERITY,
  ERROR_CODES,
  USER_ROLES 
} from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// BRUTE FORCE CONSTANTS
// ============================================================================

const BRUTE_FORCE_CONFIG = {
  // Rate limits
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  ATTEMPT_WINDOW: 5 * 60 * 1000,    // 5 minutes
  
  // Timing
  MIN_RESPONSE_TIME: 100,           // Minimum response time (ms)
  MAX_RESPONSE_TIME: 300,           // Maximum response time (ms)
  CONSTANT_TIME_DELAY: 200,         // Constant time delay (ms)
  
  // Detection thresholds
  RAPID_ATTEMPT_THRESHOLD: 10,      // Attempts per minute
  DISTRIBUTED_THRESHOLD: 50,         // Total attempts across IPs
  USERNAME_ENUM_THRESHOLD: 20,       // Username check attempts
  
  // 2FA
  OTP_LENGTH: 6,
  OTP_MAX_ATTEMPTS: 3,
  OTP_EXPIRY: 5 * 60 * 1000,        // 5 minutes
};

const COMMON_PASSWORDS = [
  '123456', 'password', '123456789', '12345678', '12345',
  '1234567', 'password123', '1234567890', 'qwerty', 'abc123',
  '111111', '123123', 'admin', 'letmein', 'welcome',
  'monkey', '1234', 'dragon', 'master', 'sunshine',
  'princess', 'football', 'qwerty123', 'starwars', 'password1',
];

const COMMON_USERNAMES = [
  'admin', 'administrator', 'root', 'user', 'test',
  'guest', 'demo', 'support', 'info', 'service',
];

// ============================================================================
// BRUTE FORCE ATTACK CLASS
// ============================================================================

export class BruteForceAttack {
  constructor() {
    this.name = 'Brute Force Attack';
    this.category = 'Authentication';
    this.cvssScore = 7.5;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A07:2021';
    this.cweId = 'CWE-307';
    
    this.attackStats = {
      totalAttempts: 0,
      successfulLogins: 0,
      failedLogins: 0,
      accountsLocked: 0,
      usernamesEnumerated: 0,
      credentialStuffingAttempts: 0,
      passwordSprayingAttempts: 0,
      timingAttacks: 0,
      distributedAttacks: 0,
      otpBruteForce: 0,
    };
    
    // Active attack tracking
    this.activeAttacks = new Map();
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: No Rate Limiting or Account Lockout
   * 
   * Attack: Unlimited login attempts
   * 
   * @param {string} username - Username (VULNERABLE)
   * @param {string} password - Password (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Login result
   */
  async vulnerableUnlimitedAttempts(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectBruteForce(username, context);
      
      if (attackDetection.isAttack) {
        await this.logBruteForceAttack({
          type: 'BRUTE_FORCE_UNLIMITED',
          severity: attackDetection.severity,
          payload: { username, ip: context.ip },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 VULNERABLE: NO RATE LIMITING', {
        username,
        ip: context.ip,
        attackDetection,
      });

      // ⚠️ VULNERABLE: No rate limiting or lockout
      const [users] = await db.execute(
        `SELECT id, username, email, password, role, is_active 
         FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        this.attackStats.failedLogins++;
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid username or password',
          metadata: {
            executionTime: Date.now() - startTime,
            attackDetected: attackDetection.isAttack,
          },
        };
      }

      const user = users[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        this.attackStats.failedLogins++;
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid username or password',
          metadata: {
            executionTime: Date.now() - startTime,
          },
        };
      }

      this.attackStats.successfulLogins++;

      return {
        success: true,
        vulnerable: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
        warning: '⚠️ No rate limiting - unlimited brute force attempts possible',
        metadata: {
          executionTime: Date.now() - startTime,
          attackDetected: attackDetection.isAttack,
        },
      };

    } catch (error) {
      return this.handleBruteForceError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Username Enumeration via Response Differences
   * 
   * Attack: Different error messages reveal valid usernames
   * 
   * @param {string} username - Username (VULNERABLE)
   * @param {string} password - Password (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Login result
   */
  async vulnerableUsernameEnumeration(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectBruteForce(username, context);
      
      if (attackDetection.isAttack) {
        await this.logBruteForceAttack({
          type: 'USERNAME_ENUMERATION',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { username, ip: context.ip },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.usernamesEnumerated++;
      }

      logger.warn('🚨 USERNAME ENUMERATION VULNERABILITY', {
        username,
        ip: context.ip,
      });

      // ⚠️ VULNERABLE: Different error messages
      const [users] = await db.execute(
        `SELECT id, username, password, is_active 
         FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        this.attackStats.failedLogins++;
        // ⚠️ VULNERABLE: Reveals username doesn't exist
        return {
          success: false,
          vulnerable: true,
          message: '❌ Username does not exist',
          errorCode: 'USERNAME_NOT_FOUND',
          metadata: {
            executionTime: Date.now() - startTime,
            usernameExists: false,
          },
        };
      }

      const user = users[0];
      
      if (!user.is_active) {
        // ⚠️ VULNERABLE: Reveals account exists but is inactive
        return {
          success: false,
          vulnerable: true,
          message: '❌ Account is inactive',
          errorCode: 'ACCOUNT_INACTIVE',
          metadata: {
            executionTime: Date.now() - startTime,
            usernameExists: true,
            accountStatus: 'inactive',
          },
        };
      }

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        this.attackStats.failedLogins++;
        // ⚠️ VULNERABLE: Reveals username exists, password wrong
        return {
          success: false,
          vulnerable: true,
          message: '❌ Password is incorrect',
          errorCode: 'INVALID_PASSWORD',
          metadata: {
            executionTime: Date.now() - startTime,
            usernameExists: true,
            passwordCorrect: false,
          },
        };
      }

      this.attackStats.successfulLogins++;

      return {
        success: true,
        vulnerable: true,
        user: {
          id: user.id,
          username: user.username,
        },
        warning: '⚠️ Different error messages enable username enumeration',
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleBruteForceError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Timing Attack - Response Time Differences
   * 
   * Attack: Valid usernames take longer to process
   * 
   * @param {string} username - Username (VULNERABLE)
   * @param {string} password - Password (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Login result with timing
   */
  async vulnerableTimingAttack(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.timingAttacks++;

      const attackDetection = this.detectBruteForce(username, context);
      
      if (attackDetection.isAttack) {
        await this.logBruteForceAttack({
          type: 'TIMING_ATTACK',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { username, ip: context.ip },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 TIMING ATTACK VULNERABILITY', {
        username,
        ip: context.ip,
      });

      // ⚠️ VULNERABLE: Timing difference reveals username existence
      const [users] = await db.execute(
        `SELECT id, username, password 
         FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        // Fast response for invalid username (no bcrypt comparison)
        const duration = Date.now() - startTime;
        
        this.attackStats.failedLogins++;
        
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid credentials',
          timing: {
            executionTime: duration,
            hint: 'Fast response - username likely invalid',
          },
          metadata: {
            usernameExists: false,
          },
        };
      }

      const user = users[0];
      
      // ⚠️ VULNERABLE: bcrypt comparison takes time, revealing valid username
      const passwordMatch = await bcrypt.compare(password, user.password);
      const duration = Date.now() - startTime;

      if (!passwordMatch) {
        this.attackStats.failedLogins++;
        
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid credentials',
          timing: {
            executionTime: duration,
            hint: 'Slow response - username valid, password wrong',
          },
          metadata: {
            usernameExists: true,
            passwordCorrect: false,
          },
        };
      }

      this.attackStats.successfulLogins++;

      return {
        success: true,
        vulnerable: true,
        user: {
          id: user.id,
          username: user.username,
        },
        warning: '⚠️ Timing differences enable username enumeration',
        timing: {
          executionTime: duration,
        },
      };

    } catch (error) {
      return this.handleBruteForceError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Weak Account Lockout Implementation
   * 
   * Attack: Easy to bypass or causes DoS
   * 
   * @param {string} username - Username (VULNERABLE)
   * @param {string} password - Password (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Login result
   */
  async vulnerableWeakLockout(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectBruteForce(username, context);
      
      if (attackDetection.isAttack) {
        await this.logBruteForceAttack({
          type: 'WEAK_LOCKOUT_BYPASS',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { username, ip: context.ip },
          patterns: attackDetection.patterns,
          context,
        });
      }

      // ⚠️ VULNERABLE: Check lockout based only on username (not IP)
      const lockoutKey = `lockout:${username}`;
      const failedAttempts = await cache.get(lockoutKey) || 0;

      // ⚠️ VULNERABLE: Predictable lockout duration
      if (failedAttempts >= BRUTE_FORCE_CONFIG.MAX_LOGIN_ATTEMPTS) {
        this.attackStats.accountsLocked++;
        
        logger.warn('🚨 WEAK LOCKOUT - Account locked', {
          username,
          failedAttempts,
          lockoutDuration: BRUTE_FORCE_CONFIG.LOCKOUT_DURATION,
        });

        return {
          success: false,
          vulnerable: true,
          locked: true,
          message: `Account locked after ${failedAttempts} failed attempts`,
          lockoutInfo: {
            attempts: failedAttempts,
            // ⚠️ VULNERABLE: Reveals exact lockout duration
            remainingTime: BRUTE_FORCE_CONFIG.LOCKOUT_DURATION,
            // ⚠️ VULNERABLE: Reveals exact reset time
            unlockAt: new Date(Date.now() + BRUTE_FORCE_CONFIG.LOCKOUT_DURATION),
          },
          warning: '⚠️ Weak lockout: No IP-based protection, predictable timing',
          metadata: {
            executionTime: Date.now() - startTime,
          },
        };
      }

      // Attempt login
      const [users] = await db.execute(
        `SELECT id, username, password 
         FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0 || !(await bcrypt.compare(password, users[0].password))) {
        // ⚠️ VULNERABLE: Increment without IP check (attacker can use multiple IPs)
        await cache.set(lockoutKey, failedAttempts + 1, BRUTE_FORCE_CONFIG.LOCKOUT_DURATION);
        
        this.attackStats.failedLogins++;

        return {
          success: false,
          vulnerable: true,
          message: 'Invalid credentials',
          attemptsRemaining: BRUTE_FORCE_CONFIG.MAX_LOGIN_ATTEMPTS - (failedAttempts + 1),
          metadata: {
            executionTime: Date.now() - startTime,
            failedAttempts: failedAttempts + 1,
          },
        };
      }

      // Reset attempts on successful login
      await cache.delete(lockoutKey);
      this.attackStats.successfulLogins++;

      return {
        success: true,
        vulnerable: true,
        user: {
          id: users[0].id,
          username: users[0].username,
        },
        warning: '⚠️ Lockout can be bypassed with distributed attack',
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleBruteForceError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Dictionary Attack Simulation
   * 
   * Attack: Try common passwords against username
   * 
   * @param {string} username - Target username
   * @param {Array<string>} customDictionary - Optional custom password list
   * @param {object} context - Request context
   * @returns {Promise<object>} Attack results
   */
  async vulnerableDictionaryAttack(username, customDictionary = null, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const dictionary = customDictionary || COMMON_PASSWORDS;
      const results = {
        username,
        totalPasswords: dictionary.length,
        attemptedPasswords: 0,
        successfulPassword: null,
        timeTaken: 0,
      };

      logger.warn('🚨 DICTIONARY ATTACK SIMULATION', {
        username,
        dictionarySize: dictionary.length,
        ip: context.ip,
      });

      // Get user once
      const [users] = await db.execute(
        `SELECT id, username, password 
         FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Username not found',
          results,
          metadata: {
            executionTime: Date.now() - startTime,
          },
        };
      }

      const user = users[0];

      // Try each password
      for (const password of dictionary) {
        results.attemptedPasswords++;
        
        const match = await bcrypt.compare(password, user.password);
        
        if (match) {
          results.successfulPassword = password;
          this.attackStats.successfulLogins++;
          break;
        }
        
        this.attackStats.failedLogins++;
      }

      results.timeTaken = Date.now() - startTime;

      await this.logBruteForceAttack({
        type: 'DICTIONARY_ATTACK',
        severity: ATTACK_SEVERITY.HIGH,
        payload: { 
          username, 
          dictionarySize: dictionary.length,
          success: !!results.successfulPassword,
        },
        patterns: [],
        context,
      });

      return {
        success: !!results.successfulPassword,
        vulnerable: true,
        results,
        warning: '⚠️ No rate limiting allows dictionary attacks',
        metadata: {
          executionTime: results.timeTaken,
          attackType: 'DICTIONARY',
        },
      };

    } catch (error) {
      return this.handleBruteForceError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Password Spraying Attack
   * 
   * Attack: One password against many usernames
   * 
   * @param {string} password - Common password to try
   * @param {Array<string>} usernames - List of usernames
   * @param {object} context - Request context
   * @returns {Promise<object>} Attack results
   */
  async vulnerablePasswordSpraying(password, usernames = null, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.passwordSprayingAttempts++;

      const targetUsernames = usernames || COMMON_USERNAMES;
      const results = {
        password: '***',
        totalUsernames: targetUsernames.length,
        successfulLogins: [],
        failedLogins: 0,
      };

      logger.warn('🚨 PASSWORD SPRAYING ATTACK', {
        usernameCount: targetUsernames.length,
        ip: context.ip,
      });

      for (const username of targetUsernames) {
        const [users] = await db.execute(
          `SELECT id, username, password 
           FROM ${tables.USERS} 
           WHERE username = ? AND deleted_at IS NULL`,
          [username]
        );

        if (users.length === 0) {
          results.failedLogins++;
          continue;
        }

        const user = users[0];
        const match = await bcrypt.compare(password, user.password);

        if (match) {
          results.successfulLogins.push({
            username: user.username,
            userId: user.id,
          });
          this.attackStats.successfulLogins++;
        } else {
          results.failedLogins++;
          this.attackStats.failedLogins++;
        }
      }

      await this.logBruteForceAttack({
        type: 'PASSWORD_SPRAYING',
        severity: ATTACK_SEVERITY.HIGH,
        payload: { 
          usernameCount: targetUsernames.length,
          successfulLogins: results.successfulLogins.length,
        },
        patterns: [],
        context,
      });

      return {
        success: results.successfulLogins.length > 0,
        vulnerable: true,
        results,
        warning: '⚠️ Password spraying bypasses per-account rate limiting',
        metadata: {
          executionTime: Date.now() - startTime,
          attackType: 'PASSWORD_SPRAYING',
        },
      };

    } catch (error) {
      return this.handleBruteForceError(error, 'multiple', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: 2FA OTP Brute Force
   * 
   * Attack: Brute force 6-digit OTP codes
   * 
   * @param {string} username - Username
   * @param {string} otpAttempt - OTP code attempt
   * @param {object} context - Request context
   * @returns {Promise<object>} Verification result
   */
  async vulnerableOTPBruteForce(username, otpAttempt, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.otpBruteForce++;

      const attackDetection = this.detectBruteForce(username, context);
      
      if (attackDetection.isAttack) {
        await this.logBruteForceAttack({
          type: 'OTP_BRUTE_FORCE',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { username, ip: context.ip },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 OTP BRUTE FORCE ATTEMPT', {
        username,
        otpAttempt,
        ip: context.ip,
      });

      // ⚠️ VULNERABLE: No rate limiting on OTP attempts
      // Get stored OTP (simulated)
      const otpKey = `otp:${username}`;
      const storedOTP = await cache.get(otpKey);

      if (!storedOTP) {
        return {
          success: false,
          vulnerable: true,
          message: 'No OTP found or expired',
          metadata: {
            executionTime: Date.now() - startTime,
          },
        };
      }

      // ⚠️ VULNERABLE: Simple string comparison (timing attack possible)
      if (otpAttempt === storedOTP) {
        await cache.delete(otpKey);
        this.attackStats.successfulLogins++;

        return {
          success: true,
          vulnerable: true,
          message: 'OTP verified',
          warning: '⚠️ No rate limiting on OTP - 6 digits = 1M combinations',
          metadata: {
            executionTime: Date.now() - startTime,
          },
        };
      }

      this.attackStats.failedLogins++;

      return {
        success: false,
        vulnerable: true,
        message: 'Invalid OTP',
        metadata: {
          executionTime: Date.now() - startTime,
          attemptsRemaining: 'unlimited',
        },
      };

    } catch (error) {
      return this.handleBruteForceError(error, username, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Rate Limited Login with Account Lockout
   * 
   * @param {string} username - Username (SAFE)
   * @param {string} password - Password (SAFE)
   * @param {string} ip - Client IP address
   * @returns {Promise<object>} Login result
   */
  async secureRateLimitedLogin(username, password, ip) {
    const startTime = Date.now();

    try {
      // ✅ Validate input
      if (typeof username !== 'string' || username.length > 50) {
        throw new AppError('Invalid username', HTTP_STATUS.BAD_REQUEST);
      }

      if (typeof password !== 'string' || password.length > 100) {
        throw new AppError('Invalid password', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Check IP-based rate limit
      const ipKey = `login_attempts:ip:${ip}`;
      const ipAttempts = await cache.get(ipKey) || 0;

      if (ipAttempts >= BRUTE_FORCE_CONFIG.RAPID_ATTEMPT_THRESHOLD) {
        logger.warn('IP rate limit exceeded', { ip, attempts: ipAttempts });
        throw new AppError('Too many login attempts. Please try again later.', HTTP_STATUS.TOO_MANY_REQUESTS);
      }

      // ✅ Check account-based rate limit
      const accountKey = `login_attempts:account:${username}`;
      const accountAttempts = await cache.get(accountKey) || 0;

      if (accountAttempts >= BRUTE_FORCE_CONFIG.MAX_LOGIN_ATTEMPTS) {
        const lockoutKey = `account_locked:${username}`;
        const lockedUntil = await cache.get(lockoutKey);

        if (lockedUntil && Date.now() < lockedUntil) {
          logger.warn('Account locked', { username, ip });
          throw new AppError('Account temporarily locked. Please try again later.', HTTP_STATUS.FORBIDDEN);
        }
      }

      // ✅ Always perform bcrypt comparison (constant time)
      const [users] = await db.execute(
        `SELECT id, username, email, password, role, is_active 
         FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      let passwordMatch = false;
      let user = null;

      if (users.length > 0) {
        user = users[0];
        passwordMatch = await bcrypt.compare(password, user.password);
      } else {
        // ✅ Perform dummy bcrypt to prevent timing attacks
        await bcrypt.compare(password, '$2b$10$dummy.hash.to.prevent.timing.attacks.here');
      }

      // ✅ Add constant delay to prevent timing attacks
      const elapsed = Date.now() - startTime;
      if (elapsed < BRUTE_FORCE_CONFIG.CONSTANT_TIME_DELAY) {
        await this.delay(BRUTE_FORCE_CONFIG.CONSTANT_TIME_DELAY - elapsed);
      }

      if (!user || !passwordMatch || !user.is_active) {
        // ✅ Increment rate limit counters
        await cache.increment(ipKey, 1);
        await cache.expire(ipKey, BRUTE_FORCE_CONFIG.ATTEMPT_WINDOW);
        
        await cache.increment(accountKey, 1);
        await cache.expire(accountKey, BRUTE_FORCE_CONFIG.ATTEMPT_WINDOW);

        // ✅ Lock account if threshold exceeded
        if (accountAttempts + 1 >= BRUTE_FORCE_CONFIG.MAX_LOGIN_ATTEMPTS) {
          const lockoutKey = `account_locked:${username}`;
          await cache.set(lockoutKey, Date.now() + BRUTE_FORCE_CONFIG.LOCKOUT_DURATION, BRUTE_FORCE_CONFIG.LOCKOUT_DURATION);
          
          logger.warn('Account locked after failed attempts', { username, ip, attempts: accountAttempts + 1 });
        }

        // ✅ Generic error message (no username enumeration)
        throw new AppError('Invalid credentials', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Clear rate limit counters on successful login
      await cache.delete(ipKey);
      await cache.delete(accountKey);

      return {
        success: true,
        vulnerable: false,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_RATE_LIMITED',
        },
      };

    } catch (error) {
      logger.error('Secure login error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: OTP Verification with Rate Limiting
   */
  async secureOTPVerification(username, otpAttempt, ip) {
    const startTime = Date.now();

    try {
      // ✅ Rate limit OTP attempts
      const otpAttemptsKey = `otp_attempts:${username}:${ip}`;
      const attempts = await cache.get(otpAttemptsKey) || 0;

      if (attempts >= BRUTE_FORCE_CONFIG.OTP_MAX_ATTEMPTS) {
        throw new AppError('Too many OTP attempts. Please request a new code.', HTTP_STATUS.TOO_MANY_REQUESTS);
      }

      // ✅ Get stored OTP
      const otpKey = `otp:${username}`;
      const storedOTP = await cache.get(otpKey);

      if (!storedOTP) {
        throw new AppError('OTP expired or not found', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Constant-time comparison
      const match = this.constantTimeCompare(otpAttempt, storedOTP);

      if (!match) {
        // ✅ Increment attempts
        await cache.increment(otpAttemptsKey, 1);
        await cache.expire(otpAttemptsKey, BRUTE_FORCE_CONFIG.OTP_EXPIRY);

        throw new AppError('Invalid OTP', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Clear OTP and attempts
      await cache.delete(otpKey);
      await cache.delete(otpAttemptsKey);

      return {
        success: true,
        vulnerable: false,
        message: 'OTP verified successfully',
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_OTP',
        },
      };

    } catch (error) {
      logger.error('Secure OTP verification error', { error: error.message });
      throw error;
    }
  }

  /**
   * Constant-time string comparison
   */
  constantTimeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  /**
   * Delay helper
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect brute force attack patterns
   */
  detectBruteForce(username, context) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;

    const ip = context.ip || 'unknown';
    const userAgent = context.userAgent || '';

    // Track attempts per IP
    const ipKey = `bf_detection:ip:${ip}`;
    const ipAttempts = this.activeAttacks.get(ipKey) || { count: 0, firstAttempt: Date.now() };
    ipAttempts.count++;
    this.activeAttacks.set(ipKey, ipAttempts);

    // Check rapid attempts from single IP
    const timeSinceFirst = Date.now() - ipAttempts.firstAttempt;
    const attemptsPerMinute = (ipAttempts.count / (timeSinceFirst / 60000));

    if (attemptsPerMinute > BRUTE_FORCE_CONFIG.RAPID_ATTEMPT_THRESHOLD) {
      detectedPatterns.push({
        category: 'RAPID_ATTEMPTS',
        rate: attemptsPerMinute.toFixed(2) + ' attempts/min',
        matched: true,
      });
      score += 20;
      severity = ATTACK_SEVERITY.HIGH;
    }

    // Track attempts per username
    const usernameKey = `bf_detection:user:${username}`;
    const usernameAttempts = this.activeAttacks.get(usernameKey) || { count: 0, ips: new Set() };
    usernameAttempts.count++;
    usernameAttempts.ips.add(ip);
    this.activeAttacks.set(usernameKey, usernameAttempts);

    // Check distributed attack (multiple IPs, same username)
    if (usernameAttempts.ips.size > 3) {
      detectedPatterns.push({
        category: 'DISTRIBUTED_ATTACK',
        uniqueIPs: usernameAttempts.ips.size,
        matched: true,
      });
      score += 25;
      severity = ATTACK_SEVERITY.CRITICAL;
    }

    // Check for automated tools in User-Agent
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /curl/i, /wget/i,
      /python/i, /ruby/i, /perl/i, /java/i, /go-http/i,
    ];

    if (botPatterns.some(pattern => pattern.test(userAgent))) {
      detectedPatterns.push({
        category: 'AUTOMATED_TOOL',
        userAgent: userAgent.substring(0, 100),
        matched: true,
      });
      score += 15;
    }

    // Check for common test usernames
    if (COMMON_USERNAMES.includes(username.toLowerCase())) {
      detectedPatterns.push({
        category: 'COMMON_USERNAME',
        username,
        matched: true,
      });
      score += 10;
    }

    if (score >= 30) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 15) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 5) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      ipAttempts: ipAttempts.count,
      usernameAttempts: usernameAttempts.count,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log brute force attack
   */
  async logBruteForceAttack(attackData) {
    try {
      const {
        type,
        severity,
        payload,
        patterns,
        context,
        timestamp = new Date(),
      } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          type,
          severity,
          JSON.stringify(payload),
          JSON.stringify(patterns),
          context.ip || null,
          context.userAgent || null,
          context.userId || null,
          context.endpoint || null,
          timestamp,
        ]
      );

      logger.attack('Brute Force Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context,
      });

    } catch (error) {
      logger.error('Failed to log brute force attack', { error: error.message });
    }
  }

  /**
   * Handle brute force errors
   */
  handleBruteForceError(error, username, duration) {
    logger.error('Brute Force Attack Error', {
      message: error.message,
      username,
      duration,
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
      },
      metadata: {
        executionTime: duration,
        errorType: 'BRUTE_FORCE_ERROR',
      },
    };
  }

  // ==========================================================================
  // UTILITY & REPORTING
  // ==========================================================================

  /**
   * Get attack statistics
   */
  getStatistics() {
    return {
      ...this.attackStats,
      successRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulLogins / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
        : '0%',
      activeAttacks: this.activeAttacks.size,
    };
  }

  /**
   * Get vulnerability information
   */
  getVulnerabilityInfo() {
    return {
      name: this.name,
      category: this.category,
      cvssScore: this.cvssScore,
      severity: this.severity,
      owaspId: this.owaspId,
      cweId: this.cweId,
      description: 'Brute force attacks attempt to guess credentials through systematic trial of many passwords or usernames',
      impact: [
        'Account compromise',
        'Unauthorized access',
        'Data breach',
        'Identity theft',
        'Service disruption (DoS)',
        'Credential database exposure',
        'Lateral movement',
        'Privilege escalation',
      ],
      attackTypes: [
        'Classic Brute Force - Try all combinations',
        'Dictionary Attack - Use common passwords',
        'Credential Stuffing - Use leaked credentials',
        'Password Spraying - One password, many users',
        'Reverse Brute Force - One user, many passwords',
        'Username Enumeration - Discover valid accounts',
        'Timing Attack - Exploit response differences',
        'OTP Brute Force - Guess 2FA codes',
        'Distributed Attack - Multiple IP sources',
      ],
      vulnerabilities: [
        'No rate limiting',
        'No account lockout',
        'Username enumeration via error messages',
        'Username enumeration via timing',
        'Weak lockout implementation',
        'Predictable lockout duration',
        'No CAPTCHA',
        'No multi-factor authentication',
        'Weak password policy',
      ],
      remediation: [
        'Implement progressive rate limiting',
        'Use account lockout after N failed attempts',
        'Generic error messages (no enumeration)',
        'Constant-time password comparison',
        'CAPTCHA after failed attempts',
        'Multi-factor authentication (MFA/2FA)',
        'Strong password policy',
        'Monitor for suspicious patterns',
        'IP-based rate limiting',
        'Distributed attack detection',
        'Security questions or challenges',
        'Email/SMS notifications on failed attempts',
        'Honeypot accounts',
        'Device fingerprinting',
      ],
      references: [
        'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
        'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
        'CWE-307: Improper Restriction of Excessive Authentication Attempts',
        'NIST SP 800-63B: Digital Identity Guidelines',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulLogins: 0,
      failedLogins: 0,
      accountsLocked: 0,
      usernamesEnumerated: 0,
      credentialStuffingAttempts: 0,
      passwordSprayingAttempts: 0,
      timingAttacks: 0,
      distributedAttacks: 0,
      otpBruteForce: 0,
    };
    this.activeAttacks.clear();
  }

  /**
   * Clear active attack tracking (for testing)
   */
  clearActiveAttacks() {
    this.activeAttacks.clear();
    logger.info('Active attack tracking cleared');
  }

  /**
   * Get common password list
   */
  getCommonPasswords() {
    return COMMON_PASSWORDS;
  }

  /**
   * Get common username list
   */
  getCommonUsernames() {
    return COMMON_USERNAMES;
  }

  /**
   * Generate attack simulation report
   */
  async generateAttackReport(startDate, endDate) {
    try {
      const [attackLogs] = await db.execute(
        `SELECT 
          attack_type,
          severity,
          COUNT(*) as count,
          COUNT(DISTINCT ip_address) as unique_ips,
          COUNT(DISTINCT JSON_EXTRACT(payload, '$.username')) as unique_usernames
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%BRUTE%' OR attack_type LIKE '%OTP%'
         AND created_at BETWEEN ? AND ?
         GROUP BY attack_type, severity
         ORDER BY count DESC`,
        [startDate, endDate]
      );

      return {
        period: { start: startDate, end: endDate },
        attacks: attackLogs,
        statistics: this.getStatistics(),
        generatedAt: new Date().toISOString(),
      };

    } catch (error) {
      logger.error('Failed to generate attack report', { error: error.message });
      throw error;
    }
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getBruteForceAttack = () => {
  if (!instance) {
    instance = new BruteForceAttack();
  }
  return instance;
};

export const createBruteForceHandler = (method) => {
  return async (req, res, next) => {
    try {
      const attack = getBruteForceAttack();
      
      if (Config.security.mode !== 'vulnerable') {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.FORBIDDEN,
          message: 'This endpoint is only available in vulnerable mode',
        });
      }

      const context = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.user?.id,
        endpoint: req.path,
      };

      const params = { ...req.body, ...req.query, ...req.params };
      const result = await attack[method](...Object.values(params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  BruteForceAttack,
  getBruteForceAttack,
  createBruteForceHandler,
};
