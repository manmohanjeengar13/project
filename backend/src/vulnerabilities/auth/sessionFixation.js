/**
 * ============================================================================
 * SESSION FIXATION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Session Fixation Demonstration Platform
 * Implements session management vulnerabilities
 * 
 * @module vulnerabilities/auth/sessionFixation
 * @category Security Training - OWASP A07:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates session fixation and management vulnerabilities:
 * - Session Fixation - Attacker sets victim's session ID
 * - Session Hijacking - Session ID theft
 * - Session Prediction - Predictable session IDs
 * - Cross-Site Session Transfer
 * - Concurrent Session Issues
 * - Session Timeout Problems
 * - Insecure Session Storage
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to complete account takeover
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Classic Session Fixation - Set session before login
 * 2. Session Hijacking - Steal active session
 * 3. Predictable Session IDs - Guess valid sessions
 * 4. Session Side-jacking - Steal via network sniffing
 * 5. Cross-Site Session Transfer - Share sessions across domains
 * 6. Session Donation - Transfer authenticated session
 * 7. Concurrent Session Abuse - Multiple active sessions
 * 8. Session Token in URL - Expose via Referer header
 * 
 * @requires uuid
 * @requires Database
 * @requires Logger
 */

import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { 
  HTTP_STATUS, 
  ATTACK_TYPES,
  ATTACK_SEVERITY,
  ERROR_CODES 
} from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// SESSION FIXATION CONSTANTS
// ============================================================================

const SESSION_CONFIG = {
  // Session settings
  DEFAULT_EXPIRY: 30 * 60 * 1000,     // 30 minutes
  REMEMBER_ME_EXPIRY: 30 * 24 * 60 * 60 * 1000, // 30 days
  IDLE_TIMEOUT: 15 * 60 * 1000,       // 15 minutes
  ABSOLUTE_TIMEOUT: 8 * 60 * 60 * 1000, // 8 hours
  
  // Security settings
  REGENERATE_ON_LOGIN: true,
  REGENERATE_ON_PRIVILEGE_CHANGE: true,
  MAX_CONCURRENT_SESSIONS: 5,
  SESSION_TOKEN_LENGTH: 32,
  
  // Cookie settings
  COOKIE_NAME: 'session_id',
  COOKIE_SECURE: false, // Should be true in production
  COOKIE_HTTP_ONLY: true,
  COOKIE_SAME_SITE: 'lax',
};

// ============================================================================
// SESSION FIXATION CLASS
// ============================================================================

export class SessionFixation {
  constructor() {
    this.name = 'Session Fixation';
    this.category = 'Authentication';
    this.cvssScore = 8.1;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A07:2021';
    this.cweId = 'CWE-384';
    
    this.attackStats = {
      totalAttempts: 0,
      sessionFixations: 0,
      sessionHijackings: 0,
      predictedSessions: 0,
      concurrentSessionAbuse: 0,
      crossSiteTransfers: 0,
      successfulTakeovers: 0,
    };
    
    // Weak session counter for predictable IDs
    this.sessionCounter = 1000;
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Session Not Regenerated on Login
   * 
   * Attack: Attacker sets session ID, victim logs in with that ID
   * 
   * @param {string} username - Username
   * @param {string} password - Password
   * @param {string} existingSessionId - Pre-set session ID (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Login result with session
   */
  async vulnerableNoRegeneration(username, password, existingSessionId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.sessionFixations++;

      const attackDetection = this.detectSessionFixation(existingSessionId, context);
      
      if (attackDetection.isAttack) {
        await this.logSessionAttack({
          type: 'SESSION_FIXATION',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { username, sessionId: existingSessionId },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 SESSION FIXATION: No Regeneration', {
        username,
        existingSessionId,
        ip: context.ip,
      });

      // Authenticate user
      const [users] = await db.execute(
        `SELECT id, username, email, role FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid credentials',
        };
      }

      const user = users[0];

      // ⚠️ VULNERABLE: Use existing session ID instead of regenerating
      const sessionId = existingSessionId || this.generateWeakSessionId();

      // Store session
      await this.storeSession(sessionId, {
        userId: user.id,
        username: user.username,
        role: user.role,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: context.ip,
        userAgent: context.userAgent,
      });

      if (attackDetection.isAttack) {
        this.attackStats.successfulTakeovers++;
      }

      return {
        success: true,
        vulnerable: true,
        sessionId,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        warning: '⚠️ Session not regenerated - vulnerable to fixation attack',
        metadata: {
          executionTime: Date.now() - startTime,
          attackDetected: attackDetection.isAttack,
        },
      };

    } catch (error) {
      return this.handleSessionError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Predictable Session IDs
   * 
   * Attack: Guess valid session IDs through pattern analysis
   * 
   * @param {string} username - Username
   * @param {string} password - Password
   * @param {object} context - Request context
   * @returns {Promise<object>} Login result with predictable session
   */
  async vulnerablePredictableSessions(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.predictedSessions++;

      logger.warn('🚨 PREDICTABLE SESSION ID GENERATION', {
        username,
        sessionCounter: this.sessionCounter,
      });

      // Authenticate user
      const [users] = await db.execute(
        `SELECT id, username, email, role FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid credentials',
        };
      }

      const user = users[0];

      // ⚠️ VULNERABLE: Sequential/predictable session ID
      const sessionId = `sess_${this.sessionCounter++}_${Date.now()}`;

      await this.storeSession(sessionId, {
        userId: user.id,
        username: user.username,
        role: user.role,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: context.ip,
        userAgent: context.userAgent,
      });

      return {
        success: true,
        vulnerable: true,
        sessionId,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        warning: '⚠️ Predictable session ID - can be guessed by attackers',
        pattern: {
          format: 'sess_{counter}_{timestamp}',
          nextPredicted: `sess_${this.sessionCounter}_${Date.now()}`,
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleSessionError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Session Hijacking via Token Theft
   * 
   * Attack: Use stolen session token
   * 
   * @param {string} stolenSessionId - Stolen session ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Session validation result
   */
  async vulnerableSessionHijacking(stolenSessionId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.sessionHijackings++;

      logger.warn('🚨 SESSION HIJACKING ATTEMPT', {
        sessionId: stolenSessionId,
        ip: context.ip,
      });

      // ⚠️ VULNERABLE: No IP binding or device fingerprinting
      const session = await this.getSession(stolenSessionId);

      if (!session) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid session',
        };
      }

      // ⚠️ VULNERABLE: Accept session from any IP
      const originalIP = session.ip;
      const currentIP = context.ip;

      logger.warn('Session used from different IP', {
        originalIP,
        currentIP,
        sessionId: stolenSessionId,
      });

      await this.logSessionAttack({
        type: 'SESSION_HIJACKING',
        severity: ATTACK_SEVERITY.CRITICAL,
        payload: { 
          sessionId: stolenSessionId,
          originalIP,
          currentIP,
          userId: session.userId,
        },
        patterns: [],
        context,
      });

      this.attackStats.successfulTakeovers++;

      // Update last activity
      session.lastActivity = Date.now();
      session.hijacked = true;
      session.hijackedIP = currentIP;
      await this.storeSession(stolenSessionId, session);

      return {
        success: true,
        vulnerable: true,
        session,
        warning: '⚠️ Session hijacked - no IP validation',
        hijackingInfo: {
          originalIP,
          hijackerIP: currentIP,
          ipMismatch: originalIP !== currentIP,
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleSessionError(error, stolenSessionId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Unlimited Concurrent Sessions
   * 
   * Attack: Create many sessions for reconnaissance or persistence
   * 
   * @param {string} username - Username
   * @param {string} password - Password
   * @param {object} context - Request context
   * @returns {Promise<object>} New session info
   */
  async vulnerableConcurrentSessions(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.concurrentSessionAbuse++;

      // Authenticate
      const [users] = await db.execute(
        `SELECT id, username, email, role FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid credentials',
        };
      }

      const user = users[0];

      // ⚠️ VULNERABLE: No limit on concurrent sessions
      const sessionId = uuidv4();

      await this.storeSession(sessionId, {
        userId: user.id,
        username: user.username,
        role: user.role,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: context.ip,
        userAgent: context.userAgent,
      });

      // Count user's active sessions
      const activeSessions = await this.getUserActiveSessions(user.id);

      logger.warn('🚨 CONCURRENT SESSION ABUSE', {
        username,
        activeSessionCount: activeSessions.length,
        newSessionId: sessionId,
      });

      if (activeSessions.length > 10) {
        await this.logSessionAttack({
          type: 'CONCURRENT_SESSION_ABUSE',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { 
            username,
            sessionCount: activeSessions.length,
          },
          patterns: [],
          context,
        });
      }

      return {
        success: true,
        vulnerable: true,
        sessionId,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        warning: '⚠️ Unlimited concurrent sessions - no session management',
        sessionInfo: {
          totalActiveSessions: activeSessions.length,
          sessionIds: activeSessions.map(s => s.sessionId),
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleSessionError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Session Token in URL
   * 
   * Attack: Session exposed via URL/Referer header
   * 
   * @param {string} username - Username
   * @param {string} password - Password
   * @param {object} context - Request context
   * @returns {Promise<object>} Login result with URL token
   */
  async vulnerableSessionInURL(username, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      // Authenticate
      const [users] = await db.execute(
        `SELECT id, username, email, role FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid credentials',
        };
      }

      const user = users[0];
      const sessionId = uuidv4();

      await this.storeSession(sessionId, {
        userId: user.id,
        username: user.username,
        role: user.role,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: context.ip,
        userAgent: context.userAgent,
        inURL: true,
      });

      logger.warn('🚨 SESSION TOKEN IN URL', {
        username,
        sessionId,
      });

      await this.logSessionAttack({
        type: 'SESSION_IN_URL',
        severity: ATTACK_SEVERITY.MEDIUM,
        payload: { username, sessionId },
        patterns: [],
        context,
      });

      // ⚠️ VULNERABLE: Return URL with session token
      const dashboardURL = `${Config.app.url}/dashboard?sessionId=${sessionId}`;

      return {
        success: true,
        vulnerable: true,
        sessionId,
        redirectURL: dashboardURL,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        warning: '⚠️ Session token in URL - exposed via Referer header and browser history',
        risks: [
          'Visible in browser history',
          'Leaked via Referer header',
          'Exposed in server logs',
          'Shared via copy-paste',
          'Visible over shoulder surfing',
        ],
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleSessionError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: No Session Timeout
   * 
   * Attack: Sessions remain valid indefinitely
   * 
   * @param {string} sessionId - Session ID to check
   * @param {object} context - Request context
   * @returns {Promise<object>} Session validation
   */
  async vulnerableNoTimeout(sessionId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const session = await this.getSession(sessionId);

      if (!session) {
        return {
          success: false,
          vulnerable: true,
          message: 'Invalid session',
        };
      }

      // ⚠️ VULNERABLE: No timeout check
      const ageInHours = (Date.now() - session.createdAt) / (1000 * 60 * 60);
      const idleTimeMinutes = (Date.now() - session.lastActivity) / (1000 * 60);

      logger.warn('🚨 NO SESSION TIMEOUT', {
        sessionId,
        ageInHours: ageInHours.toFixed(2),
        idleTimeMinutes: idleTimeMinutes.toFixed(2),
      });

      // Update last activity
      session.lastActivity = Date.now();
      await this.storeSession(sessionId, session);

      return {
        success: true,
        vulnerable: true,
        session,
        warning: '⚠️ No session timeout - sessions valid indefinitely',
        sessionAge: {
          createdAt: new Date(session.createdAt).toISOString(),
          ageInHours: ageInHours.toFixed(2),
          idleTimeMinutes: idleTimeMinutes.toFixed(2),
          shouldBeExpired: ageInHours > 24 || idleTimeMinutes > 30,
        },
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleSessionError(error, sessionId, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Session Regeneration on Login
   */
  async secureLoginWithRegeneration(username, password, oldSessionId, context) {
    const startTime = Date.now();

    try {
      // Validate credentials
      const [users] = await db.execute(
        `SELECT id, username, email, role FROM ${tables.USERS} 
         WHERE username = ? AND deleted_at IS NULL`,
        [username]
      );

      if (users.length === 0) {
        throw new AppError('Invalid credentials', HTTP_STATUS.UNAUTHORIZED);
      }

      const user = users[0];

      // ✅ Destroy old session
      if (oldSessionId) {
        await this.destroySession(oldSessionId);
      }

      // ✅ Generate cryptographically secure session ID
      const sessionId = this.generateSecureSessionId();

      // ✅ Store session with security metadata
      await this.storeSession(sessionId, {
        userId: user.id,
        username: user.username,
        role: user.role,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ip: context.ip,
        userAgent: context.userAgent,
        fingerprint: this.generateDeviceFingerprint(context),
        regenerated: true,
      });

      // ✅ Limit concurrent sessions
      await this.enforceSessionLimit(user.id, SESSION_CONFIG.MAX_CONCURRENT_SESSIONS);

      return {
        success: true,
        vulnerable: false,
        sessionId,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_REGENERATION',
          sessionRegenerated: true,
        },
      };

    } catch (error) {
      logger.error('Secure login error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Session Validation with Timeout and IP Binding
   */
  async secureSessionValidation(sessionId, context) {
    const startTime = Date.now();

    try {
      const session = await this.getSession(sessionId);

      if (!session) {
        throw new AppError('Invalid session', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Check absolute timeout
      const sessionAge = Date.now() - session.createdAt;
      if (sessionAge > SESSION_CONFIG.ABSOLUTE_TIMEOUT) {
        await this.destroySession(sessionId);
        throw new AppError('Session expired', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Check idle timeout
      const idleTime = Date.now() - session.lastActivity;
      if (idleTime > SESSION_CONFIG.IDLE_TIMEOUT) {
        await this.destroySession(sessionId);
        throw new AppError('Session timed out due to inactivity', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Validate IP address
      if (session.ip !== context.ip) {
        logger.warn('Session IP mismatch', {
          sessionId,
          originalIP: session.ip,
          currentIP: context.ip,
        });
        
        // Optionally destroy session or require re-authentication
        await this.destroySession(sessionId);
        throw new AppError('Session security violation', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Validate device fingerprint
      const currentFingerprint = this.generateDeviceFingerprint(context);
      if (session.fingerprint !== currentFingerprint) {
        logger.warn('Session fingerprint mismatch', { sessionId });
        await this.destroySession(sessionId);
        throw new AppError('Session security violation', HTTP_STATUS.UNAUTHORIZED);
      }

      // ✅ Update last activity
      session.lastActivity = Date.now();
      await this.storeSession(sessionId, session);

      return {
        success: true,
        vulnerable: false,
        session,
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_VALIDATION',
        },
      };

    } catch (error) {
      logger.error('Secure session validation error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // SESSION MANAGEMENT HELPERS
  // ==========================================================================

  /**
   * Generate weak/predictable session ID (VULNERABLE)
   */
  generateWeakSessionId() {
    return `sess_${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Generate secure session ID
   */
  generateSecureSessionId() {
    return crypto.randomBytes(SESSION_CONFIG.SESSION_TOKEN_LENGTH).toString('hex');
  }

  /**
   * Generate device fingerprint
   */
  generateDeviceFingerprint(context) {
    const data = `${context.userAgent}|${context.ip}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Store session
   */
  async storeSession(sessionId, sessionData) {
    const key = `session:${sessionId}`;
    await cache.set(key, JSON.stringify(sessionData), SESSION_CONFIG.DEFAULT_EXPIRY);
  }

  /**
   * Get session
   */
  async getSession(sessionId) {
    const key = `session:${sessionId}`;
    const data = await cache.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Destroy session
   */
  async destroySession(sessionId) {
    const key = `session:${sessionId}`;
    await cache.delete(key);
  }

  /**
   * Get user's active sessions
   */
  async getUserActiveSessions(userId) {
    const sessions = [];
    const pattern = 'session:*';
    
    // Scan all sessions (simplified - in production use better approach)
    // This is a demonstration method
    const keys = await cache.keys(pattern);
    
    for (const key of keys) {
      const sessionData = await cache.get(key);
      if (sessionData) {
        const session = JSON.parse(sessionData);
        if (session.userId === userId) {
          sessions.push({
            sessionId: key.replace('session:', ''),
            ...session,
          });
        }
      }
    }

    return sessions;
  }

  /**
   * Enforce session limit
   */
  async enforceSessionLimit(userId, maxSessions) {
    const sessions = await this.getUserActiveSessions(userId);
    
    if (sessions.length > maxSessions) {
      // Sort by last activity, destroy oldest
      sessions.sort((a, b) => a.lastActivity - b.lastActivity);
      
      const toDestroy = sessions.slice(0, sessions.length - maxSessions);
      for (const session of toDestroy) {
        await this.destroySession(session.sessionId);
        logger.info('Session destroyed due to limit', {
          userId,
          sessionId: session.sessionId,
        });
      }
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect session fixation patterns
   */
  detectSessionFixation(sessionId, context) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;

    // Check if session ID looks suspicious
    if (sessionId && sessionId.length < 16) {
      detectedPatterns.push({
        category: 'WEAK_SESSION_ID',
        length: sessionId.length,
        matched: true,
      });
      score += 10;
    }

    // Check for predictable patterns
    if (sessionId && /sess_\d+/.test(sessionId)) {
      detectedPatterns.push({
        category: 'PREDICTABLE_PATTERN',
        pattern: 'Sequential counter detected',
        matched: true,
      });
      score += 15;
      severity = ATTACK_SEVERITY.HIGH;
    }

    // Check for URL-based session
    if (context.endpoint && context.endpoint.includes('sessionId=')) {
      detectedPatterns.push({
        category: 'SESSION_IN_URL',
        matched: true,
      });
      score += 12;
    }

    const isAttack = detectedPatterns.length > 0;

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log session attack
   */
  async logSessionAttack(attackData) {
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

      logger.attack('Session Attack Detected', {
        type,
        severity,
        payload,
        patterns,
        context,
      });

    } catch (error) {
      logger.error('Failed to log session attack', { error: error.message });
    }
  }

  /**
   * Handle session errors
   */
  handleSessionError(error, identifier, duration) {
    logger.error('Session Attack Error', {
      message: error.message,
      identifier,
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
        errorType: 'SESSION_ERROR',
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
      currentSessionCounter: this.sessionCounter,
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
      description: 'Session fixation allows attackers to hijack user sessions by setting the session ID before authentication',
      impact: [
        'Complete account takeover',
        'Session hijacking',
        'Identity theft',
        'Unauthorized access',
        'Data breach',
        'Privacy violation',
      ],
      vulnerabilities: [
        'Session not regenerated on login',
        'Predictable session IDs',
        'No IP binding',
        'No device fingerprinting',
        'Session tokens in URLs',
        'No session timeout',
        'Unlimited concurrent sessions',
        'Insecure session storage',
      ],
      remediation: [
        'Regenerate session ID on login',
        'Use cryptographically secure session IDs',
        'Implement IP binding validation',
        'Add device fingerprinting',
        'Never expose session tokens in URLs',
        'Implement session timeouts',
        'Limit concurrent sessions',
        'Use secure cookie flags (HttpOnly, Secure, SameSite)',
        'Regenerate on privilege escalation',
        'Monitor for suspicious session activity',
        'Implement session revocation mechanism',
        'Use short-lived session tokens',
      ],
      references: [
        'https://owasp.org/www-community/attacks/Session_fixation',
        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        'CWE-384: Session Fixation',
        'CWE-613: Insufficient Session Expiration',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      sessionFixations: 0,
      sessionHijackings: 0,
      predictedSessions: 0,
      concurrentSessionAbuse: 0,
      crossSiteTransfers: 0,
      successfulTakeovers: 0,
    };
    this.sessionCounter = 1000;
  }

  /**
   * Clear all sessions (for testing)
   */
  async clearAllSessions() {
    const pattern = 'session:*';
    const keys = await cache.keys(pattern);
    
    for (const key of keys) {
      await cache.delete(key);
    }
    
    logger.info('All sessions cleared');
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getSessionFixation = () => {
  if (!instance) {
    instance = new SessionFixation();
  }
  return instance;
};

export const createSessionHandler = (method) => {
  return async (req, res, next) => {
    try {
      const sessionAttack = getSessionFixation();
      
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
      const result = await sessionAttack[method](...Object.values(params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  SessionFixation,
  getSessionFixation,
  createSessionHandler,
};
