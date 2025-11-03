/**
 * ============================================================================
 * SECOND-ORDER SQL INJECTION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Second-Order SQLi Demonstration Platform
 * 
 * @module vulnerabilities/sqli/secondorder
 * @version 3.0.0
 * ⚠️  FOR EDUCATIONAL PURPOSES ONLY
 */

import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { HTTP_STATUS, ATTACK_SEVERITY, ERROR_CODES } from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';
import crypto from 'crypto';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// SECOND-ORDER CONSTANTS
// ============================================================================

const SECOND_ORDER_PATTERNS = {
  STORED_BYPASS: [/admin'--/i, /admin'#/i, /[a-z]+'--/i],
  STORED_UNION: [/'\s+UNION\s+SELECT/i, /'.*UNION.*SELECT/i],
  STORED_CONDITIONAL: [/'\s+OR\s+'1'\s*=\s*'1/i, /'\s+OR\s+1\s*=\s*1/i]
};

// ============================================================================
// SECOND-ORDER SQL INJECTION CLASS
// ============================================================================

export class SecondOrderSQLInjection {
  constructor() {
    this.name = 'Second-Order SQL Injection';
    this.cvssScore = 9.1;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.attackStats = {
      totalStorageAttempts: 0,
      successfulStorages: 0,
      totalExecutionAttempts: 0,
      successfulExecutions: 0,
      bypasses: 0
    };
    this.storedPayloads = new Map();
  }

  /**
   * ✅ SAFE: Store username with prepared statement (Phase 1)
   */
  async safeStoragePhase(username, email, password, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalStorageAttempts++;

      const payloadDetection = this.detectSecondOrderPayload(username);
      
      if (payloadDetection.isPotentialPayload) {
        await this.logSecondOrderStorage({
          phase: 'STORAGE',
          type: 'SECOND_ORDER_PAYLOAD_STORED',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { username, email },
          patterns: payloadDetection.patterns,
          context
        });

        this.attackStats.successfulStorages++;
        this.storedPayloads.set(username, {
          username,
          email,
          storedAt: new Date(),
          patterns: payloadDetection.patterns,
          context
        });
      }

      const hashedPassword = this.hashPassword(password);
      
      const query = 'INSERT INTO users (username, email, password, is_active, created_at) VALUES (?, ?, ?, ?, NOW())';
      const [result] = await db.execute(query, [username, email, hashedPassword, true]);

      const userId = result.insertId;
      const duration = Date.now() - startTime;

      logger.info('✅ SAFE STORAGE: User stored with prepared statement', { userId, username, payloadDetected: payloadDetection.isPotentialPayload });

      return {
        success: true,
        phase: 'STORAGE',
        userId,
        username,
        message: 'User registered successfully',
        payloadDetected: payloadDetection.isPotentialPayload,
        warning: payloadDetection.isPotentialPayload ? '⚠️ Potential SQLi payload detected - stored safely but may execute later' : null,
        metadata: { query, executionTime: duration, safeStorage: true, patterns: payloadDetection.patterns }
      };

    } catch (error) {
      logger.error('Storage phase error', { error: error.message });
      throw error;
    }
  }

  /**
   * ⚠️ VULNERABLE: Use stored username in vulnerable query (Phase 2)
   */
  async vulnerableExecutionPhase(userId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalExecutionAttempts++;

      const [users] = await db.execute('SELECT id, username, email FROM users WHERE id = ? LIMIT 1', [userId]);

      if (users.length === 0) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND);
      }

      const storedUsername = users[0].username;
      const trackedPayload = this.storedPayloads.get(storedUsername);
      const isTrackedAttack = trackedPayload !== undefined;

      if (isTrackedAttack) {
        await this.logSecondOrderExecution({
          phase: 'EXECUTION',
          type: 'SECOND_ORDER_SQLI_EXECUTED',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { userId, storedUsername },
          storedPayload: trackedPayload,
          context
        });

        this.attackStats.successfulExecutions++;
      }

      // ⚠️ VULNERABLE: String concatenation with stored data
      const query = `
        SELECT u.id, u.username, u.email, u.role, COUNT(o.id) as order_count, SUM(o.total_amount) as total_spent
        FROM ${tables.USERS} u
        LEFT JOIN ${tables.ORDERS} o ON o.user_id = u.id
        WHERE u.username = '${storedUsername}'
        GROUP BY u.id
      `;

      logger.warn('🚨 SECOND-ORDER EXECUTION: Stored data used unsafely', { query, userId, storedUsername, isTrackedAttack });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      if (isTrackedAttack && results.length > 0) {
        this.attackStats.bypasses++;
      }

      return {
        success: true,
        vulnerable: true,
        phase: 'EXECUTION',
        data: results,
        storedUsername,
        secondOrderAttack: isTrackedAttack,
        message: isTrackedAttack ? '🚨 SECOND-ORDER ATTACK EXECUTED!' : 'Query executed with stored data',
        metadata: { query, executionTime: duration, attackExecuted: isTrackedAttack, storedPayload: trackedPayload }
      };

    } catch (error) {
      return this.handleSecondOrderError(error, userId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Profile Update → Search
   */
  async vulnerableProfileUpdateSearch(userId, newBio, context = {}) {
    const startTime = Date.now();

    try {
      await db.execute('UPDATE users SET bio = ?, updated_at = NOW() WHERE id = ?', [newBio, userId]);
      logger.info('✅ Profile bio updated safely', { userId });

      const [users] = await db.execute('SELECT id, username, bio FROM users WHERE id = ? LIMIT 1', [userId]);
      const storedBio = users[0].bio;

      const searchQuery = `
        SELECT id, username, email, bio FROM ${tables.USERS}
        WHERE bio LIKE '%${storedBio}%' OR username LIKE '%${storedBio}%' LIMIT 10
      `;

      logger.warn('🚨 SECOND-ORDER: Bio used in search', { searchQuery, userId });

      const [searchResults] = await db.query(searchQuery);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        phase: 'PROFILE_UPDATE_SEARCH',
        updateSuccess: true,
        searchResults,
        metadata: { updateQuery: 'Parameterized (SAFE)', searchQuery, executionTime: duration }
      };

    } catch (error) {
      return this.handleSecondOrderError(error, userId, Date.now() - startTime);
    }
  }

  /**
   * Complete Attack Simulation
   */
  async simulateCompleteAttack(username, email, password, context = {}) {
    const startTime = Date.now();
    const attackFlow = [];

    try {
      logger.warn('🚨 SIMULATING COMPLETE SECOND-ORDER ATTACK', { username, email });

      const storageResult = await this.safeStoragePhase(username, email, password, context);
      attackFlow.push({ phase: 1, name: 'SAFE_STORAGE', result: storageResult, timestamp: new Date() });

      const userId = storageResult.userId;
      await this.delay(100);

      const executionResult = await this.vulnerableExecutionPhase(userId, context);
      attackFlow.push({ phase: 2, name: 'VULNERABLE_EXECUTION', result: executionResult, timestamp: new Date() });

      await this.delay(100);

      const profileResult = await this.vulnerableProfileUpdateSearch(userId, "My bio' OR '1'='1", context);
      attackFlow.push({ phase: 3, name: 'PROFILE_SEARCH_ATTACK', result: profileResult, timestamp: new Date() });

      const duration = Date.now() - startTime;
      const attackSuccessful = storageResult.payloadDetected && executionResult.secondOrderAttack;

      logger.warn('🚨 SECOND-ORDER ATTACK COMPLETED', { username, userId, attackSuccessful, totalDuration: `${duration}ms` });

      return {
        success: true,
        vulnerable: true,
        attackSuccessful,
        username,
        userId,
        attackFlow,
        summary: {
          totalPhases: attackFlow.length,
          payloadStored: storageResult.payloadDetected,
          payloadExecuted: executionResult.secondOrderAttack,
          dataExfiltrated: attackSuccessful,
          totalDuration: duration
        },
        message: attackSuccessful ? '🚨 CRITICAL: Second-order attack successful!' : 'Attack simulation completed',
        remediation: [
          'Always use parameterized queries for BOTH storage AND retrieval',
          'Validate data even when reading from database',
          'Implement context-aware output encoding',
          'Regular security audits of data flow'
        ]
      };

    } catch (error) {
      logger.error('Attack simulation error', { error: error.message });
      throw error;
    }
  }

  /**
   * Detect Second-Order Payload
   */
  detectSecondOrderPayload(input) {
    const detectedPatterns = [];
    let score = 0;

    for (const [category, patterns] of Object.entries(SECOND_ORDER_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(input)) {
          detectedPatterns.push({ category, pattern: pattern.toString() });
          score += 10;
        }
      }
    }

    const sqlKeywords = ['SELECT', 'UNION', 'DROP', 'INSERT', 'UPDATE', 'DELETE'];
    const foundKeywords = sqlKeywords.filter(kw => new RegExp(`\\b${kw}\\b`, 'i').test(input));

    if (foundKeywords.length > 0) {
      detectedPatterns.push({ category: 'SQL_KEYWORDS', keywords: foundKeywords });
      score += foundKeywords.length * 5;
    }

    return {
      isPotentialPayload: detectedPatterns.length > 0,
      score,
      patterns: detectedPatterns,
      confidence: score >= 20 ? 'HIGH' : score >= 10 ? 'MEDIUM' : 'LOW'
    };
  }

  /**
   * Log Storage Phase
   */
  async logSecondOrderStorage(data) {
    try {
      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (attack_type, severity, payload, patterns, ip_address, user_agent, metadata, timestamp, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          data.type,
          data.severity,
          JSON.stringify(data.payload),
          JSON.stringify(data.patterns),
          data.context.ip || null,
          data.context.userAgent || null,
          JSON.stringify({ phase: data.phase }),
          new Date()
        ]
      );
      logger.attack('Second-Order Storage Phase', data);
    } catch (error) {
      logger.error('Failed to log storage', { error: error.message });
    }
  }

  /**
   * Log Execution Phase
   */
  async logSecondOrderExecution(data) {
    try {
      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (attack_type, severity, payload, patterns, ip_address, user_agent, metadata, timestamp, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          data.type,
          data.severity,
          JSON.stringify(data.payload),
          JSON.stringify(data.storedPayload),
          data.context.ip || null,
          data.context.userAgent || null,
          JSON.stringify({ phase: data.phase, storedPayload: data.storedPayload }),
          new Date()
        ]
      );
      logger.attack('Second-Order Execution Phase', data);
    } catch (error) {
      logger.error('Failed to log execution', { error: error.message });
    }
  }

  /**
   * Handle Error
   */
  handleSecondOrderError(error, identifier, duration) {
    logger.error('Second-Order Error', { message: error.message, identifier, duration });
    return {
      success: false,
      vulnerable: true,
      error: { message: error.message, code: error.code },
      metadata: { executionTime: duration }
    };
  }

  /**
   * Utility: Delay
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Utility: Hash Password
   */
  hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  /**
   * Get Statistics
   */
  getStatistics() {
    return {
      ...this.attackStats,
      storageSuccessRate: this.attackStats.totalStorageAttempts > 0
        ? ((this.attackStats.successfulStorages / this.attackStats.totalStorageAttempts) * 100).toFixed(2) + '%'
        : '0%',
      executionSuccessRate: this.attackStats.totalExecutionAttempts > 0
        ? ((this.attackStats.successfulExecutions / this.attackStats.totalExecutionAttempts) * 100).toFixed(2) + '%'
        : '0%',
      activePayloads: this.storedPayloads.size
    };
  }

  /**
   * Get Vulnerability Info
   */
  getVulnerabilityInfo() {
    return {
      name: this.name,
      cvssScore: this.cvssScore,
      severity: this.severity,
      description: 'Second-Order SQLi occurs when data is stored safely but later used unsafely',
      impact: [
        'Delayed attack execution',
        'Bypass of input validation',
        'Authentication bypass',
        'Data exfiltration',
        'Admin panel compromise'
      ]
    };
  }

  /**
   * Get Stored Payloads
   */
  getStoredPayloads() {
    return Array.from(this.storedPayloads.entries()).map(([username, data]) => ({
      username,
      ...data,
      age: Date.now() - new Date(data.storedAt).getTime()
    }));
  }

  /**
   * Clear Stored Payloads
   */
  clearStoredPayloads() {
    const count = this.storedPayloads.size;
    this.storedPayloads.clear();
    logger.info('Cleared stored payloads', { count });
    return count;
  }

  /**
   * Reset Statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalStorageAttempts: 0,
      successfulStorages: 0,
      totalExecutionAttempts: 0,
      successfulExecutions: 0,
      bypasses: 0
    };
    this.storedPayloads.clear();
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

let instance = null;

export const getSecondOrderSQLInjection = () => {
  if (!instance) instance = new SecondOrderSQLInjection();
  return instance;
};

export const createSecondOrderHandler = (method) => {
  return async (req, res, next) => {
    try {
      const sqli = getSecondOrderSQLInjection();
      if (Config.security.mode !== 'vulnerable') {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.FORBIDDEN,
          message: 'Only available in vulnerable mode'
        });
      }
      const context = { ip: req.ip, userAgent: req.get('user-agent'), userId: req.user?.id };
      const result = await sqli[method](...Object.values(req.body || req.query), context);
      res.json(result);
    } catch (error) {
      next(error);
    }
  };
};

export default {
  SecondOrderSQLInjection,
  getSecondOrderSQLInjection,
  createSecondOrderHandler
};
