/**
 * ============================================================================
 * CLASSIC SQL INJECTION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade SQLi Demonstration Platform
 * Implements textbook SQL injection vulnerabilities for educational purposes
 * 
 * @module vulnerabilities/sqli/classic
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module intentionally contains SEVERE security vulnerabilities.
 * - Direct string concatenation in SQL queries
 * - No input validation or sanitization
 * - Bypasses prepared statements
 * - Exposes database structure
 * - Allows data exfiltration
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Must be deployed in isolated, controlled environments
 * 
 * ============================================================================
 * VULNERABILITY TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Authentication Bypass (OR 1=1)
 * 2. Data Extraction (UNION-based)
 * 3. Comment Injection (-- and /**/)
 * 4. Stacked Queries (multiple statements)
 * 5. Error-based Information Disclosure
 * 6. Boolean-based Blind SQLi
 * 7. Integer-based SQLi
 * 8. String-based SQLi
 * 9. Second-Order SQLi
 * 10. Out-of-Band SQLi preparation
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - ' OR '1'='1
 * - admin'--
 * - ' OR 1=1--
 * - ' UNION SELECT NULL--
 * - '; DROP TABLE users--
 * - 1' AND '1'='1
 * - -1 UNION SELECT @@version--
 * - ' AND SLEEP(5)--
 * - ' OR 'a'='a
 * - admin'/*
 * 
 * ============================================================================
 * DETECTION CAPABILITIES:
 * ============================================================================
 * - Pattern recognition (quotes, comments, operators)
 * - SQL keyword detection
 * - Encoding/obfuscation detection
 * - Payload complexity scoring
 * - Real-time attack logging
 * - Forensic evidence collection
 * - Attack attempt profiling
 * 
 * @requires Database
 * @requires Logger
 * @requires AttackDetector
 */

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
  ERROR_MESSAGES 
} from '../../config/constants.js';
import { AppError, DatabaseError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VULNERABILITY CONSTANTS & CONFIGURATION
// ============================================================================

const SQLI_PATTERNS = {
  // Authentication bypass patterns
  AUTH_BYPASS: [
    /'\s*OR\s*'1'\s*=\s*'1/i,
    /'\s*OR\s*1\s*=\s*1/i,
    /admin'\s*--/i,
    /admin'\s*#/i,
    /'\s*OR\s*'a'\s*=\s*'a/i,
    /'\s*OR\s*''='/i,
    /1'\s*OR\s*'1'\s*=\s*'1/i,
    /'\s*OR\s*TRUE/i,
    /'\s*OR\s*1/i
  ],
  
  // Union-based patterns
  UNION_BASED: [
    /UNION\s+(ALL\s+)?SELECT/i,
    /UNION\s+SELECT\s+NULL/i,
    /'\s*UNION\s+SELECT/i,
    /-1\s+UNION\s+SELECT/i,
    /\)\s*UNION\s+SELECT/i
  ],
  
  // Comment injection
  COMMENTS: [
    /--\s*$/,
    /#.*$/,
    /\/\*.*\*\//,
    /;\s*--/,
    /'\s*--/,
    /'\s*#/
  ],
  
  // Stacked queries
  STACKED: [
    /;\s*DROP/i,
    /;\s*DELETE/i,
    /;\s*UPDATE/i,
    /;\s*INSERT/i,
    /;\s*CREATE/i,
    /;\s*ALTER/i,
    /;\s*EXEC/i
  ],
  
  // Information gathering
  INFO_GATHERING: [
    /@@version/i,
    /@@hostname/i,
    /database\(\)/i,
    /user\(\)/i,
    /current_user/i,
    /version\(\)/i,
    /information_schema/i,
    /table_name/i,
    /column_name/i
  ],
  
  // Time-based blind
  TIME_BASED: [
    /SLEEP\s*\(/i,
    /BENCHMARK\s*\(/i,
    /WAITFOR\s+DELAY/i,
    /pg_sleep\s*\(/i,
    /DBMS_LOCK\.SLEEP/i
  ],
  
  // Error-based
  ERROR_BASED: [
    /CAST\s*\(/i,
    /CONVERT\s*\(/i,
    /EXTRACTVALUE\s*\(/i,
    /UPDATEXML\s*\(/i,
    /exp\s*\(/i
  ]
};

const ATTACK_SIGNATURES = {
  CRITICAL: [
    'DROP TABLE',
    'DROP DATABASE',
    'TRUNCATE',
    'DELETE FROM users',
    'UPDATE users SET',
    "admin'--",
    "' OR '1'='1",
    'UNION SELECT @@version'
  ],
  HIGH: [
    'UNION SELECT',
    'information_schema',
    'mysql.user',
    'pg_catalog',
    'sys.tables',
    'LOAD_FILE',
    'INTO OUTFILE'
  ],
  MEDIUM: [
    'SLEEP(',
    'BENCHMARK(',
    'WAITFOR',
    '@@version',
    'database()',
    'user()'
  ],
  LOW: [
    "'--",
    "'#",
    "' OR '",
    '1=1',
    "'='",
    '/*'
  ]
};

const SQL_KEYWORDS = [
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
  'UNION', 'JOIN', 'WHERE', 'FROM', 'INTO', 'VALUES', 'SET',
  'TABLE', 'DATABASE', 'SCHEMA', 'INDEX', 'VIEW', 'PROCEDURE',
  'FUNCTION', 'TRIGGER', 'GRANT', 'REVOKE', 'EXEC', 'EXECUTE',
  'DECLARE', 'CAST', 'CONVERT', 'SUBSTRING', 'ASCII', 'CHAR',
  'CONCAT', 'GROUP_CONCAT', 'LOAD_FILE', 'OUTFILE', 'DUMPFILE'
];

// ============================================================================
// CLASSIC SQL INJECTION CLASS
// ============================================================================

export class ClassicSQLInjection {
  constructor() {
    this.name = 'Classic SQL Injection';
    this.category = 'SQL Injection';
    this.cvssScore = 9.8;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-89';
    
    // Attack statistics
    this.attackStats = {
      totalAttempts: 0,
      successfulAttacks: 0,
      blockedAttempts: 0,
      uniquePayloads: new Set(),
      attackTypes: {},
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      }
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Authentication Login - String Concatenation
   * 
   * Classic authentication bypass vulnerability
   * Attack vectors:
   * - admin'--
   * - ' OR '1'='1
   * - ' OR 1=1--
   * - admin'/*
   * 
   * @param {string} username - User input (VULNERABLE)
   * @param {string} password - Password input (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} User data or attack result
   */
  async vulnerableLogin(username, password, context = {}) {
    const startTime = Date.now();
    
    try {
      // Log attack attempt
      this.attackStats.totalAttempts++;
      
      // Detect attack
      const attackDetection = this.detectSQLInjection(username, password);
      
      if (attackDetection.isAttack) {
        await this.logAttack({
          type: 'AUTH_BYPASS_ATTEMPT',
          severity: attackDetection.severity,
          payload: { username, password: '***' },
          patterns: attackDetection.patterns,
          context,
          timestamp: new Date()
        });
      }

      // ⚠️ VULNERABLE: Direct string concatenation
      const query = `
        SELECT id, username, email, role, is_active 
        FROM ${tables.USERS} 
        WHERE username = '${username}' 
        AND password = '${password}' 
        LIMIT 1
      `;

      logger.warn('🚨 EXECUTING VULNERABLE QUERY', {
        query,
        username,
        mode: Config.security.mode
      });

      // Execute vulnerable query
      const [results] = await db.query(query);
      
      const duration = Date.now() - startTime;

      if (results && results.length > 0) {
        this.attackStats.successfulAttacks++;
        
        logger.warn('🚨 SQL INJECTION SUCCESSFUL', {
          username,
          affectedRows: results.length,
          duration,
          attackDetection
        });

        return {
          success: true,
          vulnerable: true,
          data: results[0],
          metadata: {
            query,
            executionTime: duration,
            attackDetected: attackDetection.isAttack,
            severity: attackDetection.severity
          }
        };
      }

      return {
        success: false,
        vulnerable: true,
        message: 'Authentication failed',
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack
        }
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      
      // SQL errors can reveal database structure
      logger.error('SQL Injection Error (Information Disclosure)', {
        error: error.message,
        sqlState: error.sqlState,
        errno: error.errno,
        sql: error.sql,
        username,
        duration
      });

      // ⚠️ VULNERABLE: Exposing detailed error messages
      return {
        success: false,
        vulnerable: true,
        error: error.message,
        sqlState: error.sqlState,
        errno: error.errno,
        sql: error.sql,
        metadata: {
          executionTime: duration,
          errorType: 'SQL_SYNTAX_ERROR'
        }
      };
    }
  }

  /**
   * ⚠️ VULNERABLE: User Search - Partial String Match
   * 
   * Demonstrates LIKE clause injection
   * Attack vectors:
   * - %' OR '1'='1
   * - %' UNION SELECT NULL--
   * - a%'--
   * 
   * @param {string} searchTerm - Search input (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Search results
   */
  async vulnerableSearch(searchTerm, context = {}) {
    const startTime = Date.now();

    try {
      const attackDetection = this.detectSQLInjection(searchTerm);
      
      if (attackDetection.isAttack) {
        await this.logAttack({
          type: 'SEARCH_SQLI',
          severity: attackDetection.severity,
          payload: { searchTerm },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: LIKE clause with string concatenation
      const query = `
        SELECT id, username, email, first_name, last_name, role, created_at
        FROM ${tables.USERS}
        WHERE username LIKE '%${searchTerm}%' 
        OR email LIKE '%${searchTerm}%'
        OR CONCAT(first_name, ' ', last_name) LIKE '%${searchTerm}%'
        LIMIT 100
      `;

      logger.warn('🚨 EXECUTING VULNERABLE SEARCH', {
        query,
        searchTerm,
        mode: Config.security.mode
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack && results.length > 0) {
        this.attackStats.successfulAttacks++;
      }

      return {
        success: true,
        vulnerable: true,
        data: results,
        count: results.length,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, searchTerm, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Integer-based SQL Injection
   * 
   * Demonstrates numeric field injection without quotes
   * Attack vectors:
   * - 1 OR 1=1
   * - -1 UNION SELECT
   * - 1; DROP TABLE
   * 
   * @param {number|string} userId - User ID (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} User data
   */
  async vulnerableGetUserById(userId, context = {}) {
    const startTime = Date.now();

    try {
      const attackDetection = this.detectSQLInjection(String(userId));
      
      if (attackDetection.isAttack) {
        await this.logAttack({
          type: 'INTEGER_SQLI',
          severity: attackDetection.severity,
          payload: { userId },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: Integer field without validation or casting
      const query = `
        SELECT 
          u.id, u.username, u.email, u.first_name, u.last_name, 
          u.role, u.is_active, u.created_at,
          COUNT(o.id) as total_orders,
          SUM(o.total_amount) as total_spent
        FROM ${tables.USERS} u
        LEFT JOIN ${tables.ORDERS} o ON u.id = o.user_id
        WHERE u.id = ${userId}
        GROUP BY u.id
      `;

      logger.warn('🚨 EXECUTING VULNERABLE INTEGER QUERY', {
        query,
        userId,
        mode: Config.security.mode
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      if (attackDetection.isAttack && results.length > 0) {
        this.attackStats.successfulAttacks++;
      }

      return {
        success: true,
        vulnerable: true,
        data: results[0] || null,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, userId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Order By Clause Injection
   * 
   * Demonstrates ORDER BY manipulation
   * Attack vectors:
   * - (SELECT CASE WHEN (1=1) THEN 'username' ELSE 1/0 END)
   * - username; DROP TABLE
   * - IF(1=1, 'username', 'email')
   * 
   * @param {string} sortField - Sort field (VULNERABLE)
   * @param {string} sortOrder - Sort order (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Sorted results
   */
  async vulnerableGetUsersSorted(sortField = 'id', sortOrder = 'ASC', context = {}) {
    const startTime = Date.now();

    try {
      const attackDetection = this.detectSQLInjection(sortField + ' ' + sortOrder);
      
      if (attackDetection.isAttack) {
        await this.logAttack({
          type: 'ORDER_BY_SQLI',
          severity: attackDetection.severity,
          payload: { sortField, sortOrder },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: Dynamic ORDER BY without validation
      const query = `
        SELECT id, username, email, role, created_at
        FROM ${tables.USERS}
        WHERE deleted_at IS NULL
        ORDER BY ${sortField} ${sortOrder}
        LIMIT 50
      `;

      logger.warn('🚨 EXECUTING VULNERABLE ORDER BY', {
        query,
        sortField,
        sortOrder,
        mode: Config.security.mode
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: results,
        count: results.length,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, sortField, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: LIMIT/OFFSET Injection
   * 
   * Demonstrates pagination parameter injection
   * Attack vectors:
   * - 10 UNION SELECT
   * - 10,10 UNION SELECT
   * - 0,10000
   * 
   * @param {number|string} limit - Limit value (VULNERABLE)
   * @param {number|string} offset - Offset value (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Paginated results
   */
  async vulnerableGetUsersPaginated(limit = 10, offset = 0, context = {}) {
    const startTime = Date.now();

    try {
      const attackDetection = this.detectSQLInjection(`${limit},${offset}`);
      
      if (attackDetection.isAttack) {
        await this.logAttack({
          type: 'LIMIT_OFFSET_SQLI',
          severity: attackDetection.severity,
          payload: { limit, offset },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: LIMIT/OFFSET without validation
      const query = `
        SELECT id, username, email, role, created_at
        FROM ${tables.USERS}
        WHERE deleted_at IS NULL
        ORDER BY id DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      logger.warn('🚨 EXECUTING VULNERABLE PAGINATION', {
        query,
        limit,
        offset,
        mode: Config.security.mode
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: results,
        pagination: {
          limit,
          offset,
          count: results.length
        },
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, `${limit},${offset}`, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Parameterized Login Query
   * 
   * Demonstrates proper SQL injection prevention
   * Uses prepared statements with parameter binding
   * 
   * @param {string} username - User input (SAFE)
   * @param {string} password - Password input (SAFE)
   * @returns {Promise<object>} User data
   */
  async secureLogin(username, password) {
    const startTime = Date.now();

    try {
      // ✅ SECURE: Parameterized query with placeholders
      const query = `
        SELECT id, username, email, role, is_active
        FROM ${tables.USERS}
        WHERE username = ? AND password = ?
        LIMIT 1
      `;

      // ✅ SECURE: Parameters passed separately
      const [results] = await db.execute(query, [username, password]);
      const duration = Date.now() - startTime;

      return {
        success: results.length > 0,
        vulnerable: false,
        data: results[0] || null,
        metadata: {
          executionTime: duration,
          method: 'PARAMETERIZED_QUERY'
        }
      };

    } catch (error) {
      logger.error('Secure login error', { error: error.message });
      throw new DatabaseError('Login failed');
    }
  }

  /**
   * ✅ SECURE: Parameterized Search with Validation
   * 
   * @param {string} searchTerm - Search input (SAFE)
   * @returns {Promise<object>} Search results
   */
  async secureSearch(searchTerm) {
    const startTime = Date.now();

    try {
      // ✅ Input validation
      if (typeof searchTerm !== 'string' || searchTerm.length > 100) {
        throw new AppError('Invalid search term', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Sanitize input
      const sanitized = searchTerm.trim();

      // ✅ SECURE: Parameterized query
      const query = `
        SELECT id, username, email, first_name, last_name, role, created_at
        FROM ${tables.USERS}
        WHERE (username LIKE ? OR email LIKE ? OR CONCAT(first_name, ' ', last_name) LIKE ?)
        AND deleted_at IS NULL
        LIMIT 100
      `;

      const searchPattern = `%${sanitized}%`;
      const [results] = await db.execute(query, [searchPattern, searchPattern, searchPattern]);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: results,
        count: results.length,
        metadata: {
          executionTime: duration,
          method: 'PARAMETERIZED_QUERY'
        }
      };

    } catch (error) {
      logger.error('Secure search error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Integer Parameter with Validation
   * 
   * @param {number|string} userId - User ID (SAFE)
   * @returns {Promise<object>} User data
   */
  async secureGetUserById(userId) {
    const startTime = Date.now();

    try {
      // ✅ Type validation and casting
      const id = parseInt(userId, 10);
      
      if (isNaN(id) || id <= 0) {
        throw new AppError('Invalid user ID', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ SECURE: Parameterized query with validated integer
      const query = `
        SELECT 
          u.id, u.username, u.email, u.first_name, u.last_name,
          u.role, u.is_active, u.created_at,
          COUNT(o.id) as total_orders,
          SUM(o.total_amount) as total_spent
        FROM ${tables.USERS} u
        LEFT JOIN ${tables.ORDERS} o ON u.id = o.user_id
        WHERE u.id = ?
        GROUP BY u.id
      `;

      const [results] = await db.execute(query, [id]);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: results[0] || null,
        metadata: {
          executionTime: duration,
          method: 'PARAMETERIZED_QUERY_WITH_VALIDATION'
        }
      };

    } catch (error) {
      logger.error('Secure get user error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Whitelisted ORDER BY
   * 
   * @param {string} sortField - Sort field (SAFE)
   * @param {string} sortOrder - Sort order (SAFE)
   * @returns {Promise<object>} Sorted results
   */
  async secureGetUsersSorted(sortField = 'id', sortOrder = 'ASC') {
    const startTime = Date.now();

    try {
      // ✅ Whitelist validation
      const allowedFields = ['id', 'username', 'email', 'created_at', 'role'];
      const allowedOrders = ['ASC', 'DESC'];

      if (!allowedFields.includes(sortField)) {
        throw new AppError('Invalid sort field', HTTP_STATUS.BAD_REQUEST);
      }

      if (!allowedOrders.includes(sortOrder.toUpperCase())) {
        throw new AppError('Invalid sort order', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ SECURE: Whitelisted values, not user input
      const query = `
        SELECT id, username, email, role, created_at
        FROM ${tables.USERS}
        WHERE deleted_at IS NULL
        ORDER BY ${sortField} ${sortOrder.toUpperCase()}
        LIMIT 50
      `;

      const [results] = await db.execute(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: results,
        count: results.length,
        metadata: {
          executionTime: duration,
          method: 'WHITELISTED_ORDER_BY'
        }
      };

    } catch (error) {
      logger.error('Secure sort error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect SQL injection patterns in input
   * 
   * @param {...string} inputs - Input strings to analyze
   * @returns {object} Detection results
   */
  detectSQLInjection(...inputs) {
    const combinedInput = inputs.join(' ');
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.LOW;
    let score = 0;

    // Check all pattern categories
    for (const [category, patterns] of Object.entries(SQLI_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(combinedInput)) {
          detectedPatterns.push({
            category,
            pattern: pattern.toString(),
            matched: true
          });
          score += this.getPatternScore(category);
        }
      }
    }

    // Check for SQL keywords
    const foundKeywords = SQL_KEYWORDS.filter(keyword => 
      new RegExp(`\\b${keyword}\\b`, 'i').test(combinedInput)
    );
    
    if (foundKeywords.length > 0) {
      detectedPatterns.push({
        category: 'SQL_KEYWORDS',
        keywords: foundKeywords,
        count: foundKeywords.length
      });
      score += foundKeywords.length * 2;
    }

    // Check attack signatures
    for (const [level, signatures] of Object.entries(ATTACK_SIGNATURES)) {
      for (const sig of signatures) {
        if (combinedInput.toLowerCase().includes(sig.toLowerCase())) {
          detectedPatterns.push({
            category: 'ATTACK_SIGNATURE',
            level,
            signature: sig
          });
          score += this.getSeverityScore(level);
          
          if (level === 'CRITICAL') severity = ATTACK_SEVERITY.CRITICAL;
          else if (level === 'HIGH' && severity !== ATTACK_SEVERITY.CRITICAL) {
            severity = ATTACK_SEVERITY.HIGH;
          }
        }
      }
    }

    // Determine severity based on score
    if (score >= 20) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 10) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 5) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    if (isAttack) {
      this.updateAttackStats(severity, combinedInput);
    }

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      input: combinedInput.substring(0, 200), // Truncate for logging
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Log attack attempt to database and cache
   * 
   * @param {object} attackData - Attack details
   * @returns {Promise<void>}
   */
  async logAttack(attackData) {
    try {
      const {
        type,
        severity,
        payload,
        patterns,
        context,
        timestamp = new Date()
      } = attackData;

      // Log to database
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
          timestamp
        ]
      );

      // Cache recent attacks for rate limiting
      const cacheKey = CacheKeyBuilder.custom('sqli_attacks:', context.ip);
      const recentAttacks = await cache.get(cacheKey) || [];
      recentAttacks.push({
        type,
        severity,
        timestamp: timestamp.toISOString()
      });
      await cache.set(cacheKey, recentAttacks, 3600); // 1 hour

      // Log to file
      logger.attack('SQL Injection Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context
      });

      // Update statistics
      this.attackStats.uniquePayloads.add(JSON.stringify(payload));

    } catch (error) {
      logger.error('Failed to log attack', { error: error.message });
    }
  }

  /**
   * Handle vulnerable query errors with detailed disclosure
   * 
   * @param {Error} error - Database error
   * @param {string} input - User input
   * @param {number} duration - Execution time
   * @returns {object} Error response
   */
  handleVulnerableError(error, input, duration) {
    logger.error('SQL Injection Error', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      sql: error.sql,
      input,
      duration
    });

    // ⚠️ VULNERABLE: Exposing detailed SQL errors
    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        sqlMessage: error.sqlMessage,
        sql: error.sql
      },
      metadata: {
        executionTime: duration,
        errorType: 'DATABASE_ERROR',
        input: input
      }
    };
  }

  /**
   * Get pattern severity score
   */
  getPatternScore(category) {
    const scores = {
      STACKED: 10,
      UNION_BASED: 8,
      AUTH_BYPASS: 8,
      ERROR_BASED: 6,
      TIME_BASED: 6,
      INFO_GATHERING: 5,
      COMMENTS: 3
    };
    return scores[category] || 1;
  }

  /**
   * Get severity level score
   */
  getSeverityScore(level) {
    const scores = {
      CRITICAL: 15,
      HIGH: 10,
      MEDIUM: 5,
      LOW: 2
    };
    return scores[level] || 1;
  }

  /**
   * Update attack statistics
   */
  updateAttackStats(severity, payload) {
    const severityMap = {
      [ATTACK_SEVERITY.CRITICAL]: 'critical',
      [ATTACK_SEVERITY.HIGH]: 'high',
      [ATTACK_SEVERITY.MEDIUM]: 'medium',
      [ATTACK_SEVERITY.LOW]: 'low'
    };

    const key = severityMap[severity];
    if (key) {
      this.attackStats.severityBreakdown[key]++;
    }

    this.attackStats.blockedAttempts++;
  }

  // ==========================================================================
  // UTILITY & REPORTING METHODS
  // ==========================================================================

  /**
   * Get attack statistics
   */
  getStatistics() {
    return {
      ...this.attackStats,
      uniquePayloads: this.attackStats.uniquePayloads.size,
      successRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.successfulAttacks / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
        : '0%'
    };
  }

  /**
   * Reset attack statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulAttacks: 0,
      blockedAttempts: 0,
      uniquePayloads: new Set(),
      attackTypes: {},
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      }
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
      description: 'Classic SQL Injection through direct string concatenation in database queries',
      impact: [
        'Unauthorized data access',
        'Authentication bypass',
        'Data modification or deletion',
        'Database structure disclosure',
        'Privilege escalation',
        'Denial of Service'
      ],
      attackVectors: [
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1 OR 1=1",
        "-1 UNION SELECT @@version--"
      ],
      remediation: [
        'Use parameterized queries (prepared statements)',
        'Implement input validation and sanitization',
        'Apply principle of least privilege for database accounts',
        'Use ORM frameworks with built-in protection',
        'Implement Web Application Firewall (WAF)',
        'Regular security audits and code reviews'
      ]
    };
  }

  /**
   * Generate attack report
   */
  async generateAttackReport(startDate, endDate) {
    try {
      const [attacks] = await db.execute(
        `SELECT 
          attack_type,
          severity,
          COUNT(*) as count,
          DATE(timestamp) as date
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%SQLI%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY attack_type, severity, DATE(timestamp)
         ORDER BY timestamp DESC`,
        [startDate, endDate]
      );

      const [topPayloads] = await db.execute(
        `SELECT 
          payload,
          COUNT(*) as frequency,
          MAX(severity) as max_severity
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%SQLI%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY payload
         ORDER BY frequency DESC
         LIMIT 10`,
        [startDate, endDate]
      );

      return {
        period: { start: startDate, end: endDate },
        attacks,
        topPayloads: topPayloads.map(p => ({
          ...p,
          payload: JSON.parse(p.payload)
        })),
        statistics: this.getStatistics(),
        generatedAt: new Date().toISOString()
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

/**
 * Create and return singleton instance
 */
let instance = null;

export const getClassicSQLInjection = () => {
  if (!instance) {
    instance = new ClassicSQLInjection();
  }
  return instance;
};

/**
 * Route handler wrapper for vulnerable endpoints
 */
export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const sqli = getClassicSQLInjection();
      
      // Check if in vulnerable mode
      if (Config.security.mode !== 'vulnerable') {
        return res.status(HTTP_STATUS.FORBIDDEN).json({
          success: false,
          error: ERROR_CODES.FORBIDDEN,
          message: 'This endpoint is only available in vulnerable mode'
        });
      }

      const context = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.user?.id,
        endpoint: req.path
      };

      const result = await sqli[method](...Object.values(req.body), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  ClassicSQLInjection,
  getClassicSQLInjection,
  createVulnerableHandler
};
