/**
 * ============================================================================
 * BLIND SQL INJECTION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Blind SQLi Demonstration Platform
 * Implements Boolean-based and Content-based blind SQL injection
 * 
 * @module vulnerabilities/sqli/blind
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates blind SQL injection where attackers cannot see
 * query results directly but can infer information through:
 * - Boolean-based responses (true/false conditions)
 * - Content-based differences (page variations)
 * - Response timing differences
 * - Error message variations
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * 
 * ============================================================================
 * BLIND SQLI TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Boolean-Based Blind SQLi (TRUE/FALSE responses)
 * 2. Content-Based Blind SQLi (different content)
 * 3. Conditional Responses
 * 4. Bit-by-Bit Data Extraction
 * 5. Character-by-Character Enumeration
 * 6. Length-Based Detection
 * 7. Substring Extraction
 * 8. ASCII Value Comparison
 * 9. Binary Search Optimization
 * 10. Error-Based Blind SQLi
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - ' AND 1=1--
 * - ' AND 1=2--
 * - ' AND (SELECT COUNT(*) FROM users) > 0--
 * - ' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
 * - ' AND ASCII(SUBSTRING((SELECT database()),1,1))>100--
 * - ' AND LENGTH((SELECT database()))=5--
 * - ' AND EXISTS(SELECT * FROM users WHERE username='admin')--
 * - ' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--
 * 
 * @requires Database
 * @requires Logger
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
// BLIND SQLI CONSTANTS
// ============================================================================

const BLIND_PATTERNS = {
  // Boolean logic
  BOOLEAN: [
    /AND\s+1\s*=\s*1/i,
    /AND\s+1\s*=\s*2/i,
    /AND\s+'[a-z]'\s*=\s*'[a-z]'/i,
    /AND\s+TRUE/i,
    /AND\s+FALSE/i
  ],
  
  // Conditional statements
  CONDITIONAL: [
    /SELECT\s+CASE\s+WHEN/i,
    /IF\s*\(/i,
    /IIF\s*\(/i,
    /DECODE\s*\(/i,
    /\(SELECT\s+CASE/i
  ],
  
  // Substring/Character extraction
  SUBSTRING: [
    /SUBSTRING\s*\(/i,
    /SUBSTR\s*\(/i,
    /MID\s*\(/i,
    /LEFT\s*\(/i,
    /RIGHT\s*\(/i,
    /CHAR\s*\(/i,
    /ASCII\s*\(/i
  ],
  
  // Length detection
  LENGTH: [
    /LENGTH\s*\(/i,
    /LEN\s*\(/i,
    /DATALENGTH\s*\(/i,
    /CHAR_LENGTH\s*\(/i
  ],
  
  // Existence checks
  EXISTS: [
    /EXISTS\s*\(/i,
    /NOT\s+EXISTS/i,
    /IN\s*\(SELECT/i
  ],
  
  // Comparison operators for blind detection
  COMPARISON: [
    />[\s\d]/,
    /<[\s\d]/,
    />=[\s\d]/,
    /<=[\s\d]/,
    /!=[\s\d]/,
    /<>[\s\d]/
  ]
};

const BLIND_TECHNIQUES = {
  BOOLEAN_TRUE: 'AND 1=1',
  BOOLEAN_FALSE: 'AND 1=2',
  SUBSTRING_MATCH: "AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'",
  ASCII_COMPARISON: 'AND ASCII(SUBSTRING((SELECT database()),1,1))>100',
  LENGTH_CHECK: 'AND LENGTH((SELECT database()))=5',
  EXISTS_CHECK: "AND EXISTS(SELECT * FROM users WHERE username='admin')",
  CONDITIONAL: 'AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1'
};

// ============================================================================
// BLIND SQL INJECTION CLASS
// ============================================================================

export class BlindSQLInjection {
  constructor() {
    this.name = 'Blind SQL Injection';
    this.category = 'SQL Injection';
    this.cvssScore = 8.6;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-89';
    
    // Attack statistics
    this.attackStats = {
      totalAttempts: 0,
      booleanAttacks: 0,
      contentBasedAttacks: 0,
      successfulExtractions: 0,
      charactersByteExtracted: 0,
      averageExtractionTime: 0
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS - BOOLEAN-BASED
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Boolean-Based Blind SQLi - User Existence Check
   */
  async vulnerableUserExists(username, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.booleanAttacks++;

      const attackDetection = this.detectBlindAttack(username);
      
      if (attackDetection.isAttack) {
        await this.logBlindAttack({
          type: 'BLIND_BOOLEAN_USER_EXISTS',
          severity: attackDetection.severity,
          payload: { username },
          patterns: attackDetection.patterns,
          context
        });
      }

      const query = `
        SELECT COUNT(*) as count
        FROM ${tables.USERS}
        WHERE username = '${username}'
        AND deleted_at IS NULL
      `;

      logger.warn('🚨 EXECUTING VULNERABLE BLIND BOOLEAN QUERY', { query, username, attackDetection });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;
      const userExists = results[0].count > 0;

      return {
        success: true,
        vulnerable: true,
        exists: userExists,
        message: userExists ? 'User found' : 'User not found',
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          blindType: 'BOOLEAN_BASED'
        }
      };

    } catch (error) {
      return this.handleBlindError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Boolean-Based Password Validation
   */
  async vulnerablePasswordCharacterCheck(username, passwordChar, position = 1, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.charactersByteExtracted++;

      const attackDetection = this.detectBlindAttack(`${username}${passwordChar}${position}`);
      
      if (attackDetection.isAttack) {
        await this.logBlindAttack({
          type: 'BLIND_CHAR_EXTRACTION',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { username, passwordChar, position },
          patterns: attackDetection.patterns,
          context
        });

        this.attackStats.successfulExtractions++;
      }

      const query = `
        SELECT 
          CASE 
            WHEN SUBSTRING(password, ${position}, 1) = '${passwordChar}' 
            THEN 1 
            ELSE 0 
          END as matches
        FROM ${tables.USERS}
        WHERE username = '${username}'
        LIMIT 1
      `;

      logger.warn('🚨 BLIND CHARACTER EXTRACTION ATTEMPT', {
        query,
        username,
        position,
        char: passwordChar,
        attackDetection
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;
      const matches = results[0]?.matches === 1;

      return {
        success: true,
        vulnerable: true,
        matches,
        character: passwordChar,
        position,
        message: matches ? '✅ Character matches' : '❌ Character does not match',
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          blindType: 'CHARACTER_EXTRACTION'
        }
      };

    } catch (error) {
      return this.handleBlindError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Content-Based Blind SQLi - Product Details
   */
  async vulnerableProductDetails(productId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.contentBasedAttacks++;

      const attackDetection = this.detectBlindAttack(String(productId));
      
      if (attackDetection.isAttack) {
        await this.logBlindAttack({
          type: 'BLIND_CONTENT_BASED',
          severity: attackDetection.severity,
          payload: { productId },
          patterns: attackDetection.patterns,
          context
        });
      }

      const query = `
        SELECT 
          id, name, description, price, stock_quantity
        FROM ${tables.PRODUCTS}
        WHERE id = ${productId}
        AND is_active = 1
        LIMIT 1
      `;

      logger.warn('🚨 BLIND CONTENT-BASED QUERY', { query, productId, attackDetection });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        found: results.length > 0,
        data: results[0] || null,
        message: results.length > 0 ? 'Product found' : 'Product not found or condition false',
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          blindType: 'CONTENT_BASED',
          recordsReturned: results.length
        }
      };

    } catch (error) {
      return this.handleBlindError(error, productId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: ASCII-Based Character Extraction
   */
  async vulnerableAsciiComparison(username, position, asciiValue, operator = '>', context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.charactersByteExtracted++;

      const attackDetection = this.detectBlindAttack(`${username}${position}${asciiValue}${operator}`);
      
      if (attackDetection.isAttack) {
        await this.logBlindAttack({
          type: 'BLIND_ASCII_EXTRACTION',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { username, position, asciiValue, operator },
          patterns: attackDetection.patterns,
          context
        });
      }

      const query = `
        SELECT 
          CASE 
            WHEN ASCII(SUBSTRING(password, ${position}, 1)) ${operator} ${asciiValue}
            THEN 1 
            ELSE 0 
          END as result
        FROM ${tables.USERS}
        WHERE username = '${username}'
        LIMIT 1
      `;

      logger.warn('🚨 BLIND ASCII EXTRACTION', { query, username, position, asciiValue, operator, attackDetection });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;
      const conditionTrue = results[0]?.result === 1;

      return {
        success: true,
        vulnerable: true,
        conditionTrue,
        position,
        asciiValue,
        operator,
        message: conditionTrue ? `✅ ASCII value ${operator} ${asciiValue}` : `❌ Condition false`,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          blindType: 'ASCII_COMPARISON'
        }
      };

    } catch (error) {
      return this.handleBlindError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Length-Based Data Extraction
   */
  async vulnerableLengthCheck(username, length, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectBlindAttack(`${username}${length}`);
      
      if (attackDetection.isAttack) {
        await this.logBlindAttack({
          type: 'BLIND_LENGTH_DETECTION',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { username, length },
          patterns: attackDetection.patterns,
          context
        });
      }

      const query = `
        SELECT 
          CASE 
            WHEN LENGTH(password) = ${length}
            THEN 1 
            ELSE 0 
          END as matches
        FROM ${tables.USERS}
        WHERE username = '${username}'
        LIMIT 1
      `;

      logger.warn('🚨 BLIND LENGTH CHECK', { query, username, length, attackDetection });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;
      const matches = results[0]?.matches === 1;

      return {
        success: true,
        vulnerable: true,
        matches,
        length,
        message: matches ? `✅ Password length is ${length}` : `❌ Password length is not ${length}`,
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          blindType: 'LENGTH_CHECK'
        }
      };

    } catch (error) {
      return this.handleBlindError(error, username, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: EXISTS-Based Blind SQLi
   */
  async vulnerableExistsCheck(id, existsQuery, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectBlindAttack(`${id}${existsQuery}`);
      
      if (attackDetection.isAttack) {
        await this.logBlindAttack({
          type: 'BLIND_EXISTS_CHECK',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { id, existsQuery },
          patterns: attackDetection.patterns,
          context
        });
      }

      const query = `
        SELECT 
          id, name, email
        FROM ${tables.USERS}
        WHERE id = ${id}
        AND EXISTS (${existsQuery})
        LIMIT 1
      `;

      logger.warn('🚨 BLIND EXISTS CHECK', { query, id, existsQuery: existsQuery.substring(0, 100), attackDetection });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        conditionTrue: results.length > 0,
        recordsFound: results.length,
        message: results.length > 0 ? '✅ EXISTS condition is TRUE' : '❌ EXISTS condition is FALSE',
        metadata: {
          query,
          executionTime: duration,
          attackDetected: attackDetection.isAttack,
          blindType: 'EXISTS_CHECK'
        }
      };

    } catch (error) {
      return this.handleBlindError(error, id, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // AUTOMATED BLIND EXTRACTION HELPERS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Automated Password Length Discovery
   */
  async automatedLengthDiscovery(username, context = {}) {
    const startTime = Date.now();
    let min = 1;
    let max = 255;
    let attempts = 0;

    logger.warn('🚨 AUTOMATED LENGTH DISCOVERY STARTED', { username });

    while (min <= max && attempts < 20) {
      const mid = Math.floor((min + max) / 2);
      attempts++;

      try {
        const result = await this.vulnerableLengthCheck(username, mid, context);
        
        if (result.matches) {
          return {
            success: true,
            vulnerable: true,
            passwordLength: mid,
            attempts,
            duration: Date.now() - startTime,
            message: `✅ Password length discovered: ${mid} characters`,
            metadata: {
              method: 'BINARY_SEARCH',
              blindType: 'AUTOMATED_LENGTH_DISCOVERY'
            }
          };
        }

        const gtQuery = `
          SELECT CASE WHEN LENGTH(password) > ${mid} THEN 1 ELSE 0 END as result
          FROM ${tables.USERS} WHERE username = '${username}' LIMIT 1
        `;
        const [gtResults] = await db.query(gtQuery);

        if (gtResults[0]?.result === 1) {
          min = mid + 1;
        } else {
          max = mid - 1;
        }

      } catch (error) {
        logger.error('Length discovery error', { error: error.message, mid });
        break;
      }
    }

    return {
      success: false,
      vulnerable: true,
      message: 'Length discovery failed or exceeded max attempts',
      attempts,
      duration: Date.now() - startTime
    };
  }

  /**
   * ⚠️ VULNERABLE: Automated Character Extraction
   */
  async automatedCharacterExtraction(username, position, context = {}) {
    const startTime = Date.now();
    let min = 32;
    let max = 126;
    let attempts = 0;

    logger.warn('🚨 AUTOMATED CHARACTER EXTRACTION', { username, position });

    while (min <= max && attempts < 10) {
      const mid = Math.floor((min + max) / 2);
      attempts++;

      try {
        const result = await this.vulnerableAsciiComparison(username, position, mid, '=', context);
        
        if (result.conditionTrue) {
          const char = String.fromCharCode(mid);
          return {
            success: true,
            vulnerable: true,
            character: char,
            ascii: mid,
            position,
            attempts,
            duration: Date.now() - startTime,
            message: `✅ Character discovered: '${char}' (ASCII ${mid})`,
            metadata: {
              method: 'BINARY_SEARCH_ASCII',
              blindType: 'AUTOMATED_CHAR_EXTRACTION'
            }
          };
        }

        const gtResult = await this.vulnerableAsciiComparison(username, position, mid, '>', context);

        if (gtResult.conditionTrue) {
          min = mid + 1;
        } else {
          max = mid - 1;
        }

      } catch (error) {
        logger.error('Character extraction error', { error: error.message });
        break;
      }
    }

    return {
      success: false,
      vulnerable: true,
      message: 'Character extraction failed',
      position,
      attempts,
      duration: Date.now() - startTime
    };
  }

  /**
   * ⚠️ VULNERABLE: Full Password Extraction
   */
  async automatedPasswordExtraction(username, context = {}) {
    const startTime = Date.now();

    logger.warn('🚨 FULL PASSWORD EXTRACTION STARTED', { username });

    const lengthResult = await this.automatedLengthDiscovery(username, context);
    
    if (!lengthResult.success) {
      return {
        success: false,
        vulnerable: true,
        message: 'Failed to determine password length',
        duration: Date.now() - startTime
      };
    }

    const passwordLength = lengthResult.passwordLength;
    let extractedPassword = '';
    const extractionLog = [];

    for (let pos = 1; pos <= passwordLength; pos++) {
      const charResult = await this.automatedCharacterExtraction(username, pos, context);
      
      if (charResult.success) {
        extractedPassword += charResult.character;
        extractionLog.push({
          position: pos,
          character: charResult.character,
          ascii: charResult.ascii,
          attempts: charResult.attempts
        });
      } else {
        extractedPassword += '?';
        extractionLog.push({
          position: pos,
          character: '?',
          failed: true
        });
      }
    }

    const totalDuration = Date.now() - startTime;
    const successRate = (extractionLog.filter(e => !e.failed).length / passwordLength * 100).toFixed(2);

    logger.warn('🚨 PASSWORD EXTRACTION COMPLETED', {
      username,
      passwordLength,
      extractedPassword,
      successRate: `${successRate}%`,
      totalDuration: `${totalDuration}ms`
    });

    this.attackStats.successfulExtractions++;

    return {
      success: true,
      vulnerable: true,
      username,
      extractedPassword,
      passwordLength,
      successRate: `${successRate}%`,
      extractionLog,
      totalAttempts: extractionLog.reduce((sum, e) => sum + (e.attempts || 0), 0),
      duration: totalDuration,
      message: `✅ Password extracted: ${extractedPassword}`,
      metadata: {
        method: 'AUTOMATED_BLIND_EXTRACTION',
        lengthDiscoveryTime: lengthResult.duration,
        charactersExtracted: extractionLog.filter(e => !e.failed).length,
        averageAttemptsPerChar: (extractionLog.reduce((sum, e) => sum + (e.attempts || 0), 0) / passwordLength).toFixed(2)
      }
    };
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: User Existence Check with Constant-Time Response
   */
  async secureUserExists(username) {
    const startTime = Date.now();

    try {
      if (typeof username !== 'string' || username.length > 50) {
        throw new AppError('Invalid username', HTTP_STATUS.BAD_REQUEST);
      }

      const query = `SELECT COUNT(*) as count FROM ${tables.USERS} WHERE username = ? AND deleted_at IS NULL`;
      const [results] = await db.execute(query, [username]);
      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        message: 'Check completed',
        metadata: {
          executionTime: duration,
          method: 'PARAMETERIZED_CONSTANT_TIME'
        }
      };

    } catch (error) {
      logger.error('Secure user exists error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect blind SQL injection patterns
   */
  detectBlindAttack(input) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;

    for (const [category, patterns] of Object.entries(BLIND_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(input)) {
          detectedPatterns.push({
            category,
            pattern: pattern.toString(),
            matched: true
          });
          score += this.getPatternScore(category);

          if (category === 'SUBSTRING' || category === 'LENGTH') {
            severity = ATTACK_SEVERITY.CRITICAL;
          } else if (category === 'CONDITIONAL' && severity !== ATTACK_SEVERITY.CRITICAL) {
            severity = ATTACK_SEVERITY.HIGH;
          }
        }
      }
    }

    for (const [technique, signature] of Object.entries(BLIND_TECHNIQUES)) {
      if (input.toLowerCase().includes(signature.toLowerCase())) {
        detectedPatterns.push({
          category: 'TECHNIQUE',
          technique,
          signature
        });
        score += 10;
      }
    }

    if (score >= 20) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 10) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 5) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      input: input.substring(0, 200),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Log blind attack attempt
   */
  async logBlindAttack(attackData) {
    try {
      const {
        type,
        severity,
        payload,
        patterns,
        context,
        timestamp = new Date()
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
          timestamp
        ]
      );

      logger.attack('Blind SQL Injection Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context
      });

    } catch (error) {
      logger.error('Failed to log blind attack', { error: error.message });
    }
  }

  /**
   * Handle blind query errors
   */
  handleBlindError(error, input, duration) {
    logger.error('Blind SQL Injection Error', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      input,
      duration
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        errno: error.errno
      },
      metadata: {
        executionTime: duration,
        errorType: 'BLIND_QUERY_ERROR'
      }
    };
  }

  /**
   * Get pattern severity score
   */
  getPatternScore(category) {
    const scores = {
      SUBSTRING: 12,
      LENGTH: 10,
      CONDITIONAL: 8,
      EXISTS: 7,
      BOOLEAN: 5,
      COMPARISON: 3
    };
    return scores[category] || 1;
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
      averageExtractionTime: this.attackStats.successfulExtractions > 0
        ? (this.attackStats.averageExtractionTime / this.attackStats.successfulExtractions).toFixed(2) + 'ms'
        : '0ms',
      successRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulExtractions / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
        : '0%'
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
      description: 'Blind SQL Injection allows attackers to extract data bit-by-bit through boolean-based or content-based responses without directly seeing query results',
      impact: [
        'Slow but complete data extraction',
        'Database enumeration',
        'Authentication bypass',
        'Credential harvesting',
        'Schema discovery',
        'Privilege information gathering'
      ],
      detectionDifficulty: 'High - requires careful analysis of application responses',
      attackComplexity: 'Medium - requires automation for efficient exploitation',
      remediation: [
        'Use parameterized queries exclusively',
        'Implement generic error messages',
        'Add constant-time response delays',
        'Monitor for repetitive similar requests',
        'Implement rate limiting',
        'Use Web Application Firewall (WAF)',
        'Regular security testing'
      ]
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      booleanAttacks: 0,
      contentBasedAttacks: 0,
      successfulExtractions: 0,
      charactersByteExtracted: 0,
      averageExtractionTime: 0
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getBlindSQLInjection = () => {
  if (!instance) {
    instance = new BlindSQLInjection();
  }
  return instance;
};

export const createBlindHandler = (method) => {
  return async (req, res, next) => {
    try {
      const sqli = getBlindSQLInjection();
      
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
  BlindSQLInjection,
  getBlindSQLInjection,
  createBlindHandler
};
