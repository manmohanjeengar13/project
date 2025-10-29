/**
 * ============================================================================
 * TIME-BASED BLIND SQL INJECTION VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Time-Based Blind SQLi Demonstration Platform
 * Implements timing-based data extraction techniques
 * 
 * @module vulnerabilities/sqli/timebased
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates time-based blind SQL injection where attackers
 * infer information through response time delays:
 * - SLEEP() function exploitation (MySQL)
 * - WAITFOR DELAY (SQL Server)
 * - pg_sleep() (PostgreSQL)
 * - BENCHMARK() abuse
 * - Heavy query computation
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can cause Denial of Service if exploited
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
// TIME-BASED SQLI CONSTANTS
// ============================================================================

const TIME_PATTERNS = {
  MYSQL_SLEEP: [
    /SLEEP\s*\(\s*\d+\s*\)/i,
    /SLEEP\s*\([^)]+\)/i,
    /IF\s*\([^,]+,\s*SLEEP/i,
    /CASE\s+WHEN\s+.+SLEEP/i
  ],
  BENCHMARK: [
    /BENCHMARK\s*\(/i,
    /BENCHMARK\s*\(\s*\d+/i,
    /BENCHMARK\s*\([^,]+,\s*[^)]+\)/i
  ],
  SQLSERVER_WAITFOR: [
    /WAITFOR\s+DELAY/i,
    /WAITFOR\s+TIME/i,
    /WAITFOR\s+DELAY\s+['"][\d:]+['"]/i
  ],
  POSTGRESQL_SLEEP: [
    /pg_sleep\s*\(/i,
    /pg_sleep\s*\(\s*\d+/i
  ],
  ORACLE_SLEEP: [
    /DBMS_LOCK\.SLEEP/i,
    /DBMS_LOCK\.SLEEP\s*\(\s*\d+/i
  ],
  HEAVY_QUERY: [
    /COUNT\s*\(\s*\*\s*\)\s+FROM\s+information_schema/i,
    /RLIKE\s+SLEEP/i,
    /REGEXP\s+SLEEP/i
  ]
};

const TIMING_THRESHOLDS = {
  BASELINE: 100,
  DELAY_SHORT: 2000,
  DELAY_MEDIUM: 5000,
  DELAY_LONG: 10000,
  DETECTION_THRESHOLD: 1500,
  MAX_SAFE_DELAY: 30000
};

// ============================================================================
// TIME-BASED SQL INJECTION CLASS
// ============================================================================

export class TimeBasedSQLInjection {
  constructor() {
    this.name = 'Time-Based Blind SQL Injection';
    this.category = 'SQL Injection';
    this.cvssScore = 7.5;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-89';
    
    this.attackStats = {
      totalAttempts: 0,
      successfulDelays: 0,
      totalDelayTime: 0,
      averageDelayTime: 0,
      characterExtractions: 0,
      dosAttempts: 0,
      timingBaseline: TIMING_THRESHOLDS.BASELINE
    };
    
    this.baselineTimes = [];
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS - TIME-BASED
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Time-Based User Validation
   */
  async vulnerableTimeBasedValidation(username, context = {}) {
    const startTime = Date.now();
    const baseline = await this.measureBaseline();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectTimeBasedAttack(username);
      
      if (attackDetection.isAttack) {
        await this.logTimeAttack({
          type: 'TIME_BASED_VALIDATION',
          severity: attackDetection.severity,
          payload: { username },
          patterns: attackDetection.patterns,
          expectedDelay: attackDetection.expectedDelay,
          context
        });
      }

      const query = `
        SELECT id, username, email, is_active
        FROM ${tables.USERS}
        WHERE username = '${username}'
        AND deleted_at IS NULL
        LIMIT 1
      `;

      logger.warn('🚨 EXECUTING VULNERABLE TIME-BASED QUERY', {
        query,
        username,
        baseline: `${baseline}ms`,
        attackDetection
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;
      const delayDetected = duration > (baseline + TIMING_THRESHOLDS.DETECTION_THRESHOLD);

      if (delayDetected) {
        this.attackStats.successfulDelays++;
        this.attackStats.totalDelayTime += duration;
      }

      return {
        success: true,
        vulnerable: true,
        data: results[0] || null,
        timing: {
          executionTime: duration,
          baseline,
          deviation: duration - baseline,
          delayDetected,
          significant: delayDetected
        },
        metadata: {
          query,
          attackDetected: attackDetection.isAttack,
          severity: attackDetection.severity,
          expectedDelay: attackDetection.expectedDelay
        }
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      return this.handleTimeError(error, username, duration, baseline);
    }
  }

  /**
   * ⚠️ VULNERABLE: Conditional Time-Based Character Extraction
   */
  async vulnerableConditionalDelay(username, position, character, delay = 5, context = {}) {
    const startTime = Date.now();
    const baseline = await this.measureBaseline();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.characterExtractions++;

      if (delay > TIMING_THRESHOLDS.MAX_SAFE_DELAY / 1000) {
        throw new AppError('Delay too long - potential DoS', HTTP_STATUS.BAD_REQUEST);
      }

      const attackDetection = this.detectTimeBasedAttack(`${username}${character}${delay}`);
      
      if (attackDetection.isAttack) {
        await this.logTimeAttack({
          type: 'TIME_BASED_CHAR_EXTRACTION',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { username, position, character, delay },
          patterns: attackDetection.patterns,
          expectedDelay: delay * 1000,
          context
        });
      }

      const query = `
        SELECT 
          id,
          username,
          IF(
            SUBSTRING(password, ${position}, 1) = '${character}',
            SLEEP(${delay}),
            0
          ) as delay_executed
        FROM ${tables.USERS}
        WHERE username = '${username}'
        LIMIT 1
      `;

      logger.warn('🚨 TIME-BASED CHARACTER EXTRACTION', {
        query,
        username,
        position,
        character,
        delay: `${delay}s`,
        expectedDelay: `${delay * 1000}ms`
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;
      const expectedDelayMs = delay * 1000;
      const delayOccurred = duration >= (baseline + expectedDelayMs - 500);
      const matches = delayOccurred;

      if (delayOccurred) {
        this.attackStats.successfulDelays++;
        this.attackStats.totalDelayTime += duration;
      }

      return {
        success: true,
        vulnerable: true,
        matches,
        character,
        position,
        timing: {
          executionTime: duration,
          baseline,
          expectedDelay: expectedDelayMs,
          deviation: duration - baseline,
          delayOccurred,
          confidence: this.calculateConfidence(duration, baseline, expectedDelayMs)
        },
        message: matches 
          ? `✅ Character matches (delay detected: ${duration}ms)` 
          : `❌ Character does not match (no delay: ${duration}ms)`,
        metadata: {
          query,
          attackDetected: attackDetection.isAttack,
          blindType: 'TIME_BASED_CONDITIONAL'
        }
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      return this.handleTimeError(error, username, duration, baseline);
    }
  }

  /**
   * ⚠️ VULNERABLE: BENCHMARK-Based Heavy Query Attack
   */
  async vulnerableBenchmarkAttack(id, iterations = 5000000, context = {}) {
    const startTime = Date.now();
    const baseline = await this.measureBaseline();

    try {
      this.attackStats.totalAttempts++;

      if (iterations > 50000000) {
        this.attackStats.dosAttempts++;
        throw new AppError('Iterations too high - DoS prevention', HTTP_STATUS.BAD_REQUEST);
      }

      const attackDetection = this.detectTimeBasedAttack(`BENCHMARK(${iterations})`);
      
      if (attackDetection.isAttack) {
        await this.logTimeAttack({
          type: 'BENCHMARK_DOS',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { id, iterations },
          patterns: attackDetection.patterns,
          expectedDelay: this.estimateBenchmarkDelay(iterations),
          context
        });

        this.attackStats.dosAttempts++;
      }

      const query = `
        SELECT 
          id, name, email,
          BENCHMARK(${iterations}, SHA1('test')) as benchmark_result
        FROM ${tables.USERS}
        WHERE id = ${id}
        LIMIT 1
      `;

      logger.warn('🚨 BENCHMARK ATTACK DETECTED', {
        query,
        id,
        iterations,
        estimatedDelay: `${this.estimateBenchmarkDelay(iterations)}ms`,
        warning: 'HIGH CPU USAGE EXPECTED'
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      this.attackStats.successfulDelays++;
      this.attackStats.totalDelayTime += duration;

      return {
        success: true,
        vulnerable: true,
        data: results[0] || null,
        timing: {
          executionTime: duration,
          baseline,
          iterations,
          cpuIntensive: true,
          deviation: duration - baseline
        },
        warning: '⚠️  BENCHMARK attack can cause Denial of Service',
        metadata: {
          query,
          attackDetected: attackDetection.isAttack,
          attackType: 'BENCHMARK_DOS'
        }
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      return this.handleTimeError(error, id, duration, baseline);
    }
  }

  /**
   * ⚠️ VULNERABLE: Stacked Time Delays
   */
  async vulnerableStackedDelays(id, delays = [2, 3, 5], context = {}) {
    const startTime = Date.now();
    const baseline = await this.measureBaseline();

    try {
      this.attackStats.totalAttempts++;

      const totalExpectedDelay = delays.reduce((sum, d) => sum + d, 0) * 1000;

      if (totalExpectedDelay > TIMING_THRESHOLDS.MAX_SAFE_DELAY) {
        this.attackStats.dosAttempts++;
        throw new AppError('Total delay too long - DoS prevention', HTTP_STATUS.BAD_REQUEST);
      }

      const attackDetection = this.detectTimeBasedAttack(delays.join(','));
      
      if (attackDetection.isAttack) {
        await this.logTimeAttack({
          type: 'STACKED_TIME_DELAYS',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { id, delays },
          patterns: attackDetection.patterns,
          expectedDelay: totalExpectedDelay,
          context
        });
      }

      const sleepCalls = delays.map(d => `SLEEP(${d})`).join(' OR ');
      const query = `
        SELECT 
          id, name, email,
          (${sleepCalls}) as stacked_delays
        FROM ${tables.USERS}
        WHERE id = ${id}
        LIMIT 1
      `;

      logger.warn('🚨 STACKED TIME DELAYS ATTACK', {
        query,
        id,
        delays,
        totalExpectedDelay: `${totalExpectedDelay}ms`
      });

      const [results] = await db.query(query);
      const duration = Date.now() - startTime;

      this.attackStats.successfulDelays++;
      this.attackStats.totalDelayTime += duration;

      return {
        success: true,
        vulnerable: true,
        data: results[0] || null,
        timing: {
          executionTime: duration,
          baseline,
          expectedDelay: totalExpectedDelay,
          actualDelay: duration - baseline,
          delays,
          deviation: Math.abs(duration - totalExpectedDelay)
        },
        metadata: {
          query,
          attackDetected: attackDetection.isAttack,
          attackType: 'STACKED_DELAYS'
        }
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      return this.handleTimeError(error, id, duration, baseline);
    }
  }

  /**
   * ⚠️ VULNERABLE: Automated Time-Based Password Extraction
   */
  async automatedTimeBasedExtraction(username, delay = 3, context = {}) {
    const startTime = Date.now();

    logger.warn('🚨 AUTOMATED TIME-BASED EXTRACTION STARTED', { 
      username, 
      delayPerCheck: `${delay}s` 
    });

    let passwordLength = 0;
    for (let len = 1; len <= 50; len++) {
      const lengthQuery = `
        SELECT IF(LENGTH(password) = ${len}, SLEEP(${delay}), 0) as result
        FROM ${tables.USERS} WHERE username = '${username}' LIMIT 1
      `;

      const testStart = Date.now();
      try {
        await db.query(lengthQuery);
        const testDuration = Date.now() - testStart;
        
        if (testDuration >= (delay * 1000 - 500)) {
          passwordLength = len;
          logger.info(`✅ Password length found: ${len}`);
          break;
        }
      } catch (error) {
        logger.error('Length discovery error', { len, error: error.message });
      }
    }

    if (passwordLength === 0) {
      return {
        success: false,
        vulnerable: true,
        message: 'Failed to determine password length',
        duration: Date.now() - startTime
      };
    }

    let extractedPassword = '';
    const extractionLog = [];

    for (let pos = 1; pos <= passwordLength; pos++) {
      let found = false;
      let character = '';

      for (let ascii = 32; ascii <= 126; ascii++) {
        const char = String.fromCharCode(ascii);
        
        const result = await this.vulnerableConditionalDelay(
          username,
          pos,
          char,
          delay,
          context
        );

        if (result.matches) {
          character = char;
          found = true;
          logger.info(`✅ Position ${pos}: '${char}' (ASCII ${ascii})`);
          break;
        }
      }

      if (found) {
        extractedPassword += character;
        extractionLog.push({
          position: pos,
          character,
          ascii: character.charCodeAt(0),
          found: true
        });
      } else {
        extractedPassword += '?';
        extractionLog.push({
          position: pos,
          character: '?',
          found: false
        });
      }
    }

    const totalDuration = Date.now() - startTime;
    const successRate = (extractionLog.filter(e => e.found).length / passwordLength * 100).toFixed(2);

    logger.warn('🚨 TIME-BASED EXTRACTION COMPLETED', {
      username,
      passwordLength,
      extractedPassword,
      successRate: `${successRate}%`,
      totalDuration: `${totalDuration}ms`
    });

    this.attackStats.successfulDelays++;

    return {
      success: true,
      vulnerable: true,
      username,
      extractedPassword,
      passwordLength,
      successRate: `${successRate}%`,
      extractionLog,
      delayPerCheck: delay,
      totalDelayTime: passwordLength * delay * 1000,
      duration: totalDuration,
      efficiency: ((totalDuration / (passwordLength * delay * 1000)) * 100).toFixed(2) + '%',
      message: `✅ Password extracted: ${extractedPassword}`,
      metadata: {
        method: 'TIME_BASED_EXTRACTION',
        charactersExtracted: extractionLog.filter(e => e.found).length,
        averageTimePerChar: (totalDuration / passwordLength).toFixed(2) + 'ms'
      }
    };
  }

  // ==========================================================================
  // TIMING UTILITIES
  // ==========================================================================

  /**
   * Measure baseline query execution time
   */
  async measureBaseline() {
    const cachedBaseline = await cache.get('timing_baseline');
    if (cachedBaseline) return cachedBaseline;

    const measurements = [];
    
    for (let i = 0; i < 5; i++) {
      const start = Date.now();
      try {
        await db.execute('SELECT 1');
        measurements.push(Date.now() - start);
      } catch (error) {
        logger.error('Baseline measurement error', { error: error.message });
      }
    }

    const baseline = measurements.length > 0
      ? Math.round(measurements.reduce((a, b) => a + b, 0) / measurements.length)
      : TIMING_THRESHOLDS.BASELINE;

    await cache.set('timing_baseline', baseline, 300);

    this.attackStats.timingBaseline = baseline;
    this.baselineTimes = measurements;

    return baseline;
  }

  /**
   * Calculate confidence level for time-based detection
   */
  calculateConfidence(actual, baseline, expected) {
    const deviation = Math.abs((actual - baseline) - expected);
    const tolerance = expected * 0.1;

    if (deviation < tolerance) return 'HIGH';
    if (deviation < tolerance * 2) return 'MEDIUM';
    if (deviation < tolerance * 3) return 'LOW';
    return 'VERY_LOW';
  }

  /**
   * Estimate BENCHMARK delay
   */
  estimateBenchmarkDelay(iterations) {
    return Math.round(iterations / 50);
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Parameterized Query with Timeout Protection
   */
  async secureValidation(username) {
    const startTime = Date.now();

    try {
      if (typeof username !== 'string' || username.length > 50) {
        throw new AppError('Invalid username', HTTP_STATUS.BAD_REQUEST);
      }

      const query = `
        SELECT id, username, email, is_active
        FROM ${tables.USERS}
        WHERE username = ?
        AND deleted_at IS NULL
        LIMIT 1
      `;

      const connection = await db.pool.getConnection();
      await connection.query('SET SESSION MAX_EXECUTION_TIME=1000');
      
      const [results] = await connection.execute(query, [username]);
      connection.release();

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: results[0] || null,
        metadata: {
          executionTime: duration,
          method: 'PARAMETERIZED_WITH_TIMEOUT',
          maxExecutionTime: '1000ms'
        }
      };

    } catch (error) {
      logger.error('Secure validation error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect time-based SQL injection patterns
   */
  detectTimeBasedAttack(input) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;
    let expectedDelay = 0;

    for (const [category, patterns] of Object.entries(TIME_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(input)) {
          detectedPatterns.push({
            category,
            pattern: pattern.toString(),
            matched: true
          });
          score += this.getPatternScore(category);

          if (category === 'MYSQL_SLEEP' || category === 'BENCHMARK') {
            severity = ATTACK_SEVERITY.CRITICAL;
          } else if (category !== 'HEAVY_QUERY' && severity !== ATTACK_SEVERITY.CRITICAL) {
            severity = ATTACK_SEVERITY.HIGH;
          }
        }
      }
    }

    const sleepMatch = input.match(/SLEEP\s*\(\s*(\d+)\s*\)/i);
    if (sleepMatch) {
      expectedDelay = parseInt(sleepMatch[1], 10) * 1000;
    }

    const benchmarkMatch = input.match(/BENCHMARK\s*\(\s*(\d+)/i);
    if (benchmarkMatch) {
      const iterations = parseInt(benchmarkMatch[1], 10);
      expectedDelay = this.estimateBenchmarkDelay(iterations);
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
      expectedDelay,
      input: input.substring(0, 200),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Log time-based attack attempt
   */
  async logTimeAttack(attackData) {
    try {
      const {
        type,
        severity,
        payload,
        patterns,
        expectedDelay,
        context,
        timestamp = new Date()
      } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          metadata, timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          type,
          severity,
          JSON.stringify(payload),
          JSON.stringify(patterns),
          context.ip || null,
          context.userAgent || null,
          context.userId || null,
          context.endpoint || null,
          JSON.stringify({ expectedDelay }),
          timestamp
        ]
      );

      logger.attack('Time-Based SQL Injection Attack Detected', {
        type,
        severity,
        payload,
        expectedDelay: `${expectedDelay}ms`,
        patterns: patterns.map(p => p.category),
        context
      });

    } catch (error) {
      logger.error('Failed to log time attack', { error: error.message });
    }
  }

  /**
   * Handle time-based query errors
   */
  handleTimeError(error, input, duration, baseline) {
    logger.error('Time-Based SQL Injection Error', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      input,
      duration,
      baseline,
      deviation: duration - baseline
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        errno: error.errno
      },
      timing: {
        executionTime: duration,
        baseline,
        deviation: duration - baseline
      },
      metadata: {
        errorType: 'TIME_BASED_QUERY_ERROR'
      }
    };
  }

  /**
   * Get pattern severity score
   */
  getPatternScore(category) {
    const scores = {
      MYSQL_SLEEP: 15,
      BENCHMARK: 15,
      SQLSERVER_WAITFOR: 15,
      POSTGRESQL_SLEEP: 15,
      ORACLE_SLEEP: 15,
      HEAVY_QUERY: 8
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
      averageDelayTime: this.attackStats.successfulDelays > 0
        ? (this.attackStats.totalDelayTime / this.attackStats.successfulDelays).toFixed(2) + 'ms'
        : '0ms',
      successRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulDelays / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
        : '0%',
      baselineTimes: this.baselineTimes
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
      description: 'Time-Based Blind SQL Injection uses database delay functions to infer information through response timing variations',
      impact: [
        'Data extraction through timing analysis',
        'Database enumeration',
        'Credential harvesting',
        'Denial of Service (through excessive delays)',
        'Resource exhaustion',
        'Slow but reliable data exfiltration'
      ],
      attackComplexity: 'High - requires precise timing measurements',
      detectionDifficulty: 'Medium - unusual response times can be detected',
      dosRisk: 'HIGH - can easily cause service degradation',
      remediation: [
        'Use parameterized queries',
        'Implement query timeouts',
        'Monitor for unusual response times',
        'Rate limit requests',
        'Disable dangerous functions (SLEEP, BENCHMARK)',
        'Use database security modules',
        'Implement Web Application Firewall (WAF)',
        'Regular performance monitoring'
      ]
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulDelays: 0,
      totalDelayTime: 0,
      averageDelayTime: 0,
      characterExtractions: 0,
      dosAttempts: 0,
      timingBaseline: TIMING_THRESHOLDS.BASELINE
    };
    this.baselineTimes = [];
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getTimeBasedSQLInjection = () => {
  if (!instance) {
    instance = new TimeBasedSQLInjection();
  }
  return instance;
};

export const createTimeBasedHandler = (method) => {
  return async (req, res, next) => {
    try {
      const sqli = getTimeBasedSQLInjection();
      
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
  TimeBasedSQLInjection,
  getTimeBasedSQLInjection,
  createTimeBasedHandler
};
