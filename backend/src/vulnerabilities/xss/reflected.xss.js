/**
 * ============================================================================
 * REFLECTED XSS (NON-PERSISTENT XSS) VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Reflected XSS Demonstration Platform
 * Implements non-persistent Cross-Site Scripting vulnerabilities
 * 
 * @module vulnerabilities/xss/reflected
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates Reflected XSS vulnerabilities:
 * - URL parameter reflection
 * - Search query XSS
 * - Error message XSS
 * - Form input reflection
 * - HTTP header reflection
 * - Referrer-based XSS
 * 
 * ⚠️  FOR EDUCATIONAL PURPOSES ONLY
 * 
 * ATTACK TYPES:
 * 1. URL Parameter XSS - ?search=<script>alert(1)</script>
 * 2. POST Data Reflection
 * 3. HTTP Header XSS (User-Agent, Referer)
 * 4. Error Message XSS
 * 5. Search Results XSS
 * 6. Redirect URL XSS
 * 
 * @requires Database
 * @requires Logger
 */

import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import { HTTP_STATUS, ATTACK_SEVERITY, ERROR_CODES } from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

export class ReflectedXSS {
  constructor() {
    this.name = 'Reflected XSS';
    this.category = 'Cross-Site Scripting';
    this.cvssScore = 7.1;
    this.severity = ATTACK_SEVERITY.MEDIUM;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-79';
    
    this.attackStats = {
      totalAttempts: 0,
      urlParameterXSS: 0,
      searchXSS: 0,
      errorMessageXSS: 0,
      headerXSS: 0,
      successfulReflections: 0,
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Search Functionality with Reflection
   */
  async vulnerableSearch(searchTerm, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.searchXSS++;

      const attackDetection = this.detectXSS(searchTerm);
      
      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'REFLECTED_XSS_SEARCH',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { searchTerm },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 REFLECTED XSS IN SEARCH', { searchTerm });

      // Simulate search
      const [results] = await db.execute(
        `SELECT id, name, description FROM ${tables.PRODUCTS}
         WHERE name LIKE ? OR description LIKE ?
         LIMIT 10`,
        [`%${searchTerm}%`, `%${searchTerm}%`]
      );

      if (attackDetection.isAttack) {
        this.attackStats.successfulReflections++;
      }

      // ⚠️ VULNERABLE: Reflect search term in response
      return {
        success: true,
        vulnerable: true,
        searchTerm, // XSS payload reflected here
        resultsCount: results.length,
        results,
        message: `Search results for: ${searchTerm}`,
        warning: '⚠️ Search term reflected without encoding',
        attackInfo: attackDetection,
        metadata: { executionTime: Date.now() - startTime },
      };

    } catch (error) {
      return this.handleXSSError(error, searchTerm, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Error Message with User Input
   */
  async vulnerableErrorMessage(errorParam, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.errorMessageXSS++;

      const attackDetection = this.detectXSS(errorParam);
      
      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'REFLECTED_XSS_ERROR',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { errorParam },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.successfulReflections++;
      }

      logger.warn('🚨 REFLECTED XSS IN ERROR MESSAGE', { errorParam });

      // ⚠️ VULNERABLE: Include user input in error message
      return {
        success: false,
        vulnerable: true,
        error: `Invalid parameter: ${errorParam}`,
        errorCode: 'INVALID_INPUT',
        parameter: errorParam,
        warning: '⚠️ User input reflected in error message',
        attackInfo: attackDetection,
        metadata: { executionTime: Date.now() - startTime },
      };

    } catch (error) {
      return this.handleXSSError(error, errorParam, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: URL Redirect with Parameter
   */
  async vulnerableRedirect(redirectUrl, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectXSS(redirectUrl);
      
      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'REFLECTED_XSS_REDIRECT',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { redirectUrl },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 REFLECTED XSS IN REDIRECT', { redirectUrl });

      // ⚠️ VULNERABLE: Reflect redirect URL
      return {
        success: true,
        vulnerable: true,
        redirectUrl,
        message: `Redirecting to: ${redirectUrl}`,
        warning: '⚠️ Redirect URL reflected without validation',
        attackInfo: attackDetection,
        metadata: { executionTime: Date.now() - startTime },
      };

    } catch (error) {
      return this.handleXSSError(error, redirectUrl, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: User-Agent Reflection
   */
  async vulnerableUserAgentReflection(context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.headerXSS++;

      const userAgent = context.userAgent || 'Unknown';
      const attackDetection = this.detectXSS(userAgent);
      
      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'REFLECTED_XSS_USER_AGENT',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { userAgent },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.successfulReflections++;
      }

      logger.warn('🚨 REFLECTED XSS IN USER-AGENT', { userAgent });

      // ⚠️ VULNERABLE: Reflect User-Agent header
      return {
        success: true,
        vulnerable: true,
        message: `Your browser: ${userAgent}`,
        userAgent,
        warning: '⚠️ User-Agent header reflected without encoding',
        attackInfo: attackDetection,
        metadata: { executionTime: Date.now() - startTime },
      };

    } catch (error) {
      return this.handleXSSError(error, 'user-agent', Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ✅ SECURE: Search with Output Encoding
   */
  async secureSearch(searchTerm, context) {
    const startTime = Date.now();

    try {
      if (typeof searchTerm !== 'string' || searchTerm.length > 100) {
        throw new AppError('Invalid search term', HTTP_STATUS.BAD_REQUEST);
      }

      const attackDetection = this.detectXSS(searchTerm);
      if (attackDetection.isAttack) {
        logger.warn('XSS attempt blocked in search', { searchTerm });
        throw new AppError('Invalid search term', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ HTML encode output
      const encodedSearchTerm = this.htmlEncode(searchTerm);

      const [results] = await db.execute(
        `SELECT id, name, description FROM ${tables.PRODUCTS}
         WHERE name LIKE ? OR description LIKE ?
         LIMIT 10`,
        [`%${searchTerm}%`, `%${searchTerm}%`]
      );

      return {
        success: true,
        vulnerable: false,
        searchTerm: encodedSearchTerm,
        resultsCount: results.length,
        results,
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'HTML_ENCODED_OUTPUT',
        },
      };

    } catch (error) {
      logger.error('Secure search error', { error: error.message });
      throw error;
    }
  }

  /**
   * HTML encode special characters
   */
  htmlEncode(str) {
    const entityMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
    };
    return String(str).replace(/[&<>"'/]/g, s => entityMap[s]);
  }

  // ==========================================================================
  // DETECTION & LOGGING
  // ==========================================================================

  detectXSS(input) {
    const patterns = [
      /<script/gi,
      /onerror\s*=/gi,
      /onload\s*=/gi,
      /javascript:/gi,
      /<iframe/gi,
      /<svg/gi,
    ];

    const detectedPatterns = [];
    let score = 0;

    for (const pattern of patterns) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'XSS_PATTERN',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 10;
      }
    }

    return {
      isAttack: detectedPatterns.length > 0,
      severity: score >= 20 ? ATTACK_SEVERITY.HIGH : ATTACK_SEVERITY.MEDIUM,
      score,
      patterns: detectedPatterns,
      input: input.substring(0, 200),
      timestamp: new Date().toISOString(),
    };
  }

  async logXSSAttack(attackData) {
    try {
      const { type, severity, payload, patterns, context, timestamp = new Date() } = attackData;

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

      logger.attack('Reflected XSS Attack Detected', {
        type,
        severity,
        payload,
        context,
      });

    } catch (error) {
      logger.error('Failed to log XSS attack', { error: error.message });
    }
  }

  handleXSSError(error, identifier, duration) {
    logger.error('Reflected XSS Error', { message: error.message, identifier, duration });
    return {
      success: false,
      vulnerable: true,
      error: { message: error.message, code: error.code },
      metadata: { executionTime: duration, errorType: 'REFLECTED_XSS_ERROR' },
    };
  }

  // ==========================================================================
  // UTILITY & REPORTING
  // ==========================================================================

  getStatistics() {
    return {
      ...this.attackStats,
      reflectionRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulReflections / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
        : '0%',
    };
  }

  getVulnerabilityInfo() {
    return {
      name: this.name,
      category: this.category,
      cvssScore: this.cvssScore,
      severity: this.severity,
      owaspId: this.owaspId,
      cweId: this.cweId,
      description: 'Reflected XSS occurs when user input is immediately returned in the response without proper encoding',
      impact: [
        'Session hijacking',
        'Phishing',
        'Credential theft',
        'Malware distribution',
        'Keylogging',
      ],
      remediation: [
        'HTML encode all output',
        'Use Content Security Policy',
        'Validate input',
        'Use framework escaping',
        'HTTPOnly cookies',
      ],
      references: [
        'https://owasp.org/www-community/attacks/xss/',
        'CWE-79',
      ],
    };
  }

  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      urlParameterXSS: 0,
      searchXSS: 0,
      errorMessageXSS: 0,
      headerXSS: 0,
      successfulReflections: 0,
    };
  }
}

let instance = null;

export const getReflectedXSS = () => {
  if (!instance) {
    instance = new ReflectedXSS();
  }
  return instance;
};

export const createReflectedXSSHandler = (method) => {
  return async (req, res, next) => {
    try {
      const xss = getReflectedXSS();
      
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
      const result = await xss[method](...Object.values(params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  ReflectedXSS,
  getReflectedXSS,
  createReflectedXSSHandler,
};
