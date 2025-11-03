/**
 * ============================================================================
 * STORED XSS (PERSISTENT XSS) VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade Stored XSS Demonstration Platform
 * Implements persistent Cross-Site Scripting vulnerabilities
 * 
 * @module vulnerabilities/xss/stored
 * @category Security Training - OWASP A03:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates Stored XSS vulnerabilities:
 * - Persistent script injection in database
 * - User-generated content attacks
 * - Comment/review XSS
 * - Profile field XSS
 * - File upload XSS (SVG, HTML)
 * - Markdown/Rich text XSS
 * - JSON/API response XSS
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to session hijacking and account takeover
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Basic Stored XSS - <script>alert(1)</script>
 * 2. Event Handler XSS - <img src=x onerror=alert(1)>
 * 3. SVG XSS - <svg onload=alert(1)>
 * 4. HTML Entity Encoding Bypass
 * 5. JavaScript Protocol - <a href="javascript:alert(1)">
 * 6. Data URI XSS - <iframe src="data:text/html,<script>alert(1)</script>">
 * 7. DOM-based Stored XSS
 * 8. Mutation XSS (mXSS)
 * 9. CSS Injection
 * 10. Polyglot XSS
 * 
 * @requires Database
 * @requires Logger
 * @requires sanitize-html
 */

import sanitizeHtml from 'sanitize-html';
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
// STORED XSS CONSTANTS
// ============================================================================

const XSS_PATTERNS = {
  // Script tags
  SCRIPT_TAGS: [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /<script[^>]*>[\s\S]*?<\/script>/gi,
    /<script\s*>/gi,
  ],

  // Event handlers
  EVENT_HANDLERS: [
    /on\w+\s*=\s*["'][^"']*["']/gi,
    /on\w+\s*=\s*[^\s>]*/gi,
    /onerror\s*=/gi,
    /onload\s*=/gi,
    /onclick\s*=/gi,
    /onmouseover\s*=/gi,
  ],

  // JavaScript protocols
  JS_PROTOCOL: [
    /javascript:/gi,
    /vbscript:/gi,
    /data:text\/html/gi,
  ],

  // Dangerous tags
  DANGEROUS_TAGS: [
    /<iframe/gi,
    /<embed/gi,
    /<object/gi,
    /<svg/gi,
    /<math/gi,
    /<link/gi,
    /<meta/gi,
    /<base/gi,
  ],

  // HTML entities
  HTML_ENTITIES: [
    /&lt;script/gi,
    /&lt;iframe/gi,
    /&#x3c;script/gi,
    /&#60;script/gi,
  ],

  // CSS injection
  CSS_INJECTION: [
    /expression\s*\(/gi,
    /import\s*["'][^"']*["']/gi,
    /behavior:\s*url/gi,
    /@import/gi,
  ],

  // Polyglot patterns
  POLYGLOT: [
    /jaVasCript:/gi,
    /\u0000/g,
    /\u0001/g,
  ],
};

const COMMON_XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<iframe src="javascript:alert(1)">',
  '<body onload=alert(1)>',
  '<input onfocus=alert(1) autofocus>',
  '<marquee onstart=alert(1)>',
  '<details open ontoggle=alert(1)>',
  '"><script>alert(String.fromCharCode(88,83,83))</script>',
  '<img src=x:alert(alt) onerror=eval(src) alt=xss>',
];

// ============================================================================
// STORED XSS CLASS
// ============================================================================

export class StoredXSS {
  constructor() {
    this.name = 'Stored XSS (Persistent XSS)';
    this.category = 'Cross-Site Scripting';
    this.cvssScore = 8.8;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A03:2021';
    this.cweId = 'CWE-79';
    
    this.attackStats = {
      totalAttempts: 0,
      storedPayloads: 0,
      commentXSS: 0,
      profileXSS: 0,
      reviewXSS: 0,
      fileUploadXSS: 0,
      successfulInjections: 0,
      victimViews: 0,
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Store Comment Without Sanitization
   * 
   * Attack: <script>alert(document.cookie)</script>
   * 
   * @param {string} content - Comment content (VULNERABLE)
   * @param {number} userId - User ID
   * @param {number} productId - Product ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Stored comment
   */
  async vulnerableStoreComment(content, userId, productId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.commentXSS++;

      const attackDetection = this.detectXSS(content);
      
      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'STORED_XSS_COMMENT',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { content: content.substring(0, 500), productId },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.storedPayloads++;
      }

      logger.warn('🚨 STORING UNSANITIZED COMMENT', {
        productId,
        contentLength: content.length,
        attackDetected: attackDetection.isAttack,
      });

      // ⚠️ VULNERABLE: Store raw content without sanitization
      const [result] = await db.execute(
        `INSERT INTO comments (user_id, product_id, content, created_at)
         VALUES (?, ?, ?, NOW())`,
        [userId, productId, content]
      );

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        commentId: result.insertId,
        content,
        warning: '⚠️ Content stored without sanitization - XSS payload will execute on retrieval',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleXSSError(error, 'comment', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Retrieve and Display Comment
   * 
   * @param {number} commentId - Comment ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Comment with XSS payload
   */
  async vulnerableRetrieveComment(commentId, context = {}) {
    const startTime = Date.now();

    try {
      const [comments] = await db.execute(
        `SELECT c.id, c.content, c.created_at, u.username 
         FROM comments c
         JOIN ${tables.USERS} u ON c.user_id = u.id
         WHERE c.id = ?`,
        [commentId]
      );

      if (comments.length === 0) {
        throw new AppError('Comment not found', HTTP_STATUS.NOT_FOUND);
      }

      const comment = comments[0];
      const attackDetection = this.detectXSS(comment.content);

      if (attackDetection.isAttack) {
        logger.warn('🚨 SERVING XSS PAYLOAD', {
          commentId,
          victimIP: context.ip,
        });

        this.attackStats.victimViews++;

        await this.logXSSAttack({
          type: 'STORED_XSS_EXECUTED',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { commentId, content: comment.content.substring(0, 200) },
          patterns: attackDetection.patterns,
          context,
        });
      }

      // ⚠️ VULNERABLE: Return unsanitized content
      return {
        success: true,
        vulnerable: true,
        comment: {
          id: comment.id,
          content: comment.content, // XSS payload here
          username: comment.username,
          createdAt: comment.created_at,
        },
        warning: attackDetection.isAttack ? '⚠️ XSS payload being served to victim' : null,
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleXSSError(error, commentId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: User Profile with XSS
   * 
   * Attack: Inject XSS in bio, website, or other fields
   * 
   * @param {number} userId - User ID
   * @param {object} profileData - Profile data (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Updated profile
   */
  async vulnerableUpdateProfile(userId, profileData, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.profileXSS++;

      const { bio, website, location, occupation } = profileData;
      const combinedContent = `${bio} ${website} ${location} ${occupation}`;
      const attackDetection = this.detectXSS(combinedContent);

      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'STORED_XSS_PROFILE',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { userId, profileData },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.storedPayloads++;
      }

      logger.warn('🚨 UPDATING PROFILE WITH UNSANITIZED DATA', {
        userId,
        attackDetected: attackDetection.isAttack,
      });

      // ⚠️ VULNERABLE: Store without sanitization
      await db.execute(
        `UPDATE ${tables.USERS} 
         SET bio = ?, website = ?, location = ?, occupation = ?, updated_at = NOW()
         WHERE id = ?`,
        [bio, website, location, occupation, userId]
      );

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        userId,
        profileData,
        warning: '⚠️ Profile fields stored without sanitization',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleXSSError(error, userId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Product Review with XSS
   * 
   * @param {number} productId - Product ID
   * @param {number} userId - User ID
   * @param {string} title - Review title (VULNERABLE)
   * @param {string} content - Review content (VULNERABLE)
   * @param {number} rating - Rating
   * @param {object} context - Request context
   * @returns {Promise<object>} Stored review
   */
  async vulnerableStoreReview(productId, userId, title, content, rating, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.reviewXSS++;

      const combinedContent = `${title} ${content}`;
      const attackDetection = this.detectXSS(combinedContent);

      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'STORED_XSS_REVIEW',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { productId, title, content: content.substring(0, 200) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.storedPayloads++;
      }

      logger.warn('🚨 STORING REVIEW WITH XSS', {
        productId,
        userId,
        attackDetected: attackDetection.isAttack,
      });

      // ⚠️ VULNERABLE: Store unsanitized review
      const [result] = await db.execute(
        `INSERT INTO ${tables.REVIEWS} (product_id, user_id, title, content, rating, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())`,
        [productId, userId, title, content, rating]
      );

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        reviewId: result.insertId,
        title,
        content,
        warning: '⚠️ Review stored without sanitization',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleXSSError(error, 'review', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: SVG File Upload with XSS
   * 
   * Attack: Upload SVG with embedded JavaScript
   * 
   * @param {string} svgContent - SVG file content (VULNERABLE)
   * @param {string} filename - Original filename
   * @param {number} userId - User ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Upload result
   */
  async vulnerableSVGUpload(svgContent, filename, userId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.fileUploadXSS++;

      const attackDetection = this.detectXSS(svgContent);

      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'STORED_XSS_SVG_UPLOAD',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { filename, contentPreview: svgContent.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.storedPayloads++;
      }

      logger.warn('🚨 SVG UPLOAD WITH XSS PAYLOAD', {
        filename,
        userId,
        attackDetected: attackDetection.isAttack,
      });

      // ⚠️ VULNERABLE: Store SVG without sanitization
      const uploadPath = `/uploads/svg/${Date.now()}_${filename}`;

      // Simulate file storage
      const [result] = await db.execute(
        `INSERT INTO uploads (user_id, filename, filepath, content_type, content, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())`,
        [userId, filename, uploadPath, 'image/svg+xml', svgContent]
      );

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        uploadId: result.insertId,
        uploadPath,
        filename,
        warning: '⚠️ SVG uploaded without sanitization - JavaScript will execute when viewed',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleXSSError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Rich Text / Markdown with XSS
   * 
   * Attack: Inject XSS through markdown or HTML
   * 
   * @param {string} markdown - Markdown content (VULNERABLE)
   * @param {number} userId - User ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Processed markdown
   */
  async vulnerableMarkdownProcessing(markdown, userId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const attackDetection = this.detectXSS(markdown);

      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'STORED_XSS_MARKDOWN',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { markdown: markdown.substring(0, 500) },
          patterns: attackDetection.patterns,
          context,
        });

        this.attackStats.storedPayloads++;
      }

      logger.warn('🚨 MARKDOWN WITH XSS', {
        userId,
        attackDetected: attackDetection.isAttack,
      });

      // ⚠️ VULNERABLE: Allow raw HTML in markdown
      // Simplified markdown to HTML conversion (vulnerable)
      const html = markdown
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2">$1</a>');

      if (attackDetection.isAttack) {
        this.attackStats.successfulInjections++;
      }

      return {
        success: true,
        vulnerable: true,
        markdown,
        html,
        warning: '⚠️ Markdown allows raw HTML - XSS possible',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleXSSError(error, 'markdown', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: JSON API Response with XSS
   * 
   * Attack: Store XSS in API data that's rendered client-side
   * 
   * @param {object} data - Data object (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} API response
   */
  async vulnerableJSONResponse(data, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;

      const jsonString = JSON.stringify(data);
      const attackDetection = this.detectXSS(jsonString);

      if (attackDetection.isAttack) {
        await this.logXSSAttack({
          type: 'STORED_XSS_JSON_API',
          severity: ATTACK_SEVERITY.MEDIUM,
          payload: { data },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 JSON API RESPONSE WITH XSS', {
        attackDetected: attackDetection.isAttack,
      });

      // ⚠️ VULNERABLE: Return unsanitized data in JSON
      return {
        success: true,
        vulnerable: true,
        data, // Contains XSS payload
        warning: '⚠️ JSON contains unsanitized data - XSS if rendered in DOM',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleXSSError(error, 'json', Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Store Comment with Sanitization
   */
  async secureStoreComment(content, userId, productId) {
    const startTime = Date.now();

    try {
      // ✅ Validate input length
      if (typeof content !== 'string' || content.length > 5000) {
        throw new AppError('Invalid comment content', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Detect XSS attempts
      const attackDetection = this.detectXSS(content);
      if (attackDetection.isAttack) {
        logger.warn('XSS attempt blocked in comment', { userId, productId });
        throw new AppError('Invalid content detected', HTTP_STATUS.BAD_REQUEST);
      }

      // ✅ Sanitize content
      const sanitized = this.sanitizeHTML(content);

      // Store sanitized content
      const [result] = await db.execute(
        `INSERT INTO comments (user_id, product_id, content, created_at)
         VALUES (?, ?, ?, NOW())`,
        [userId, productId, sanitized]
      );

      return {
        success: true,
        vulnerable: false,
        commentId: result.insertId,
        content: sanitized,
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_SANITIZATION',
        },
      };

    } catch (error) {
      logger.error('Secure comment storage error', { error: error.message });
      throw error;
    }
  }

  /**
   * HTML Sanitization
   */
  sanitizeHTML(input) {
    return sanitizeHtml(input, {
      allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
      allowedAttributes: {},
      allowedSchemes: ['http', 'https', 'mailto'],
      disallowedTagsMode: 'escape',
    });
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect XSS patterns
   */
  detectXSS(input) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;

    // Check script tags
    for (const pattern of XSS_PATTERNS.SCRIPT_TAGS) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'SCRIPT_TAG',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 20;
        severity = ATTACK_SEVERITY.HIGH;
      }
    }

    // Check event handlers
    for (const pattern of XSS_PATTERNS.EVENT_HANDLERS) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'EVENT_HANDLER',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 15;
        severity = ATTACK_SEVERITY.HIGH;
      }
    }

    // Check JavaScript protocols
    for (const pattern of XSS_PATTERNS.JS_PROTOCOL) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'JS_PROTOCOL',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 18;
        severity = ATTACK_SEVERITY.HIGH;
      }
    }

    // Check dangerous tags
    for (const pattern of XSS_PATTERNS.DANGEROUS_TAGS) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'DANGEROUS_TAG',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 12;
      }
    }

    // Check CSS injection
    for (const pattern of XSS_PATTERNS.CSS_INJECTION) {
      if (pattern.test(input)) {
        detectedPatterns.push({
          category: 'CSS_INJECTION',
          pattern: pattern.toString(),
          matched: true,
        });
        score += 10;
      }
    }

    // Check common payloads
    for (const payload of COMMON_XSS_PAYLOADS) {
      if (input.toLowerCase().includes(payload.toLowerCase())) {
        detectedPatterns.push({
          category: 'KNOWN_PAYLOAD',
          payload: payload.substring(0, 50),
          matched: true,
        });
        score += 25;
        severity = ATTACK_SEVERITY.CRITICAL;
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
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log XSS attack
   */
  async logXSSAttack(attackData) {
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

      logger.attack('Stored XSS Attack Detected', {
        type,
        severity,
        payload,
        patterns: patterns.map(p => p.category),
        context,
      });

    } catch (error) {
      logger.error('Failed to log XSS attack', { error: error.message });
    }
  }

  /**
   * Handle XSS errors
   */
  handleXSSError(error, identifier, duration) {
    logger.error('Stored XSS Error', {
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
        errorType: 'STORED_XSS_ERROR',
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
      injectionRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.successfulInjections / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
        : '0%',
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
      description: 'Stored XSS persists malicious scripts in the database, executing whenever users view the infected data',
      impact: [
        'Session hijacking (cookie theft)',
        'Account takeover',
        'Keylogging',
        'Phishing',
        'Malware distribution',
        'Defacement',
        'Credential theft',
        'Social engineering',
      ],
      commonTargets: [
        'Comment sections',
        'User profiles',
        'Product reviews',
        'Forum posts',
        'Chat messages',
        'File uploads (SVG, HTML)',
        'Rich text editors',
        'User-generated content',
      ],
      remediation: [
        'HTML encode all user input on output',
        'Use Content Security Policy (CSP)',
        'Sanitize HTML using allowlist',
        'Validate input on server-side',
        'Escape special characters',
        'Use HTTPOnly cookies',
        'Implement proper output encoding',
        'Regular security audits',
      ],
      references: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        'CWE-79: Improper Neutralization of Input During Web Page Generation',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      storedPayloads: 0,
      commentXSS: 0,
      profileXSS: 0,
      reviewXSS: 0,
      fileUploadXSS: 0,
      successfulInjections: 0,
      victimViews: 0,
    };
  }

  /**
   * Get common XSS payloads
   */
  getCommonPayloads() {
    return COMMON_XSS_PAYLOADS;
  }

  /**
   * Get XSS test cases
   */
  getTestCases() {
    return {
      basic: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
      ],
      advanced: [
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x:alert(alt) onerror=eval(src) alt=xss>',
        '<svg><animatetransform onbegin=alert(1)>',
      ],
      evasion: [
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img src="x" onerror="alert(1)">',
        '<iframe src="javascript:alert(1)">',
      ],
      encoded: [
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
      ],
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getStoredXSS = () => {
  if (!instance) {
    instance = new StoredXSS();
  }
  return instance;
};

export const createStoredXSSHandler = (method) => {
  return async (req, res, next) => {
    try {
      const xss = getStoredXSS();
      
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
  StoredXSS,
  getStoredXSS,
  createStoredXSSHandler,
};
