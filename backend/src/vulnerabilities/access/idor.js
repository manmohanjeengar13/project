/**
 * ============================================================================
 * IDOR (INSECURE DIRECT OBJECT REFERENCE) VULNERABILITY MODULE
 * ============================================================================
 * 
 * Enterprise-Grade IDOR Demonstration Platform
 * Implements access control bypass through direct object references
 * 
 * @module vulnerabilities/access/idor
 * @category Security Training - OWASP A01:2021
 * @version 3.0.0
 * @license MIT
 * @author Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING:
 * ============================================================================
 * This module demonstrates IDOR vulnerabilities:
 * - Sequential ID enumeration
 * - UUID/GUID exposure
 * - Filename predictability
 * - API endpoint parameter manipulation
 * - Missing authorization checks
 * - Horizontal privilege escalation
 * - Vertical privilege escalation
 * 
 * ⚠️  NEVER use these patterns in production code
 * ⚠️  FOR EDUCATIONAL AND TESTING PURPOSES ONLY
 * ⚠️  Can lead to unauthorized data access
 * 
 * ============================================================================
 * ATTACK TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Sequential ID Enumeration - /api/users/1, /api/users/2, etc.
 * 2. Order/Invoice Access - /api/orders/123
 * 3. File Download IDOR - /api/files/document.pdf
 * 4. Profile Access - /api/profiles/user123
 * 5. Message/Email Access - /api/messages/456
 * 6. Document Access - /api/documents/789
 * 7. Account Settings IDOR - /api/settings/account/10
 * 8. Payment Information IDOR - /api/payments/card/20
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
  ERROR_CODES,
  USER_ROLES 
} from '../../config/constants.js';
import { AppError } from '../../middleware/errorHandler.js';
import crypto from 'crypto';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// IDOR CONSTANTS
// ============================================================================

const IDOR_CONFIG = {
  // Detection thresholds
  ENUMERATION_THRESHOLD: 10,        // Sequential access attempts
  ENUMERATION_WINDOW: 60000,        // 1 minute window
  
  // ID formats
  SEQUENTIAL_ID_PATTERN: /^\d+$/,
  UUID_PATTERN: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  
  // Resource types
  SENSITIVE_RESOURCES: [
    'orders', 'invoices', 'payments', 'messages', 
    'documents', 'files', 'profiles', 'settings'
  ],
};

// ============================================================================
// IDOR CLASS
// ============================================================================

export class IDOR {
  constructor() {
    this.name = 'Insecure Direct Object Reference (IDOR)';
    this.category = 'Access Control';
    this.cvssScore = 8.2;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A01:2021';
    this.cweId = 'CWE-639';
    
    this.attackStats = {
      totalAttempts: 0,
      userDataAccess: 0,
      orderAccess: 0,
      fileAccess: 0,
      messageAccess: 0,
      documentAccess: 0,
      enumerationAttempts: 0,
      unauthorizedAccess: 0,
      horizontalEscalation: 0,
      verticalEscalation: 0,
    };
    
    // Track enumeration patterns
    this.enumerationTracking = new Map();
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: User Profile Access Without Authorization
   * 
   * Attack: /api/users/1, /api/users/2, etc.
   * 
   * @param {number} userId - User ID (VULNERABLE)
   * @param {number} requestingUserId - Current user ID
   * @param {object} context - Request context
   * @returns {Promise<object>} User profile data
   */
  async vulnerableGetUserProfile(userId, requestingUserId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.userDataAccess++;

      const attackDetection = this.detectIDORAttempt(userId, requestingUserId, 'user', context);
      
      if (attackDetection.isAttack) {
        await this.logIDORAttack({
          type: 'IDOR_USER_PROFILE',
          severity: attackDetection.severity,
          payload: { targetUserId: userId, requestingUserId },
          patterns: attackDetection.patterns,
          context,
        });

        if (userId !== requestingUserId) {
          this.attackStats.unauthorizedAccess++;
          this.attackStats.horizontalEscalation++;
        }
      }

      logger.warn('🚨 IDOR: User Profile Access', {
        targetUserId: userId,
        requestingUserId,
        unauthorized: userId !== requestingUserId,
      });

      // ⚠️ VULNERABLE: No authorization check
      const [users] = await db.execute(
        `SELECT id, username, email, phone, address, bio, website, 
                date_of_birth, created_at, last_login
         FROM ${tables.USERS}
         WHERE id = ? AND deleted_at IS NULL`,
        [userId]
      );

      if (users.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'User not found',
        };
      }

      const user = users[0];

      return {
        success: true,
        vulnerable: true,
        user,
        warning: '⚠️ No authorization check - any authenticated user can access any profile',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
          accessType: userId === requestingUserId ? 'own_profile' : 'other_user_profile',
        },
      };

    } catch (error) {
      return this.handleIDORError(error, userId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Order Access Without Ownership Check
   * 
   * Attack: /api/orders/123 - Access other users' orders
   * 
   * @param {number} orderId - Order ID (VULNERABLE)
   * @param {number} requestingUserId - Current user ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Order details
   */
  async vulnerableGetOrder(orderId, requestingUserId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.orderAccess++;

      const attackDetection = this.detectIDORAttempt(orderId, requestingUserId, 'order', context);
      
      if (attackDetection.isAttack) {
        await this.logIDORAttack({
          type: 'IDOR_ORDER_ACCESS',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { orderId, requestingUserId },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 IDOR: Order Access', {
        orderId,
        requestingUserId,
      });

      // ⚠️ VULNERABLE: Fetch order without checking ownership
      const [orders] = await db.execute(
        `SELECT o.*, u.username, u.email,
                COUNT(oi.id) as item_count
         FROM ${tables.ORDERS} o
         JOIN ${tables.USERS} u ON o.user_id = u.id
         LEFT JOIN order_items oi ON o.id = oi.order_id
         WHERE o.id = ?
         GROUP BY o.id`,
        [orderId]
      );

      if (orders.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Order not found',
        };
      }

      const order = orders[0];
      const isOwnOrder = order.user_id === requestingUserId;

      if (!isOwnOrder) {
        this.attackStats.unauthorizedAccess++;
        this.attackStats.horizontalEscalation++;
      }

      // Get order items
      const [items] = await db.execute(
        `SELECT oi.*, p.name as product_name
         FROM order_items oi
         JOIN ${tables.PRODUCTS} p ON oi.product_id = p.id
         WHERE oi.order_id = ?`,
        [orderId]
      );

      return {
        success: true,
        vulnerable: true,
        order: {
          ...order,
          items,
        },
        warning: isOwnOrder 
          ? null 
          : '⚠️ Unauthorized access to another user\'s order!',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
          isOwnOrder,
          orderOwner: order.user_id,
          requester: requestingUserId,
        },
      };

    } catch (error) {
      return this.handleIDORError(error, orderId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: File Download Without Authorization
   * 
   * Attack: /api/files/invoice_123.pdf
   * 
   * @param {string} filename - Filename (VULNERABLE)
   * @param {number} requestingUserId - Current user ID
   * @param {object} context - Request context
   * @returns {Promise<object>} File info
   */
  async vulnerableDownloadFile(filename, requestingUserId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.fileAccess++;

      const attackDetection = this.detectIDORAttempt(filename, requestingUserId, 'file', context);
      
      if (attackDetection.isAttack) {
        await this.logIDORAttack({
          type: 'IDOR_FILE_DOWNLOAD',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { filename, requestingUserId },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 IDOR: File Download', {
        filename,
        requestingUserId,
      });

      // ⚠️ VULNERABLE: Fetch file without checking ownership
      const [files] = await db.execute(
        `SELECT id, user_id, filename, filepath, content_type, size, created_at
         FROM uploads
         WHERE filename = ?`,
        [filename]
      );

      if (files.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'File not found',
        };
      }

      const file = files[0];
      const isOwnFile = file.user_id === requestingUserId;

      if (!isOwnFile) {
        this.attackStats.unauthorizedAccess++;
        this.attackStats.horizontalEscalation++;
      }

      return {
        success: true,
        vulnerable: true,
        file: {
          id: file.id,
          filename: file.filename,
          filepath: file.filepath,
          contentType: file.content_type,
          size: file.size,
          createdAt: file.created_at,
        },
        warning: isOwnFile 
          ? null 
          : '⚠️ Unauthorized file access - downloading another user\'s file!',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
          isOwnFile,
          fileOwner: file.user_id,
          requester: requestingUserId,
        },
      };

    } catch (error) {
      return this.handleIDORError(error, filename, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Message Access Without Participant Check
   * 
   * Attack: /api/messages/456
   * 
   * @param {number} messageId - Message ID (VULNERABLE)
   * @param {number} requestingUserId - Current user ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Message content
   */
  async vulnerableGetMessage(messageId, requestingUserId, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.messageAccess++;

      const attackDetection = this.detectIDORAttempt(messageId, requestingUserId, 'message', context);
      
      if (attackDetection.isAttack) {
        await this.logIDORAttack({
          type: 'IDOR_MESSAGE_ACCESS',
          severity: ATTACK_SEVERITY.CRITICAL,
          payload: { messageId, requestingUserId },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 IDOR: Message Access', {
        messageId,
        requestingUserId,
      });

      // ⚠️ VULNERABLE: No check if user is sender or recipient
      const [messages] = await db.execute(
        `SELECT m.*, 
                sender.username as sender_username,
                recipient.username as recipient_username
         FROM messages m
         JOIN ${tables.USERS} sender ON m.sender_id = sender.id
         JOIN ${tables.USERS} recipient ON m.recipient_id = recipient.id
         WHERE m.id = ?`,
        [messageId]
      );

      if (messages.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Message not found',
        };
      }

      const message = messages[0];
      const isParticipant = message.sender_id === requestingUserId || 
                           message.recipient_id === requestingUserId;

      if (!isParticipant) {
        this.attackStats.unauthorizedAccess++;
        this.attackStats.horizontalEscalation++;
      }

      return {
        success: true,
        vulnerable: true,
        message,
        warning: isParticipant 
          ? null 
          : '⚠️ Unauthorized message access - reading other users\' private messages!',
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
          isParticipant,
          requester: requestingUserId,
        },
      };

    } catch (error) {
      return this.handleIDORError(error, messageId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Document Access for Admin-Only Content
   * 
   * Attack: Access admin documents with regular user account
   * 
   * @param {number} documentId - Document ID (VULNERABLE)
   * @param {number} requestingUserId - Current user ID
   * @param {string} userRole - User role
   * @param {object} context - Request context
   * @returns {Promise<object>} Document content
   */
  async vulnerableGetDocument(documentId, requestingUserId, userRole, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.documentAccess++;

      const attackDetection = this.detectIDORAttempt(documentId, requestingUserId, 'document', context);
      
      if (attackDetection.isAttack) {
        await this.logIDORAttack({
          type: 'IDOR_DOCUMENT_ACCESS',
          severity: ATTACK_SEVERITY.HIGH,
          payload: { documentId, requestingUserId, userRole },
          patterns: attackDetection.patterns,
          context,
        });
      }

      logger.warn('🚨 IDOR: Document Access', {
        documentId,
        requestingUserId,
        userRole,
      });

      // ⚠️ VULNERABLE: No role-based access control
      const [documents] = await db.execute(
        `SELECT id, title, content, required_role, created_by, created_at
         FROM documents
         WHERE id = ?`,
        [documentId]
      );

      if (documents.length === 0) {
        return {
          success: false,
          vulnerable: true,
          message: 'Document not found',
        };
      }

      const document = documents[0];
      const hasAccess = this.checkRoleAccess(userRole, document.required_role);

      if (!hasAccess) {
        this.attackStats.unauthorizedAccess++;
        this.attackStats.verticalEscalation++;
      }

      return {
        success: true,
        vulnerable: true,
        document,
        warning: hasAccess 
          ? null 
          : `⚠️ Vertical privilege escalation - ${userRole} accessing ${document.required_role}-only document!`,
        attackInfo: attackDetection,
        metadata: {
          executionTime: Date.now() - startTime,
          hasAccess,
          requiredRole: document.required_role,
          userRole,
        },
      };

    } catch (error) {
      return this.handleIDORError(error, documentId, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Sequential ID Enumeration
   * 
   * Attack: Iterate through all user IDs to enumerate accounts
   * 
   * @param {number} startId - Starting ID
   * @param {number} count - Number of IDs to check
   * @param {object} context - Request context
   * @returns {Promise<object>} Enumeration results
   */
  async vulnerableEnumerateUsers(startId, count, context = {}) {
    const startTime = Date.now();

    try {
      this.attackStats.totalAttempts++;
      this.attackStats.enumerationAttempts++;

      logger.warn('🚨 IDOR: User Enumeration Attack', {
        startId,
        count,
        ip: context.ip,
      });

      await this.logIDORAttack({
        type: 'IDOR_ENUMERATION',
        severity: ATTACK_SEVERITY.HIGH,
        payload: { startId, count, resourceType: 'users' },
        patterns: [],
        context,
      });

      const results = [];
      const maxCount = Math.min(count, 100); // Limit to prevent DoS

      for (let id = startId; id < startId + maxCount; id++) {
        const [users] = await db.execute(
          `SELECT id, username, email, created_at
           FROM ${tables.USERS}
           WHERE id = ? AND deleted_at IS NULL`,
          [id]
        );

        if (users.length > 0) {
          results.push({
            id,
            exists: true,
            username: users[0].username,
            email: users[0].email,
            createdAt: users[0].created_at,
          });
        } else {
          results.push({
            id,
            exists: false,
          });
        }
      }

      const existingUsers = results.filter(r => r.exists);
      this.attackStats.unauthorizedAccess += existingUsers.length;

      return {
        success: true,
        vulnerable: true,
        results,
        summary: {
          total: results.length,
          existing: existingUsers.length,
          missing: results.length - existingUsers.length,
        },
        warning: '⚠️ Sequential ID enumeration allows discovering all user accounts!',
        metadata: {
          executionTime: Date.now() - startTime,
        },
      };

    } catch (error) {
      return this.handleIDORError(error, 'enumeration', Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: User Profile with Authorization
   */
  async secureGetUserProfile(userId, requestingUserId, requestingUserRole) {
    const startTime = Date.now();

    try {
      // ✅ Check authorization
      if (userId !== requestingUserId && requestingUserRole !== USER_ROLES.ADMIN) {
        throw new AppError('Unauthorized access', HTTP_STATUS.FORBIDDEN);
      }

      const [users] = await db.execute(
        `SELECT id, username, email, phone, address, bio, website, created_at
         FROM ${tables.USERS}
         WHERE id = ? AND deleted_at IS NULL`,
        [userId]
      );

      if (users.length === 0) {
        throw new AppError('User not found', HTTP_STATUS.NOT_FOUND);
      }

      return {
        success: true,
        vulnerable: false,
        user: users[0],
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'SECURE_AUTHORIZATION',
        },
      };

    } catch (error) {
      logger.error('Secure profile access error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Order Access with Ownership Verification
   */
  async secureGetOrder(orderId, requestingUserId, requestingUserRole) {
    const startTime = Date.now();

    try {
      const [orders] = await db.execute(
        `SELECT * FROM ${tables.ORDERS} WHERE id = ?`,
        [orderId]
      );

      if (orders.length === 0) {
        throw new AppError('Order not found', HTTP_STATUS.NOT_FOUND);
      }

      const order = orders[0];

      // ✅ Check ownership or admin role
      if (order.user_id !== requestingUserId && requestingUserRole !== USER_ROLES.ADMIN) {
        logger.warn('Unauthorized order access attempt', {
          orderId,
          orderOwner: order.user_id,
          requester: requestingUserId,
        });
        throw new AppError('Unauthorized access', HTTP_STATUS.FORBIDDEN);
      }

      return {
        success: true,
        vulnerable: false,
        order,
        metadata: {
          executionTime: Date.now() - startTime,
          method: 'OWNERSHIP_VERIFIED',
        },
      };

    } catch (error) {
      logger.error('Secure order access error', { error: error.message });
      throw error;
    }
  }

  /**
   * Check role-based access
   */
  checkRoleAccess(userRole, requiredRole) {
    const roleHierarchy = {
      [USER_ROLES.CUSTOMER]: 1,
      [USER_ROLES.MODERATOR]: 2,
      [USER_ROLES.ADMIN]: 3,
      [USER_ROLES.SUPER_ADMIN]: 4,
    };

    return roleHierarchy[userRole] >= roleHierarchy[requiredRole];
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect IDOR attack patterns
   */
  detectIDORAttempt(targetId, requestingUserId, resourceType, context) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.MEDIUM;
    let score = 0;

    const ip = context.ip || 'unknown';
    const trackingKey = `${ip}:${resourceType}`;

    // Track enumeration attempts
    const tracking = this.enumerationTracking.get(trackingKey) || {
      attempts: [],
      firstAttempt: Date.now(),
    };

    tracking.attempts.push({
      targetId,
      timestamp: Date.now(),
    });

    // Clean old attempts
    const window = Date.now() - IDOR_CONFIG.ENUMERATION_WINDOW;
    tracking.attempts = tracking.attempts.filter(a => a.timestamp > window);

    this.enumerationTracking.set(trackingKey, tracking);

    // Check for sequential enumeration
    if (tracking.attempts.length >= IDOR_CONFIG.ENUMERATION_THRESHOLD) {
      detectedPatterns.push({
        category: 'SEQUENTIAL_ENUMERATION',
        attempts: tracking.attempts.length,
        window: IDOR_CONFIG.ENUMERATION_WINDOW,
        matched: true,
      });
      score += 20;
      severity = ATTACK_SEVERITY.HIGH;
    }

    // Check for rapid access
    if (tracking.attempts.length > 5) {
      const timeDiff = tracking.attempts[tracking.attempts.length - 1].timestamp - 
                       tracking.attempts[tracking.attempts.length - 5].timestamp;
      
      if (timeDiff < 5000) { // 5 requests in 5 seconds
        detectedPatterns.push({
          category: 'RAPID_ACCESS',
          requestsPerSecond: (5 / (timeDiff / 1000)).toFixed(2),
          matched: true,
        });
        score += 15;
      }
    }

    // Check sensitive resource access
    if (IDOR_CONFIG.SENSITIVE_RESOURCES.includes(resourceType)) {
      detectedPatterns.push({
        category: 'SENSITIVE_RESOURCE',
        resourceType,
        matched: true,
      });
      score += 10;
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
      enumerationAttempts: tracking.attempts.length,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Log IDOR attack
   */
  async logIDORAttack(attackData) {
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

      logger.attack('IDOR Attack Detected', {
        type,
        severity,
        payload,
        patterns,
        context,
      });

    } catch (error) {
      logger.error('Failed to log IDOR attack', { error: error.message });
    }
  }

  /**
   * Handle IDOR errors
   */
  handleIDORError(error, identifier, duration) {
    logger.error('IDOR Attack Error', {
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
        errorType: 'IDOR_ERROR',
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
      unauthorizedRate: this.attackStats.totalAttempts > 0
        ? ((this.attackStats.unauthorizedAccess / this.attackStats.totalAttempts) * 100).toFixed(2) + '%'
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
      description: 'IDOR allows attackers to access unauthorized resources by manipulating direct object references',
      impact: [
        'Unauthorized data access',
        'Privacy violation',
        'Data breach',
        'Horizontal privilege escalation',
        'Vertical privilege escalation',
        'Account enumeration',
        'Sensitive information disclosure',
      ],
      commonVulnerabilities: [
        'Sequential numeric IDs',
        'Predictable UUIDs/GUIDs',
        'Missing authorization checks',
        'No ownership verification',
        'Weak access control',
        'Predictable filenames',
      ],
      remediation: [
        'Implement proper authorization checks',
        'Verify ownership before granting access',
        'Use non-sequential, unpredictable IDs',
        'Implement indirect object references',
        'Use access control lists (ACLs)',
        'Validate user permissions on every request',
        'Log and monitor access patterns',
        'Implement rate limiting',
        'Use encrypted/signed resource identifiers',
      ],
      references: [
        'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control',
        'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
        'CWE-639: Authorization Bypass Through User-Controlled Key',
      ],
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      userDataAccess: 0,
      orderAccess: 0,
      fileAccess: 0,
      messageAccess: 0,
      documentAccess: 0,
      enumerationAttempts: 0,
      unauthorizedAccess: 0,
      horizontalEscalation: 0,
      verticalEscalation: 0,
    };
    this.enumerationTracking.clear();
  }

  /**
   * Clear enumeration tracking (for testing)
   */
  clearEnumerationTracking() {
    this.enumerationTracking.clear();
    logger.info('Enumeration tracking cleared');
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getIDOR = () => {
  if (!instance) {
    instance = new IDOR();
  }
  return instance;
};

export const createIDORHandler = (method) => {
  return async (req, res, next) => {
    try {
      const idor = getIDOR();
      
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
      const result = await idor[method](...Object.values(params), context);
      
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  IDOR,
  getIDOR,
  createIDORHandler,
};
