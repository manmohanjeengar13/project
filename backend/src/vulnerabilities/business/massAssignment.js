/**
 * ============================================================================
 * MASS ASSIGNMENT VULNERABILITY - MILITARY-GRADE ENTERPRISE EDITION
 * ============================================================================
 * 
 * Advanced Mass Assignment / Auto-binding Attack Demonstration Platform
 * Implements over-posting and parameter pollution vulnerabilities
 * 
 * @module vulnerabilities/business/massAssignment
 * @category Security Training - OWASP A04:2021 (Insecure Design)
 * @version 3.0.0
 * @license MIT
 * @author Elite Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING - CRITICAL SEVERITY:
 * ============================================================================
 * This module contains INTENTIONAL CRITICAL security vulnerabilities:
 * - Unrestricted object property binding
 * - No field whitelisting
 * - Privilege escalation through parameter injection
 * - Price manipulation through hidden fields
 * - Account takeover through email modification
 * - Balance manipulation
 * - Administrative flag modification
 * - Database column pollution
 * - JSON injection vulnerabilities
 * - Nested object manipulation
 * 
 * ⚠️  EXTREME DANGER: Can compromise entire system security
 * ⚠️  FOR ISOLATED SECURITY TRAINING ONLY
 * ⚠️  Must run in controlled sandbox environments
 * ⚠️  Never use auto-binding in production
 * ⚠️  Implement strict field whitelisting
 * 
 * ============================================================================
 * VULNERABILITY TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Classic Mass Assignment (User Profile)
 * 2. Price Manipulation (E-commerce)
 * 3. Role/Permission Escalation
 * 4. Account Balance Modification
 * 5. Hidden Field Manipulation
 * 6. Verification Status Bypass
 * 7. Administrative Flag Injection
 * 8. Nested Object Pollution
 * 9. Array Parameter Pollution
 * 10. JSON Deep Merge Vulnerabilities
 * 11. Order Status Manipulation
 * 12. Discount/Coupon Manipulation
 * 13. Shipping Cost Bypass
 * 14. Tax Calculation Bypass
 * 15. Metadata Injection
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - {role: "admin", is_admin: true}
 * - {price: 0.01, discount: 100}
 * - {balance: 999999, credit_limit: 999999}
 * - {is_verified: true, is_active: true}
 * - {permissions: ["*"], access_level: 99}
 * - {shipping_cost: 0, tax_amount: 0}
 * - {order_status: "completed", paid: true}
 * 
 * ============================================================================
 * COMPLIANCE & STANDARDS:
 * ============================================================================
 * - OWASP Top 10 2021: A04 - Insecure Design
 * - CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
 * - CWE-502: Deserialization of Untrusted Data
 * - CWE-471: Modification of Assumed-Immutable Data
 * - NIST 800-53: SI-10 Information Input Validation
 * 
 * @requires Database
 * @requires Logger
 * @requires Cache
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
import { AppError, ValidationError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VULNERABILITY CONSTANTS
// ============================================================================

const SENSITIVE_FIELDS = [
  'role', 'is_admin', 'isAdmin', 'admin',
  'is_active', 'isActive', 'active',
  'is_verified', 'isVerified', 'verified',
  'balance', 'credit', 'wallet_balance',
  'price', 'cost', 'discount', 'total_amount',
  'permissions', 'access_level', 'privilege',
  'password', 'password_hash',
  'api_key', 'secret_key', 'token',
  'is_deleted', 'deleted_at',
  'created_at', 'updated_at',
  'version', 'id', 'user_id'
];

const PRIVILEGED_ROLES = ['admin', 'superadmin', 'moderator', 'root'];

const FINANCIAL_FIELDS = [
  'price', 'cost', 'amount', 'total', 'subtotal',
  'discount', 'tax', 'shipping', 'balance',
  'credit', 'debit', 'refund', 'fee'
];

// ============================================================================
// MASS ASSIGNMENT VULNERABILITY CLASS
// ============================================================================

export class MassAssignment {
  constructor() {
    this.name = 'Mass Assignment / Auto-binding';
    this.category = 'Business Logic';
    this.cvssScore = 8.5;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A04:2021';
    this.cweId = 'CWE-915';
    
    // Attack statistics
    this.attackStats = {
      totalAttempts: 0,
      successfulAssignments: 0,
      blockedAttempts: 0,
      privilegeEscalations: 0,
      priceManipulations: 0,
      balanceModifications: 0,
      roleChanges: 0,
      verificationBypasses: 0,
      sensitiveFieldAttempts: {},
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      financialImpact: 0,
      affectedUsers: new Set(),
      ipAddresses: new Set()
    };
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: User Profile Update with Mass Assignment
   * 
   * Allows modifying any user field including privileged ones
   * Attack: {role: "admin", is_verified: true, balance: 999999}
   * 
   * @param {number} userId - User ID
   * @param {object} updateData - User-supplied data (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Update result
   */
  async vulnerableUpdateProfile(userId, updateData, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 MASS ASSIGNMENT PROFILE UPDATE', {
        userId,
        fields: Object.keys(updateData),
        ip: context.ip,
        mode: Config.security.mode
      });

      // Detect attack
      const detection = this.detectMassAssignment(updateData, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'MASS_ASSIGNMENT_PROFILE',
          severity: detection.severity,
          userId,
          payload: updateData,
          detection,
          context
        });
      }

      // Get original user data
      const [originalUsers] = await db.execute(
        'SELECT * FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      const originalUser = originalUsers[0];

      // ⚠️ VULNERABLE: No field whitelisting - accepts ALL fields
      const fields = Object.keys(updateData);
      const values = Object.values(updateData);
      
      if (fields.length === 0) {
        throw new ValidationError('No fields to update');
      }

      // ⚠️ VULNERABLE: Build dynamic UPDATE query with user input
      const setClause = fields.map(field => `${field} = ?`).join(', ');
      
      const query = `
        UPDATE ${tables.USERS}
        SET ${setClause}, updated_at = NOW()
        WHERE id = ?
      `;

      await db.execute(query, [...values, userId]);

      // Get updated user
      const [updatedUsers] = await db.execute(
        'SELECT * FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      const updatedUser = updatedUsers[0];

      // Track sensitive field modifications
      const modifiedSensitiveFields = this.detectSensitiveFieldModification(
        originalUser,
        updatedUser
      );

      if (modifiedSensitiveFields.length > 0) {
        this.attackStats.successfulAssignments++;
        
        if (modifiedSensitiveFields.includes('role')) this.attackStats.roleChanges++;
        if (modifiedSensitiveFields.includes('balance')) this.attackStats.balanceModifications++;
        if (modifiedSensitiveFields.includes('is_verified')) this.attackStats.verificationBypasses++;
        
        this.attackStats.affectedUsers.add(userId);
      }

      const duration = Date.now() - startTime;

      logger.warn('🚨 MASS ASSIGNMENT SUCCESSFUL', {
        userId,
        modifiedFields: fields,
        sensitiveFieldsModified: modifiedSensitiveFields,
        duration
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          userId,
          originalData: this.sanitizeOutput(originalUser),
          updatedData: this.sanitizeOutput(updatedUser),
          modifiedFields: fields,
          sensitiveFieldsModified: modifiedSensitiveFields,
          warning: modifiedSensitiveFields.length > 0 
            ? 'CRITICAL: Sensitive fields modified via mass assignment' 
            : null
        },
        metadata: {
          executionTime: duration,
          severity: detection.severity,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableUpdateProfile', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Product Creation with Price Manipulation
   * 
   * Allows setting arbitrary prices through mass assignment
   * Attack: {name: "Product", price: 0.01, cost: 0, discount: 100}
   * 
   * @param {object} productData - Product data (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Creation result
   */
  async vulnerableCreateProduct(productData, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 MASS ASSIGNMENT PRODUCT CREATION', {
        productData,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectMassAssignment(productData, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'MASS_ASSIGNMENT_PRODUCT',
          severity: detection.severity,
          payload: productData,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Accept all fields without validation
      const fields = Object.keys(productData);
      const values = Object.values(productData);
      const placeholders = fields.map(() => '?').join(', ');

      const query = `
        INSERT INTO ${tables.PRODUCTS} (${fields.join(', ')}, created_at)
        VALUES (${placeholders}, NOW())
      `;

      const [result] = await db.execute(query, values);

      // Check for price manipulation
      const priceManipulated = productData.price !== undefined && 
        (productData.price < 1 || productData.discount > 90);

      if (priceManipulated) {
        this.attackStats.successfulAssignments++;
        this.attackStats.priceManipulations++;
        this.attackStats.financialImpact += 1000; // Estimated loss
      }

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          productId: result.insertId,
          productData,
          priceManipulated,
          warning: priceManipulated ? 'CRITICAL: Price manipulated via mass assignment' : null
        },
        metadata: {
          executionTime: duration,
          severity: detection.severity,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableCreateProduct', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Order Update with Status Manipulation
   * 
   * Allows changing order status without authorization
   * Attack: {status: "completed", paid: true, total_amount: 0.01}
   * 
   * @param {number} orderId - Order ID
   * @param {object} updateData - Update data (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Update result
   */
  async vulnerableUpdateOrder(orderId, updateData, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 MASS ASSIGNMENT ORDER UPDATE', {
        orderId,
        updateData,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectMassAssignment(updateData, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'MASS_ASSIGNMENT_ORDER',
          severity: ATTACK_SEVERITY.CRITICAL,
          orderId,
          payload: updateData,
          detection,
          context
        });
      }

      // Get original order
      const [originalOrders] = await db.execute(
        'SELECT * FROM orders WHERE id = ? LIMIT 1',
        [orderId]
      );

      if (!originalOrders.length) {
        throw new ValidationError('Order not found');
      }

      const originalOrder = originalOrders[0];

      // ⚠️ VULNERABLE: Update any field including status and payment
      const fields = Object.keys(updateData);
      const values = Object.values(updateData);
      const setClause = fields.map(field => `${field} = ?`).join(', ');

      await db.execute(
        `UPDATE ${tables.ORDERS} SET ${setClause}, updated_at = NOW() WHERE id = ?`,
        [...values, orderId]
      );

      // Check for manipulation
      const statusManipulated = updateData.status && updateData.status !== originalOrder.status;
      const paymentManipulated = updateData.paid !== undefined;
      const amountManipulated = updateData.total_amount !== undefined && 
        updateData.total_amount !== originalOrder.total_amount;

      if (statusManipulated || paymentManipulated || amountManipulated) {
        this.attackStats.successfulAssignments++;
        if (amountManipulated) {
          const priceDiff = originalOrder.total_amount - (updateData.total_amount || 0);
          this.attackStats.financialImpact += priceDiff;
        }
      }

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          orderId,
          originalOrder: this.sanitizeOutput(originalOrder),
          modifiedFields: fields,
          statusManipulated,
          paymentManipulated,
          amountManipulated,
          warning: 'CRITICAL: Order details manipulated via mass assignment'
        },
        metadata: {
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableUpdateOrder', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Nested Object Mass Assignment
   * 
   * Demonstrates JSON deep merge vulnerability
   * Attack: {profile: {role: "admin"}, settings: {admin_access: true}}
   * 
   * @param {number} userId - User ID
   * @param {object} nestedData - Nested object data (VULNERABLE)
   * @param {object} context - Request context
   * @returns {Promise<object>} Update result
   */
  async vulnerableUpdateNestedData(userId, nestedData, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 MASS ASSIGNMENT NESTED OBJECT', {
        userId,
        nestedData,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectMassAssignment(nestedData, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'MASS_ASSIGNMENT_NESTED',
          severity: ATTACK_SEVERITY.HIGH,
          userId,
          payload: nestedData,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Deep merge user input into database
      // This allows polluting nested objects
      const updates = {};

      // Flatten nested objects for database update
      const flattenObject = (obj, prefix = '') => {
        for (const [key, value] of Object.entries(obj)) {
          const newKey = prefix ? `${prefix}_${key}` : key;
          if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            flattenObject(value, newKey);
          } else {
            updates[newKey] = value;
          }
        }
      };

      flattenObject(nestedData);

      // Update with flattened data
      const fields = Object.keys(updates);
      const values = Object.values(updates);
      
      if (fields.length > 0) {
        const setClause = fields.map(field => `${field} = ?`).join(', ');
        await db.execute(
          `UPDATE ${tables.USERS} SET ${setClause}, updated_at = NOW() WHERE id = ?`,
          [...values, userId]
        );
      }

      this.attackStats.successfulAssignments++;

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          userId,
          nestedData,
          flattenedUpdates: updates,
          warning: 'CRITICAL: Nested object pollution via mass assignment'
        },
        metadata: {
          executionTime: duration,
          severity: detection.severity,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableUpdateNestedData', Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Profile Update with Field Whitelist
   * 
   * @param {number} userId - User ID
   * @param {object} updateData - Update data (VALIDATED)
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} Update result
   */
  async secureUpdateProfile(userId, updateData, req) {
    try {
      // ✅ Authentication check
      if (!req.user || req.user.id !== userId) {
        throw new ValidationError('Unauthorized');
      }

      // ✅ Field whitelist - ONLY allow safe fields
      const allowedFields = ['first_name', 'last_name', 'phone', 'address', 'bio', 'avatar'];
      const sanitizedData = {};

      for (const field of allowedFields) {
        if (updateData[field] !== undefined) {
          sanitizedData[field] = updateData[field];
        }
      }

      if (Object.keys(sanitizedData).length === 0) {
        throw new ValidationError('No valid fields to update');
      }

      // ✅ Validate each field
      if (sanitizedData.phone && !/^\+?[1-9]\d{1,14}$/.test(sanitizedData.phone)) {
        throw new ValidationError('Invalid phone number');
      }

      if (sanitizedData.bio && sanitizedData.bio.length > 500) {
        throw new ValidationError('Bio too long');
      }

      // ✅ Build safe query with whitelisted fields
      const fields = Object.keys(sanitizedData);
      const values = Object.values(sanitizedData);
      const setClause = fields.map(field => `${field} = ?`).join(', ');

      await db.execute(
        `UPDATE ${tables.USERS} SET ${setClause}, updated_at = NOW() WHERE id = ?`,
        [...values, userId]
      );

      return {
        success: true,
        vulnerable: false,
        data: { userId, updatedFields: fields }
      };

    } catch (error) {
      throw error;
    }
  }

  /**
   * ✅ SECURE: Product Creation with Validation
   * 
   * @param {object} productData - Product data (VALIDATED)
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} Creation result
   */
  async secureCreateProduct(productData, req) {
    try {
      // ✅ Authorization check
      if (!req.user || req.user.role !== 'admin') {
        throw new ValidationError('Admin privileges required');
      }

      // ✅ Required fields validation
      const requiredFields = ['name', 'description', 'price', 'stock_quantity'];
      for (const field of requiredFields) {
        if (!productData[field]) {
          throw new ValidationError(`Missing required field: ${field}`);
        }
      }

      // ✅ Field whitelist and validation
      const name = String(productData.name).substring(0, 200);
      const description = String(productData.description).substring(0, 2000);
      const price = parseFloat(productData.price);
      const stockQuantity = parseInt(productData.stock_quantity, 10);
      const categoryId = parseInt(productData.category_id, 10) || null;

      // ✅ Business logic validation
      if (price < 0.01 || price > 999999) {
        throw new ValidationError('Invalid price');
      }

      if (stockQuantity < 0) {
        throw new ValidationError('Invalid stock quantity');
      }

      // ✅ Explicit field insertion
      const [result] = await db.execute(
        `INSERT INTO ${tables.PRODUCTS} (name, description, price, stock_quantity, category_id, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())`,
        [name, description, price, stockQuantity, categoryId]
      );

      return {
        success: true,
        vulnerable: false,
        data: { productId: result.insertId }
      };

    } catch (error) {
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & ANALYSIS
  // ==========================================================================

  /**
   * Detect mass assignment attempts
   * 
   * @param {object} payload - Request payload
   * @param {object} context - Request context
   * @returns {object} Detection results
   */
  detectMassAssignment(payload, context = {}) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.LOW;
    let score = 0;

    const payloadKeys = this.getAllKeys(payload);

    // Check for sensitive fields
    for (const field of SENSITIVE_FIELDS) {
      if (payloadKeys.some(key => key.toLowerCase().includes(field.toLowerCase()))) {
        detectedPatterns.push({
          category: 'SENSITIVE_FIELD',
          field,
          matched: true
        });
        score += 15;
        
        this.attackStats.sensitiveFieldAttempts[field] = 
          (this.attackStats.sensitiveFieldAttempts[field] || 0) + 1;
      }
    }

    // Check for role/privilege escalation
    const roleFields = ['role', 'is_admin', 'admin', 'permissions', 'access_level'];
    const hasRoleField = payloadKeys.some(key => 
      roleFields.some(rf => key.toLowerCase().includes(rf))
    );

    if (hasRoleField) {
      detectedPatterns.push({
        category: 'PRIVILEGE_ESCALATION_ATTEMPT',
        matched: true
      });
      score += 20;
      severity = ATTACK_SEVERITY.CRITICAL;
      this.attackStats.privilegeEscalations++;
    }

    // Check for financial field manipulation
    const hasFinancialField = payloadKeys.some(key =>
      FINANCIAL_FIELDS.some(ff => key.toLowerCase().includes(ff))
    );

    if (hasFinancialField) {
      detectedPatterns.push({
        category: 'FINANCIAL_MANIPULATION',
        matched: true
      });
      score += 18;
      if (severity !== ATTACK_SEVERITY.CRITICAL) {
        severity = ATTACK_SEVERITY.HIGH;
      }
    }

    // Check for verification bypass
    const verificationFields = ['is_verified', 'verified', 'is_active', 'approved'];
    const hasVerificationField = payloadKeys.some(key =>
      verificationFields.some(vf => key.toLowerCase().includes(vf))
    );

    if (hasVerificationField) {
      detectedPatterns.push({
        category: 'VERIFICATION_BYPASS',
        matched: true
      });
      score += 12;
    }

    // Check for metadata manipulation
    const metadataFields = ['created_at', 'updated_at', 'deleted_at', 'id', 'version'];
    const hasMetadataField = payloadKeys.some(key =>
      metadataFields.some(mf => key.toLowerCase() === mf.toLowerCase())
    );

    if (hasMetadataField) {
      detectedPatterns.push({
        category: 'METADATA_MANIPULATION',
        matched: true
      });
      score += 10;
    }

    // Determine severity
    if (score >= 25) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 15) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 8) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    if (isAttack) {
      this.updateAttackStats(severity);
    }

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      suspiciousFields: payloadKeys.filter(key =>
        SENSITIVE_FIELDS.some(sf => key.toLowerCase().includes(sf.toLowerCase()))
      ),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Get all keys from nested object
   */
  getAllKeys(obj, prefix = '') {
    let keys = [];
    
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      keys.push(fullKey);
      
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        keys = keys.concat(this.getAllKeys(value, fullKey));
      }
    }
    
    return keys;
  }

  /**
   * Detect sensitive field modifications
   */
  detectSensitiveFieldModification(original, updated) {
    const modifiedFields = [];
    
    for (const field of SENSITIVE_FIELDS) {
      if (original[field] !== updated[field]) {
        modifiedFields.push(field);
      }
    }
    
    return modifiedFields;
  }

  /**
   * Sanitize output (hide sensitive data)
   */
  sanitizeOutput(data) {
    const sanitized = { ...data };
    const hideFields = ['password', 'password_hash', 'api_key', 'secret_key', 'token'];
    
    for (const field of hideFields) {
      if (sanitized[field]) {
        sanitized[field] = '***REDACTED***';
      }
    }
    
    return sanitized;
  }

  /**
   * Update attack statistics
   */
  updateAttackStats(severity) {
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

  /**
   * Log attack attempt
   */
  async logAttack(attackData) {
    try {
      const { type, severity, userId, orderId, payload, detection, context } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [
          type,
          severity,
          JSON.stringify(payload),
          JSON.stringify(detection.patterns),
          context.ip || null,
          context.userAgent || null,
          userId || null,
          context.endpoint || null
        ]
      );

      // Cache attack
      const cacheKey = CacheKeyBuilder.custom('mass_assignment:', context.ip);
      const recentAttacks = await cache.get(cacheKey) || [];
      recentAttacks.push({
        type,
        severity,
        timestamp: new Date().toISOString()
      });
      await cache.set(cacheKey, recentAttacks, 3600);

      if (context.ip) this.attackStats.ipAddresses.add(context.ip);

      logger.attack('Mass Assignment Attack Detected', {
        type,
        severity,
        userId,
        orderId,
        suspiciousFields: detection.suspiciousFields,
        context
      });

    } catch (error) {
      logger.error('Failed to log attack', { error: error.message });
    }
  }

  /**
   * Handle vulnerable errors
   */
  handleVulnerableError(error, method, duration) {
    logger.error('Mass assignment error', {
      message: error.message,
      method,
      duration
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        method
      },
      metadata: {
        executionTime: duration,
        errorType: 'MASS_ASSIGNMENT_ERROR'
      }
    };
  }

  // ==========================================================================
  // UTILITY & REPORTING
  // ==========================================================================

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.attackStats,
      affectedUsers: this.attackStats.affectedUsers.size,
      ipAddresses: this.attackStats.ipAddresses.size,
      successRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.successfulAssignments / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
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
      description: 'Mass Assignment vulnerabilities occur when applications automatically bind user input to internal objects without proper filtering, allowing attackers to modify sensitive fields',
      impact: [
        'Privilege escalation through role modification',
        'Financial fraud through price manipulation',
        'Account takeover through email/password changes',
        'Verification bypass',
        'Balance manipulation',
        'Order status tampering',
        'Administrative access gain',
        'Data corruption'
      ],
      attackVectors: [
        '{role: "admin", is_admin: true}',
        '{price: 0.01, discount: 100}',
        '{balance: 999999}',
        '{is_verified: true}',
        '{permissions: ["*"]}',
        '{order_status: "completed", paid: true}'
      ],
      remediation: [
        'Use explicit field whitelisting',
        'Never bind user input directly to database models',
        'Implement Data Transfer Objects (DTOs)',
        'Use separate models for input and database',
        'Validate and sanitize all input',
        'Use ORM features that prevent mass assignment',
        'Implement role-based field access control',
        'Audit all field modifications',
        'Use immutable fields for sensitive data'
      ],
      sensitiveFields: SENSITIVE_FIELDS
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulAssignments: 0,
      blockedAttempts: 0,
      privilegeEscalations: 0,
      priceManipulations: 0,
      balanceModifications: 0,
      roleChanges: 0,
      verificationBypasses: 0,
      sensitiveFieldAttempts: {},
      severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
      financialImpact: 0,
      affectedUsers: new Set(),
      ipAddresses: new Set()
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getMassAssignment = () => {
  if (!instance) {
    instance = new MassAssignment();
  }
  return instance;
};

export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const ma = getMassAssignment();
      
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

      const result = await ma[method](...Object.values(req.body || req.query), context);
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  MassAssignment,
  getMassAssignment,
  createVulnerableHandler
};
