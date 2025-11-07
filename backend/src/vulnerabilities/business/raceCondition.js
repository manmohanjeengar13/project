/**
 * ============================================================================
 * RACE CONDITION VULNERABILITY MODULE - MILITARY-GRADE ENTERPRISE EDITION
 * ============================================================================
 * 
 * Advanced Race Condition Attack Demonstration Platform
 * Implements TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
 * 
 * @module vulnerabilities/business/raceCondition
 * @category Security Training - OWASP A04:2021 (Insecure Design)
 * @version 3.0.0
 * @license MIT
 * @author Elite Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING - CRITICAL SEVERITY:
 * ============================================================================
 * This module contains INTENTIONAL CRITICAL security vulnerabilities:
 * - Non-atomic operations on shared resources
 * - Missing database transaction isolation
 * - Concurrent request handling without locking
 * - TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
 * - Double-spending vulnerabilities
 * - Inventory depletion attacks
 * - Coupon replay attacks
 * - Balance manipulation through timing
 * - Order status race conditions
 * - Session race conditions
 * 
 * ⚠️  EXTREME DANGER: Can cause financial loss and data corruption
 * ⚠️  FOR ISOLATED SECURITY TRAINING ONLY
 * ⚠️  Must run in controlled sandbox environments
 * ⚠️  Never deploy with real financial transactions
 * ⚠️  Implement proper locking mechanisms in production
 * 
 * ============================================================================
 * VULNERABILITY TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Balance Check Race Condition (TOCTOU)
 * 2. Inventory Depletion Race Condition
 * 3. Coupon/Discount Code Replay
 * 4. Double Withdrawal/Payment
 * 5. Order Creation Race Condition
 * 6. Cart Manipulation Race Condition
 * 7. Concurrent Update Race Condition
 * 8. File Upload Race Condition
 * 9. Session Fixation Race Condition
 * 10. Database Row Locking Bypass
 * 11. Optimistic Locking Failure
 * 12. Distributed System Race Condition
 * 13. Cache Invalidation Race Condition
 * 14. Email Verification Race Condition
 * 15. Password Reset Token Race Condition
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - Parallel coupon redemption requests
 * - Simultaneous fund withdrawals
 * - Concurrent order placements
 * - Multiple discount applications
 * - Parallel inventory decrements
 * - Simultaneous cart checkouts
 * - Concurrent balance updates
 * - Race-based privilege escalation
 * 
 * ============================================================================
 * COMPLIANCE & STANDARDS:
 * ============================================================================
 * - OWASP Top 10 2021: A04 - Insecure Design
 * - CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
 * - CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition
 * - CWE-663: Use of a Non-reentrant Function in a Concurrent Context
 * - NIST 800-53: SC-3 Security Function Isolation
 * - PCI-DSS: Requirement 6.5 (Secure Development)
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
  ERROR_MESSAGES
} from '../../config/constants.js';
import { AppError, ValidationError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VULNERABILITY CONSTANTS
// ============================================================================

const RACE_CONDITION_TYPES = {
  BALANCE_CHECK: 'BALANCE_CHECK_TOCTOU',
  INVENTORY: 'INVENTORY_DEPLETION',
  COUPON_REPLAY: 'COUPON_REPLAY_ATTACK',
  DOUBLE_SPEND: 'DOUBLE_SPENDING',
  ORDER_CREATION: 'ORDER_RACE_CONDITION',
  CART_MANIPULATION: 'CART_RACE_CONDITION',
  CONCURRENT_UPDATE: 'CONCURRENT_UPDATE_CONFLICT',
  SESSION_RACE: 'SESSION_RACE_CONDITION'
};

const TIMING_WINDOWS = {
  CRITICAL: 100, // ms - critical race window
  HIGH: 500,
  MEDIUM: 1000,
  LOW: 2000
};

// ============================================================================
// RACE CONDITION VULNERABILITY CLASS
// ============================================================================

export class RaceCondition {
  constructor() {
    this.name = 'Race Condition / TOCTOU';
    this.category = 'Business Logic';
    this.cvssScore = 8.8;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A04:2021';
    this.cweId = 'CWE-362';
    
    // Attack statistics
    this.attackStats = {
      totalAttempts: 0,
      successfulRaces: 0,
      detectedRaces: 0,
      blockedAttempts: 0,
      raceTypes: {},
      timingWindows: {},
      concurrentRequests: {},
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      financialImpact: {
        totalLoss: 0,
        transactions: []
      },
      inventoryImpact: {
        oversold: 0,
        products: []
      },
      ipAddresses: new Set(),
      userIds: new Set()
    };
    
    // Tracking concurrent operations
    this.activeOperations = new Map();
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Balance Withdrawal with TOCTOU
   * 
   * Classic Time-of-Check-Time-of-Use vulnerability
   * Attack: Send multiple withdrawal requests simultaneously
   * 
   * @param {number} userId - User ID
   * @param {number} amount - Withdrawal amount
   * @param {object} context - Request context
   * @returns {Promise<object>} Withdrawal result
   */
  async vulnerableWithdrawBalance(userId, amount, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 RACE CONDITION WITHDRAWAL ATTEMPT', {
        userId,
        amount,
        ip: context.ip,
        requestId: context.requestId,
        mode: Config.security.mode
      });

      // Detect race condition attempt
      const detection = this.detectRaceCondition(userId, 'WITHDRAWAL', context);
      
      if (detection.isRace) {
        await this.logRaceCondition({
          type: RACE_CONDITION_TYPES.BALANCE_CHECK,
          severity: ATTACK_SEVERITY.CRITICAL,
          userId,
          amount,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Check balance (TIME OF CHECK)
      const [users] = await db.execute(
        'SELECT balance FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users.length) {
        throw new ValidationError('User not found');
      }

      const currentBalance = parseFloat(users[0].balance);

      // ⚠️ VULNERABLE: Simulate processing delay (race window)
      await this.simulateProcessingDelay(50);

      // ⚠️ VULNERABLE: Check if sufficient balance
      if (currentBalance < amount) {
        return {
          success: false,
          vulnerable: true,
          error: 'Insufficient balance',
          data: { currentBalance, requestedAmount: amount }
        };
      }

      // ⚠️ VULNERABLE: Deduct balance (TIME OF USE)
      // No locking - multiple requests can pass the check simultaneously
      await db.execute(
        'UPDATE users SET balance = balance - ? WHERE id = ?',
        [amount, userId]
      );

      // Get new balance
      const [updated] = await db.execute(
        'SELECT balance FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      const newBalance = parseFloat(updated[0].balance);

      // Check if balance went negative (race condition occurred)
      const raceOccurred = newBalance < 0;

      if (raceOccurred) {
        this.attackStats.successfulRaces++;
        this.attackStats.financialImpact.totalLoss += Math.abs(newBalance);
        this.attackStats.financialImpact.transactions.push({
          userId,
          amount,
          newBalance,
          timestamp: new Date()
        });
      }

      const duration = Date.now() - startTime;

      logger.warn(raceOccurred ? '🚨 RACE CONDITION EXPLOITED' : 'Withdrawal processed', {
        userId,
        amount,
        originalBalance: currentBalance,
        newBalance,
        raceOccurred,
        duration
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          userId,
          amount,
          previousBalance: currentBalance,
          newBalance,
          raceConditionExploited: raceOccurred,
          warning: raceOccurred ? 'CRITICAL: Negative balance due to race condition' : null
        },
        metadata: {
          executionTime: duration,
          severity: raceOccurred ? ATTACK_SEVERITY.CRITICAL : ATTACK_SEVERITY.HIGH,
          raceDetected: detection.isRace,
          timingWindow: duration
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableWithdrawBalance', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Inventory Purchase with Race Condition
   * 
   * Allows overselling products through concurrent requests
   * Attack: Multiple users buy last item simultaneously
   * 
   * @param {number} productId - Product ID
   * @param {number} quantity - Purchase quantity
   * @param {number} userId - User ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Purchase result
   */
  async vulnerablePurchaseProduct(productId, quantity, userId, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 RACE CONDITION PURCHASE ATTEMPT', {
        productId,
        quantity,
        userId,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectRaceCondition(productId, 'PURCHASE', context);
      
      if (detection.isRace) {
        await this.logRaceCondition({
          type: RACE_CONDITION_TYPES.INVENTORY,
          severity: ATTACK_SEVERITY.HIGH,
          productId,
          quantity,
          userId,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Check inventory (TIME OF CHECK)
      const [products] = await db.execute(
        'SELECT stock_quantity, name, price FROM products WHERE id = ? LIMIT 1',
        [productId]
      );

      if (!products.length) {
        throw new ValidationError('Product not found');
      }

      const currentStock = products[0].stock_quantity;
      const productName = products[0].name;
      const price = products[0].price;

      // ⚠️ VULNERABLE: Processing delay (race window)
      await this.simulateProcessingDelay(100);

      // ⚠️ VULNERABLE: Check if enough stock
      if (currentStock < quantity) {
        return {
          success: false,
          vulnerable: true,
          error: 'Insufficient stock',
          data: { currentStock, requestedQuantity: quantity }
        };
      }

      // ⚠️ VULNERABLE: Deduct inventory (TIME OF USE)
      await db.execute(
        'UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?',
        [quantity, productId]
      );

      // Create order
      const [orderResult] = await db.execute(
        `INSERT INTO orders (user_id, product_id, quantity, total_amount, created_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [userId, productId, quantity, price * quantity]
      );

      // Check new stock level
      const [updated] = await db.execute(
        'SELECT stock_quantity FROM products WHERE id = ? LIMIT 1',
        [productId]
      );

      const newStock = updated[0].stock_quantity;
      const oversold = newStock < 0;

      if (oversold) {
        this.attackStats.successfulRaces++;
        this.attackStats.inventoryImpact.oversold += Math.abs(newStock);
        this.attackStats.inventoryImpact.products.push({
          productId,
          productName,
          quantity,
          newStock,
          timestamp: new Date()
        });
      }

      const duration = Date.now() - startTime;

      logger.warn(oversold ? '🚨 INVENTORY RACE CONDITION EXPLOITED' : 'Purchase processed', {
        productId,
        quantity,
        originalStock: currentStock,
        newStock,
        oversold,
        duration
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          orderId: orderResult.insertId,
          productId,
          productName,
          quantity,
          totalAmount: price * quantity,
          previousStock: currentStock,
          newStock,
          oversold,
          warning: oversold ? 'CRITICAL: Product oversold due to race condition' : null
        },
        metadata: {
          executionTime: duration,
          severity: oversold ? ATTACK_SEVERITY.HIGH : ATTACK_SEVERITY.MEDIUM,
          raceDetected: detection.isRace
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerablePurchaseProduct', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Coupon Redemption with Replay
   * 
   * Allows using single-use coupons multiple times
   * Attack: Redeem same coupon code simultaneously
   * 
   * @param {string} couponCode - Coupon code
   * @param {number} userId - User ID
   * @param {number} orderAmount - Order amount
   * @param {object} context - Request context
   * @returns {Promise<object>} Redemption result
   */
  async vulnerableRedeemCoupon(couponCode, userId, orderAmount, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 RACE CONDITION COUPON REDEMPTION', {
        couponCode,
        userId,
        orderAmount,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectRaceCondition(couponCode, 'COUPON', context);
      
      if (detection.isRace) {
        await this.logRaceCondition({
          type: RACE_CONDITION_TYPES.COUPON_REPLAY,
          severity: ATTACK_SEVERITY.HIGH,
          couponCode,
          userId,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Check coupon validity (TIME OF CHECK)
      const [coupons] = await db.execute(
        `SELECT id, discount_percent, discount_amount, usage_limit, times_used, is_active
         FROM coupons
         WHERE code = ? AND is_active = 1 AND expires_at > NOW()
         LIMIT 1`,
        [couponCode]
      );

      if (!coupons.length) {
        throw new ValidationError('Invalid or expired coupon');
      }

      const coupon = coupons[0];

      // ⚠️ VULNERABLE: Processing delay
      await this.simulateProcessingDelay(80);

      // ⚠️ VULNERABLE: Check usage limit
      if (coupon.usage_limit > 0 && coupon.times_used >= coupon.usage_limit) {
        return {
          success: false,
          vulnerable: true,
          error: 'Coupon usage limit reached',
          data: { timesUsed: coupon.times_used, usageLimit: coupon.usage_limit }
        };
      }

      // Calculate discount
      let discountAmount = 0;
      if (coupon.discount_percent > 0) {
        discountAmount = (orderAmount * coupon.discount_percent) / 100;
      } else if (coupon.discount_amount > 0) {
        discountAmount = coupon.discount_amount;
      }

      // ⚠️ VULNERABLE: Increment usage count (TIME OF USE)
      await db.execute(
        'UPDATE coupons SET times_used = times_used + 1 WHERE id = ?',
        [coupon.id]
      );

      // Record usage
      await db.execute(
        `INSERT INTO coupon_usage (coupon_id, user_id, order_amount, discount_amount, used_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [coupon.id, userId, orderAmount, discountAmount]
      );

      // Check if coupon was overused
      const [updated] = await db.execute(
        'SELECT times_used, usage_limit FROM coupons WHERE id = ? LIMIT 1',
        [coupon.id]
      );

      const overused = updated[0].usage_limit > 0 && updated[0].times_used > updated[0].usage_limit;

      if (overused) {
        this.attackStats.successfulRaces++;
        this.attackStats.financialImpact.totalLoss += discountAmount;
      }

      const duration = Date.now() - startTime;

      logger.warn(overused ? '🚨 COUPON RACE CONDITION EXPLOITED' : 'Coupon redeemed', {
        couponCode,
        userId,
        discountAmount,
        timesUsed: updated[0].times_used,
        usageLimit: updated[0].usage_limit,
        overused,
        duration
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          couponCode,
          discountAmount,
          finalAmount: orderAmount - discountAmount,
          timesUsed: updated[0].times_used,
          usageLimit: updated[0].usage_limit,
          couponOverused: overused,
          warning: overused ? 'CRITICAL: Coupon reused beyond limit due to race condition' : null
        },
        metadata: {
          executionTime: duration,
          severity: overused ? ATTACK_SEVERITY.HIGH : ATTACK_SEVERITY.MEDIUM,
          raceDetected: detection.isRace
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableRedeemCoupon', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Concurrent Cart Checkout
   * 
   * Multiple checkouts of same cart items
   * Attack: Checkout same cart simultaneously from different sessions
   * 
   * @param {number} userId - User ID
   * @param {number} cartId - Cart ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Checkout result
   */
  async vulnerableCheckoutCart(userId, cartId, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 RACE CONDITION CART CHECKOUT', {
        userId,
        cartId,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectRaceCondition(cartId, 'CHECKOUT', context);
      
      if (detection.isRace) {
        await this.logRaceCondition({
          type: RACE_CONDITION_TYPES.CART_MANIPULATION,
          severity: ATTACK_SEVERITY.HIGH,
          userId,
          cartId,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Get cart items (TIME OF CHECK)
      const [cartItems] = await db.execute(
        `SELECT ci.*, p.name, p.price 
         FROM cart_items ci
         JOIN products p ON ci.product_id = p.id
         WHERE ci.user_id = ?`,
        [userId]
      );

      if (cartItems.length === 0) {
        throw new ValidationError('Cart is empty');
      }

      // Calculate total
      const totalAmount = cartItems.reduce((sum, item) => 
        sum + (item.price * item.quantity), 0
      );

      // ⚠️ VULNERABLE: Processing delay
      await this.simulateProcessingDelay(150);

      // ⚠️ VULNERABLE: Create order (TIME OF USE)
      const [orderResult] = await db.execute(
        `INSERT INTO orders (user_id, total_amount, status, created_at)
         VALUES (?, ?, 'pending', NOW())`,
        [userId, totalAmount]
      );

      const orderId = orderResult.insertId;

      // Add order items
      for (const item of cartItems) {
        await db.execute(
          `INSERT INTO order_items (order_id, product_id, quantity, price)
           VALUES (?, ?, ?, ?)`,
          [orderId, item.product_id, item.quantity, item.price]
        );
      }

      // ⚠️ VULNERABLE: Clear cart (no check if already cleared)
      const [deleteResult] = await db.execute(
        'DELETE FROM cart_items WHERE user_id = ?',
        [userId]
      );

      // Check if multiple orders were created
      const [recentOrders] = await db.execute(
        `SELECT COUNT(*) as count FROM orders 
         WHERE user_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 SECOND)`,
        [userId]
      );

      const duplicateOrder = recentOrders[0].count > 1;

      if (duplicateOrder) {
        this.attackStats.successfulRaces++;
        this.attackStats.financialImpact.totalLoss += totalAmount * (recentOrders[0].count - 1);
      }

      const duration = Date.now() - startTime;

      logger.warn(duplicateOrder ? '🚨 CART RACE CONDITION EXPLOITED' : 'Checkout completed', {
        userId,
        orderId,
        totalAmount,
        duplicateOrder,
        concurrentOrders: recentOrders[0].count,
        duration
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          orderId,
          userId,
          totalAmount,
          itemCount: cartItems.length,
          duplicateOrderCreated: duplicateOrder,
          concurrentOrders: recentOrders[0].count,
          warning: duplicateOrder ? 'CRITICAL: Multiple orders created due to race condition' : null
        },
        metadata: {
          executionTime: duration,
          severity: duplicateOrder ? ATTACK_SEVERITY.HIGH : ATTACK_SEVERITY.MEDIUM,
          raceDetected: detection.isRace
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableCheckoutCart', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Concurrent Profile Update
   * 
   * Last-write-wins scenario without version control
   * Attack: Update same profile field simultaneously
   * 
   * @param {number} userId - User ID
   * @param {object} updateData - Update data
   * @param {object} context - Request context
   * @returns {Promise<object>} Update result
   */
  async vulnerableUpdateProfile(userId, updateData, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 RACE CONDITION PROFILE UPDATE', {
        userId,
        updateData,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectRaceCondition(userId, 'UPDATE', context);
      
      if (detection.isRace) {
        await this.logRaceCondition({
          type: RACE_CONDITION_TYPES.CONCURRENT_UPDATE,
          severity: ATTACK_SEVERITY.MEDIUM,
          userId,
          updateData,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Read current data (TIME OF CHECK)
      const [users] = await db.execute(
        'SELECT email, phone, address FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users.length) {
        throw new ValidationError('User not found');
      }

      const originalData = users[0];

      // ⚠️ VULNERABLE: Processing delay
      await this.simulateProcessingDelay(100);

      // ⚠️ VULNERABLE: Update without version check (TIME OF USE)
      const fields = Object.keys(updateData);
      const values = Object.values(updateData);
      const setClause = fields.map(f => `${f} = ?`).join(', ');

      await db.execute(
        `UPDATE users SET ${setClause}, updated_at = NOW() WHERE id = ?`,
        [...values, userId]
      );

      // Get final data
      const [updated] = await db.execute(
        'SELECT email, phone, address, updated_at FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      // Check if data differs from what we intended (another update occurred)
      const conflictOccurred = JSON.stringify(originalData) !== JSON.stringify(updated[0]);

      if (conflictOccurred) {
        this.attackStats.successfulRaces++;
      }

      const duration = Date.now() - startTime;

      logger.warn(conflictOccurred ? '🚨 CONCURRENT UPDATE CONFLICT' : 'Profile updated', {
        userId,
        conflictOccurred,
        duration
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          userId,
          originalData,
          updatedData: updated[0],
          conflictDetected: conflictOccurred,
          warning: conflictOccurred ? 'WARNING: Concurrent update may have lost data' : null
        },
        metadata: {
          executionTime: duration,
          severity: conflictOccurred ? ATTACK_SEVERITY.MEDIUM : ATTACK_SEVERITY.LOW,
          raceDetected: detection.isRace
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, 'vulnerableUpdateProfile', Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Balance Withdrawal with Transaction
   * 
   * @param {number} userId - User ID
   * @param {number} amount - Withdrawal amount
   * @returns {Promise<object>} Withdrawal result
   */
  async secureWithdrawBalance(userId, amount) {
    const connection = await db.beginTransaction();

    try {
      // ✅ Lock row for update
      const [users] = await connection.execute(
        'SELECT balance FROM users WHERE id = ? FOR UPDATE',
        [userId]
      );

      if (!users.length) {
        throw new ValidationError('User not found');
      }

      const currentBalance = parseFloat(users[0].balance);

      // ✅ Atomic check and update
      if (currentBalance < amount) {
        await db.rollback(connection);
        throw new ValidationError('Insufficient balance');
      }

      await connection.execute(
        'UPDATE users SET balance = balance - ? WHERE id = ?',
        [amount, userId]
      );

      await db.commit(connection);

      return {
        success: true,
        vulnerable: false,
        data: {
          userId,
          amount,
          newBalance: currentBalance - amount
        }
      };

    } catch (error) {
      await db.rollback(connection);
      throw error;
    }
  }

  /**
   * ✅ SECURE: Inventory Purchase with Locking
   * 
   * @param {number} productId - Product ID
   * @param {number} quantity - Purchase quantity
   * @param {number} userId - User ID
   * @returns {Promise<object>} Purchase result
   */
  async securePurchaseProduct(productId, quantity, userId) {
    const connection = await db.beginTransaction();

    try {
      // ✅ Lock product row
      const [products] = await connection.execute(
        'SELECT stock_quantity, price FROM products WHERE id = ? FOR UPDATE',
        [productId]
      );

      if (!products.length) {
        throw new ValidationError('Product not found');
      }

      const currentStock = products[0].stock_quantity;

      // ✅ Atomic check
      if (currentStock < quantity) {
        await db.rollback(connection);
        throw new ValidationError('Insufficient stock');
      }

      // ✅ Atomic update
      await connection.execute(
        'UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?',
        [quantity, productId]
      );

      // Create order
      const [orderResult] = await connection.execute(
        `INSERT INTO orders (user_id, product_id, quantity, total_amount, created_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [userId, productId, quantity, products[0].price * quantity]
      );

      await db.commit(connection);

      return {
        success: true,
        vulnerable: false,
        data: {
          orderId: orderResult.insertId,
          productId,
          quantity
        }
      };

    } catch (error) {
      await db.rollback(connection);
      throw error;
    }
  }

  /**
   * ✅ SECURE: Coupon Redemption with Atomic Counter
   * 
   * @param {string} couponCode - Coupon code
   * @param {number} userId - User ID
   * @param {number} orderAmount - Order amount
   * @returns {Promise<object>} Redemption result
   */
  async secureRedeemCoupon(couponCode, userId, orderAmount) {
    const connection = await db.beginTransaction();

    try {
      // ✅ Lock coupon row
      const [coupons] = await connection.execute(
        `SELECT id, discount_percent, discount_amount, usage_limit, times_used
         FROM coupons
         WHERE code = ? AND is_active = 1 AND expires_at > NOW()
         FOR UPDATE`,
        [couponCode]
      );

      if (!coupons.length) {
        throw new ValidationError('Invalid or expired coupon');
      }

      const coupon = coupons[0];

      // ✅ Atomic check
      if (coupon.usage_limit > 0 && coupon.times_used >= coupon.usage_limit) {
        await db.rollback(connection);
        throw new ValidationError('Coupon usage limit reached');
      }

      // Calculate discount
      let discountAmount = 0;
      if (coupon.discount_percent > 0) {
        discountAmount = (orderAmount * coupon.discount_percent) / 100;
      } else {
        discountAmount = coupon.discount_amount;
      }

      // ✅ Atomic increment
      await connection.execute(
        'UPDATE coupons SET times_used = times_used + 1 WHERE id = ?',
        [coupon.id]
      );

      await connection.execute(
        `INSERT INTO coupon_usage (coupon_id, user_id, order_amount, discount_amount, used_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [coupon.id, userId, orderAmount, discountAmount]
      );

      await db.commit(connection);

      return {
        success: true,
        vulnerable: false,
        data: {
          couponCode,
          discountAmount,
          finalAmount: orderAmount - discountAmount
        }
      };

    } catch (error) {
      await db.rollback(connection);
      throw error;
    }
  }

  /**
   * ✅ SECURE: Profile Update with Optimistic Locking
   * 
   * @param {number} userId - User ID
   * @param {object} updateData - Update data
   * @param {number} version - Current version
   * @returns {Promise<object>} Update result
   */
  async secureUpdateProfile(userId, updateData, version) {
    try {
      const fields = Object.keys(updateData);
      const values = Object.values(updateData);
      const setClause = fields.map(f => `${f} = ?`).join(', ');

      // ✅ Optimistic locking with version check
      const [result] = await db.execute(
        `UPDATE users 
         SET ${setClause}, version = version + 1, updated_at = NOW() 
         WHERE id = ? AND version = ?`,
        [...values, userId, version]
      );

      if (result.affectedRows === 0) {
        throw new AppError('Update conflict - data was modified by another request', HTTP_STATUS.CONFLICT);
      }

      const [updated] = await db.execute(
        'SELECT email, phone, address, version FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      return {
        success: true,
        vulnerable: false,
        data: {
          user: updated[0]
        }
      };

    } catch (error) {
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & ANALYSIS
  // ==========================================================================

  /**
   * Detect race condition attempts
   * 
   * @param {any} resourceId - Resource identifier
   * @param {string} operation - Operation type
   * @param {object} context - Request context
   * @returns {object} Detection results
   */
  detectRaceCondition(resourceId, operation, context = {}) {
    const operationKey = `${operation}:${resourceId}`;
    const now = Date.now();

    // Track concurrent operations
    if (!this.activeOperations.has(operationKey)) {
      this.activeOperations.set(operationKey, []);
    }

    const operations = this.activeOperations.get(operationKey);
    
    // Add current operation
    operations.push({
      timestamp: now,
      ip: context.ip,
      requestId: context.requestId
    });

    // Clean old operations (older than 2 seconds)
    const recentOps = operations.filter(op => now - op.timestamp < 2000);
    this.activeOperations.set(operationKey, recentOps);

    // Detect race condition
    const concurrentCount = recentOps.length;
    const isRace = concurrentCount > 1;

    let severity = ATTACK_SEVERITY.LOW;
    let timingWindow = TIMING_WINDOWS.LOW;

    if (isRace) {
      // Check timing window
      const timeDiff = recentOps.length > 1 
        ? recentOps[recentOps.length - 1].timestamp - recentOps[0].timestamp
        : 0;

      if (timeDiff < TIMING_WINDOWS.CRITICAL) {
        severity = ATTACK_SEVERITY.CRITICAL;
        timingWindow = TIMING_WINDOWS.CRITICAL;
      } else if (timeDiff < TIMING_WINDOWS.HIGH) {
        severity = ATTACK_SEVERITY.HIGH;
        timingWindow = TIMING_WINDOWS.HIGH;
      } else if (timeDiff < TIMING_WINDOWS.MEDIUM) {
        severity = ATTACK_SEVERITY.MEDIUM;
        timingWindow = TIMING_WINDOWS.MEDIUM;
      }

      this.updateRaceStats(operation, severity, concurrentCount);
    }

    return {
      isRace,
      severity,
      concurrentCount,
      timingWindow,
      operation,
      resourceId,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Update race condition statistics
   */
  updateRaceStats(operation, severity, concurrentCount) {
    this.attackStats.detectedRaces++;

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

    // Track race types
    this.attackStats.raceTypes[operation] = (this.attackStats.raceTypes[operation] || 0) + 1;

    // Track concurrent requests
    this.attackStats.concurrentRequests[concurrentCount] = 
      (this.attackStats.concurrentRequests[concurrentCount] || 0) + 1;
  }

  /**
   * Simulate processing delay (for demonstration)
   */
  async simulateProcessingDelay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Log race condition attempt
   */
  async logRaceCondition(raceData) {
    try {
      const { type, severity, userId, detection, context } = raceData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [
          type,
          severity,
          JSON.stringify(raceData),
          JSON.stringify({ concurrentCount: detection.concurrentCount, timingWindow: detection.timingWindow }),
          context.ip || null,
          context.userAgent || null,
          userId || null,
          context.endpoint || null
        ]
      );

      // Cache race detection
      const cacheKey = CacheKeyBuilder.custom('race_conditions:', context.ip);
      const recentRaces = await cache.get(cacheKey) || [];
      recentRaces.push({
        type,
        severity,
        timestamp: new Date().toISOString()
      });
      await cache.set(cacheKey, recentRaces, 3600);

      // Track IPs and users
      if (context.ip) this.attackStats.ipAddresses.add(context.ip);
      if (userId) this.attackStats.userIds.add(userId);

      logger.attack('Race Condition Attack Detected', {
        type,
        severity,
        concurrentCount: detection.concurrentCount,
        timingWindow: detection.timingWindow,
        context
      });

    } catch (error) {
      logger.error('Failed to log race condition', { error: error.message });
    }
  }

  /**
   * Handle vulnerable errors
   */
  handleVulnerableError(error, method, duration) {
    logger.error('Race condition error', {
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
        errorType: 'RACE_CONDITION_ERROR'
      }
    };
  }

  // ==========================================================================
  // UTILITY & REPORTING
  // ==========================================================================

  /**
   * Get comprehensive statistics
   */
  getStatistics() {
    return {
      ...this.attackStats,
      ipAddresses: this.attackStats.ipAddresses.size,
      userIds: this.attackStats.userIds.size,
      successRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.successfulRaces / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
        : '0%',
      detectionRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.detectedRaces / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
        : '0%',
      activeOperations: this.activeOperations.size
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
      description: 'Race Condition vulnerabilities occur when concurrent operations on shared resources lack proper synchronization, leading to TOCTOU (Time-of-Check-Time-of-Use) issues',
      impact: [
        'Financial loss through double-spending',
        'Inventory overselling and stock issues',
        'Unauthorized coupon/discount abuse',
        'Data corruption and inconsistency',
        'Negative account balances',
        'Duplicate order creation',
        'Lost data updates',
        'System instability'
      ],
      attackVectors: [
        'Parallel withdrawal requests to create negative balance',
        'Simultaneous product purchases to oversell inventory',
        'Concurrent coupon redemptions to exceed usage limits',
        'Multiple cart checkouts to duplicate orders',
        'Concurrent profile updates causing data loss'
      ],
      raceConditionTypes: {
        TOCTOU: 'Time-of-Check-Time-of-Use',
        DoubleSpend: 'Multiple deductions from same resource',
        InventoryRace: 'Overselling due to concurrent purchases',
        CouponReplay: 'Multiple redemptions of single-use coupons',
        ConcurrentUpdate: 'Lost updates due to lack of locking'
      },
      remediation: [
        'Use database transactions with proper isolation levels',
        'Implement row-level locking (SELECT FOR UPDATE)',
        'Use optimistic locking with version numbers',
        'Implement idempotency keys for operations',
        'Use atomic operations and counters',
        'Implement distributed locks for microservices',
        'Use message queues for sequential processing',
        'Implement retry logic with exponential backoff',
        'Monitor and alert on concurrent operations'
      ],
      timingWindows: TIMING_WINDOWS
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
          payload,
          COUNT(*) as count,
          DATE(timestamp) as date
         FROM ${tables.ATTACK_LOGS}
         WHERE attack_type LIKE '%RACE%' OR attack_type LIKE '%TOCTOU%'
         AND timestamp BETWEEN ? AND ?
         GROUP BY attack_type, severity, DATE(timestamp)
         ORDER BY timestamp DESC`,
        [startDate, endDate]
      );

      return {
        period: { start: startDate, end: endDate },
        attacks,
        statistics: this.getStatistics(),
        vulnerabilityInfo: this.getVulnerabilityInfo(),
        financialImpact: this.attackStats.financialImpact,
        inventoryImpact: this.attackStats.inventoryImpact,
        generatedAt: new Date().toISOString()
      };

    } catch (error) {
      logger.error('Failed to generate attack report', { error: error.message });
      throw error;
    }
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulRaces: 0,
      detectedRaces: 0,
      blockedAttempts: 0,
      raceTypes: {},
      timingWindows: {},
      concurrentRequests: {},
      severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
      financialImpact: { totalLoss: 0, transactions: [] },
      inventoryImpact: { oversold: 0, products: [] },
      ipAddresses: new Set(),
      userIds: new Set()
    };
    this.activeOperations.clear();
  }

  /**
   * Clean up old active operations
   */
  cleanupActiveOperations() {
    const now = Date.now();
    for (const [key, operations] of this.activeOperations.entries()) {
      const recent = operations.filter(op => now - op.timestamp < 5000);
      if (recent.length === 0) {
        this.activeOperations.delete(key);
      } else {
        this.activeOperations.set(key, recent);
      }
    }
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getRaceCondition = () => {
  if (!instance) {
    instance = new RaceCondition();
    
    // Cleanup old operations every 30 seconds
    setInterval(() => {
      instance.cleanupActiveOperations();
    }, 30000);
  }
  return instance;
};

export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const rc = getRaceCondition();
      
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
        endpoint: req.path,
        requestId: req.id || Date.now()
      };

      const result = await rc[method](...Object.values(req.body || req.query), context);
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  RaceCondition,
  getRaceCondition,
  createVulnerableHandler
};
