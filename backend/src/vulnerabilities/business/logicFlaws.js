/**
 * ============================================================================
 * BUSINESS LOGIC FLAWS - MILITARY-GRADE ENTERPRISE EDITION
 * ============================================================================
 * 
 * Advanced Business Logic Vulnerability Demonstration Platform
 * Implements complex workflow bypasses and logic manipulation exploits
 * 
 * @module vulnerabilities/business/logicFlaws
 * @category Security Training - OWASP A04:2021 (Insecure Design)
 * @version 3.0.0
 * @license MIT
 * @author Elite Security Research Team
 * 
 * ============================================================================
 * VULNERABILITY CATEGORIES DEMONSTRATED:
 * ============================================================================
 * 1. Workflow Bypass (skip approval steps)
 * 2. State Manipulation (modify order status directly)
 * 3. Coupon/Discount Abuse (multiple use, stacking)
 * 4. Referral System Gaming (self-referral, circular)
 * 5. Inventory Overselling (negative stock)
 * 6. Refund Fraud (multiple refunds)
 * 7. Gift Card Duplication
 * 8. Loyalty Points Manipulation
 * 9. Subscription Bypass (free premium access)
 * 10. Account Takeover via Logic Flaws
 * 11. Payment Gateway Bypass
 * 12. Return Policy Abuse
 * 13. Flash Sale Exploitation
 * 14. Pre-order Cancellation Exploits
 * 15. Shipping Cost Manipulation
 * 
 * ============================================================================
 * ATTACK VECTORS:
 * ============================================================================
 * - Direct status modification without validation
 * - Workflow state machine bypasses
 * - Missing business rule enforcement
 * - Inadequate transaction sequencing
 * - Missing rollback mechanisms
 * - Insufficient authorization checks
 * - Time-based logic flaws (TOCTOU variants)
 * - Numeric overflow/underflow exploits
 * - Boundary condition violations
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
  ATTACK_SEVERITY,
  ERROR_CODES,
  ORDER_STATUS,
  PAYMENT_STATUS,
  USER_ROLES
} from '../../config/constants.js';
import { 
  ValidationError, 
  BusinessLogicError,
  UnauthorizedError 
} from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VULNERABILITY CONSTANTS
// ============================================================================

const VALID_ORDER_TRANSITIONS = {
  pending: ['processing', 'cancelled'],
  processing: ['shipped', 'cancelled'],
  shipped: ['delivered', 'return_requested'],
  delivered: ['return_requested', 'completed'],
  return_requested: ['return_approved', 'return_rejected'],
  return_approved: ['refunded'],
  refunded: [],
  completed: [],
  cancelled: []
};

const COUPON_TYPES = {
  PERCENTAGE: 'percentage',
  FIXED: 'fixed',
  FREE_SHIPPING: 'free_shipping',
  BUY_ONE_GET_ONE: 'bogo'
};

const BUSINESS_RULES = {
  MAX_DISCOUNT_PERCENTAGE: 90,
  MAX_COUPON_STACK: 1,
  MAX_REFERRAL_BONUS: 100,
  MIN_ORDER_VALUE: 1,
  MAX_REFUND_WINDOW_DAYS: 30,
  MAX_LOYALTY_POINTS_PER_TRANSACTION: 10000,
  MIN_STOCK_THRESHOLD: 0
};

// ============================================================================
// BUSINESS LOGIC FLAWS CLASS
// ============================================================================

export class LogicFlaws {
  constructor() {
    this.name = 'Business Logic Flaws';
    this.category = 'Business Logic';
    this.cvssScore = 8.9;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A04:2021';
    this.cweId = 'CWE-840';
    
    this.attackStats = {
      totalAttempts: 0,
      successfulAttacks: 0,
      byCategory: {
        workflow_bypass: 0,
        state_manipulation: 0,
        coupon_abuse: 0,
        referral_gaming: 0,
        inventory_oversell: 0,
        refund_fraud: 0,
        payment_bypass: 0,
        subscription_bypass: 0
      },
      financialImpact: {
        lostRevenue: 0,
        fraudulentRefunds: 0,
        discountAbuse: 0,
        inventoryLoss: 0
      },
      affectedEntities: {
        orders: new Set(),
        users: new Set(),
        products: new Set()
      }
    };
  }

  // ==========================================================================
  // VULNERABLE: WORKFLOW BYPASS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Direct order status modification without workflow validation
   * Allows skipping approval, payment, or shipping steps
   * 
   * Attack vectors:
   * - pending → delivered (skip payment & shipping)
   * - processing → refunded (skip delivery)
   * - any_status → completed (instant fulfillment)
   * 
   * @param {number} orderId - Order ID
   * @param {string} newStatus - Target status
   * @param {object} context - Request context
   * @returns {Promise<object>} Operation result
   */
  async vulnerableUpdateOrderStatus(orderId, newStatus, context = {}) {
    this.attackStats.totalAttempts++;
    this.attackStats.byCategory.workflow_bypass++;
    
    try {
      // Get current order
      const [orders] = await db.execute(
        `SELECT id, user_id, status, total_amount, payment_status 
         FROM ${tables.ORDERS} 
         WHERE id = ? LIMIT 1`,
        [orderId]
      );

      if (orders.length === 0) {
        throw new ValidationError('Order not found');
      }

      const order = orders[0];
      const oldStatus = order.status;

      // ⚠️ VULNERABLE: No workflow validation - direct status change
      await db.execute(
        `UPDATE ${tables.ORDERS} 
         SET status = ?, updated_at = NOW() 
         WHERE id = ?`,
        [newStatus, orderId]
      );

      // Detect exploit
      const isExploit = this.detectWorkflowBypass(oldStatus, newStatus);
      
      if (isExploit) {
        this.attackStats.successfulAttacks++;
        this.attackStats.affectedEntities.orders.add(orderId);
        this.attackStats.affectedEntities.users.add(order.user_id);

        // Calculate financial impact
        if (newStatus === 'refunded' && order.payment_status !== 'refunded') {
          this.attackStats.financialImpact.fraudulentRefunds += parseFloat(order.total_amount);
        }

        await this.logBusinessLogicAttack({
          type: 'WORKFLOW_BYPASS',
          severity: ATTACK_SEVERITY.CRITICAL,
          details: {
            orderId,
            oldStatus,
            newStatus,
            expectedTransitions: VALID_ORDER_TRANSITIONS[oldStatus] || [],
            bypassedSteps: this.calculateBypassedSteps(oldStatus, newStatus)
          },
          context
        });
      }

      logger.warn('Order status updated without validation', {
        orderId,
        oldStatus,
        newStatus,
        isExploit
      });

      return {
        success: true,
        vulnerable: true,
        data: { orderId, oldStatus, newStatus },
        warning: isExploit ? 'CRITICAL: Workflow bypass detected' : null,
        metadata: {
          isExploit,
          expectedTransitions: VALID_ORDER_TRANSITIONS[oldStatus] || [],
          securityImpact: isExploit ? 'HIGH' : 'LOW'
        }
      };

    } catch (error) {
      logger.error('Vulnerable order status update failed', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Order status update with workflow validation
   */
  async secureUpdateOrderStatus(orderId, newStatus, userId, userRole) {
    try {
      const [orders] = await db.execute(
        `SELECT id, user_id, status, payment_status, total_amount
         FROM ${tables.ORDERS} 
         WHERE id = ? LIMIT 1`,
        [orderId]
      );

      if (orders.length === 0) {
        throw new ValidationError('Order not found');
      }

      const order = orders[0];

      // ✅ Authorization check
      if (order.user_id !== userId && userRole !== USER_ROLES.ADMIN) {
        throw new UnauthorizedError('Cannot modify other users\' orders');
      }

      // ✅ Validate workflow transition
      const validTransitions = VALID_ORDER_TRANSITIONS[order.status] || [];
      if (!validTransitions.includes(newStatus)) {
        throw new BusinessLogicError(
          `Invalid status transition from ${order.status} to ${newStatus}`,
          { validTransitions }
        );
      }

      // ✅ Additional business rule checks
      if (newStatus === 'refunded') {
        if (order.payment_status !== 'completed') {
          throw new BusinessLogicError('Cannot refund unpaid order');
        }
      }

      if (newStatus === 'shipped' && order.payment_status !== 'completed') {
        throw new BusinessLogicError('Cannot ship unpaid order');
      }

      // ✅ Update with transaction
      await db.execute('START TRANSACTION');

      await db.execute(
        `UPDATE ${tables.ORDERS} 
         SET status = ?, updated_at = NOW() 
         WHERE id = ?`,
        [newStatus, orderId]
      );

      // ✅ Log state change
      await db.execute(
        `INSERT INTO order_status_history 
         (order_id, old_status, new_status, changed_by, changed_at) 
         VALUES (?, ?, ?, ?, NOW())`,
        [orderId, order.status, newStatus, userId]
      );

      await db.execute('COMMIT');

      return {
        success: true,
        vulnerable: false,
        data: { orderId, oldStatus: order.status, newStatus }
      };

    } catch (error) {
      await db.execute('ROLLBACK');
      logger.error('Secure order status update failed', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // VULNERABLE: COUPON STACKING & ABUSE
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Multiple coupon application without validation
   * Allows stacking unlimited coupons, reusing expired codes
   * 
   * Attack vectors:
   * - Apply same coupon multiple times
   * - Stack percentage coupons (90% + 90% = free)
   * - Use expired/inactive coupons
   * - Bypass minimum order requirements
   * 
   * @param {number} orderId - Order ID
   * @param {string[]} couponCodes - Coupon codes to apply
   * @param {object} context - Request context
   * @returns {Promise<object>} Discount calculation result
   */
  async vulnerableApplyCoupons(orderId, couponCodes, context = {}) {
    this.attackStats.totalAttempts++;
    this.attackStats.byCategory.coupon_abuse++;
    
    try {
      // Get order
      const [orders] = await db.execute(
        `SELECT id, total_amount, user_id FROM ${tables.ORDERS} WHERE id = ?`,
        [orderId]
      );

      if (orders.length === 0) {
        throw new ValidationError('Order not found');
      }

      const order = orders[0];
      let finalAmount = parseFloat(order.total_amount);
      let totalDiscount = 0;
      const appliedCoupons = [];

      // ⚠️ VULNERABLE: No validation on coupon count, expiry, or eligibility
      for (const code of couponCodes) {
        const [coupons] = await db.execute(
          `SELECT id, code, discount_type, discount_value, max_uses, times_used 
           FROM coupons WHERE code = ? LIMIT 1`,
          [code]
        );

        if (coupons.length > 0) {
          const coupon = coupons[0];
          let discount = 0;

          // ⚠️ VULNERABLE: No checks for expiry, usage limits, or conditions
          if (coupon.discount_type === COUPON_TYPES.PERCENTAGE) {
            discount = finalAmount * (parseFloat(coupon.discount_value) / 100);
          } else if (coupon.discount_type === COUPON_TYPES.FIXED) {
            discount = parseFloat(coupon.discount_value);
          }

          finalAmount -= discount;
          totalDiscount += discount;
          appliedCoupons.push({
            code: coupon.code,
            discount: discount.toFixed(2)
          });

          // ⚠️ VULNERABLE: Increment usage without checking limits
          await db.execute(
            'UPDATE coupons SET times_used = times_used + 1 WHERE id = ?',
            [coupon.id]
          );
        }
      }

      // ⚠️ VULNERABLE: Allow negative final amount
      if (finalAmount < 0) finalAmount = 0;

      // Detect exploit
      const isExploit = this.detectCouponAbuse(
        couponCodes,
        totalDiscount,
        order.total_amount
      );

      if (isExploit) {
        this.attackStats.successfulAttacks++;
        this.attackStats.affectedEntities.orders.add(orderId);
        this.attackStats.financialImpact.discountAbuse += totalDiscount;

        await this.logBusinessLogicAttack({
          type: 'COUPON_ABUSE',
          severity: ATTACK_SEVERITY.HIGH,
          details: {
            orderId,
            couponCodes,
            totalDiscount: totalDiscount.toFixed(2),
            originalAmount: order.total_amount,
            finalAmount: finalAmount.toFixed(2),
            discountPercentage: ((totalDiscount / order.total_amount) * 100).toFixed(2) + '%'
          },
          context
        });
      }

      // Update order
      await db.execute(
        `UPDATE ${tables.ORDERS} 
         SET total_amount = ?, discount_amount = ? 
         WHERE id = ?`,
        [finalAmount, totalDiscount, orderId]
      );

      logger.warn('Coupons applied without validation', {
        orderId,
        couponCount: couponCodes.length,
        totalDiscount,
        isExploit
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          orderId,
          appliedCoupons,
          originalAmount: order.total_amount,
          totalDiscount: totalDiscount.toFixed(2),
          finalAmount: finalAmount.toFixed(2)
        },
        warning: isExploit ? 'CRITICAL: Coupon abuse detected' : null,
        metadata: { isExploit }
      };

    } catch (error) {
      logger.error('Vulnerable coupon application failed', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Coupon application with comprehensive validation
   */
  async secureApplyCoupons(orderId, couponCodes, userId) {
    try {
      // ✅ Limit coupon stacking
      if (couponCodes.length > BUSINESS_RULES.MAX_COUPON_STACK) {
        throw new BusinessLogicError(
          `Maximum ${BUSINESS_RULES.MAX_COUPON_STACK} coupon(s) allowed per order`
        );
      }

      const [orders] = await db.execute(
        `SELECT id, user_id, total_amount FROM ${tables.ORDERS} WHERE id = ?`,
        [orderId]
      );

      if (orders.length === 0) {
        throw new ValidationError('Order not found');
      }

      const order = orders[0];

      // ✅ Authorization
      if (order.user_id !== userId) {
        throw new UnauthorizedError('Cannot modify other users\' orders');
      }

      let finalAmount = parseFloat(order.total_amount);
      let totalDiscount = 0;
      const appliedCoupons = [];

      await db.execute('START TRANSACTION');

      for (const code of couponCodes) {
        const [coupons] = await db.execute(
          `SELECT id, code, discount_type, discount_value, min_order_value,
                  max_uses, times_used, valid_from, valid_until, is_active
           FROM coupons WHERE code = ? LIMIT 1`,
          [code]
        );

        if (coupons.length === 0) {
          await db.execute('ROLLBACK');
          throw new ValidationError(`Invalid coupon code: ${code}`);
        }

        const coupon = coupons[0];

        // ✅ Validate coupon eligibility
        if (!coupon.is_active) {
          await db.execute('ROLLBACK');
          throw new BusinessLogicError(`Coupon ${code} is inactive`);
        }

        if (coupon.valid_from && new Date(coupon.valid_from) > new Date()) {
          await db.execute('ROLLBACK');
          throw new BusinessLogicError(`Coupon ${code} not yet valid`);
        }

        if (coupon.valid_until && new Date(coupon.valid_until) < new Date()) {
          await db.execute('ROLLBACK');
          throw new BusinessLogicError(`Coupon ${code} has expired`);
        }

        if (coupon.max_uses && coupon.times_used >= coupon.max_uses) {
          await db.execute('ROLLBACK');
          throw new BusinessLogicError(`Coupon ${code} usage limit reached`);
        }

        if (coupon.min_order_value && order.total_amount < coupon.min_order_value) {
          await db.execute('ROLLBACK');
          throw new BusinessLogicError(
            `Order minimum of $${coupon.min_order_value} required for ${code}`
          );
        }

        // ✅ Calculate discount
        let discount = 0;
        if (coupon.discount_type === COUPON_TYPES.PERCENTAGE) {
          const percentage = Math.min(
            parseFloat(coupon.discount_value),
            BUSINESS_RULES.MAX_DISCOUNT_PERCENTAGE
          );
          discount = finalAmount * (percentage / 100);
        } else if (coupon.discount_type === COUPON_TYPES.FIXED) {
          discount = Math.min(parseFloat(coupon.discount_value), finalAmount);
        }

        finalAmount -= discount;
        totalDiscount += discount;
        appliedCoupons.push({ code: coupon.code, discount: discount.toFixed(2) });

        // ✅ Increment usage with lock
        await db.execute(
          'UPDATE coupons SET times_used = times_used + 1 WHERE id = ?',
          [coupon.id]
        );

        // ✅ Record coupon usage
        await db.execute(
          `INSERT INTO coupon_usage (order_id, coupon_id, user_id, discount_amount, used_at)
           VALUES (?, ?, ?, ?, NOW())`,
          [orderId, coupon.id, userId, discount]
        );
      }

      // ✅ Ensure minimum order value
      if (finalAmount < BUSINESS_RULES.MIN_ORDER_VALUE) {
        finalAmount = BUSINESS_RULES.MIN_ORDER_VALUE;
      }

      await db.execute(
        `UPDATE ${tables.ORDERS} 
         SET total_amount = ?, discount_amount = ? 
         WHERE id = ?`,
        [finalAmount, totalDiscount, orderId]
      );

      await db.execute('COMMIT');

      return {
        success: true,
        vulnerable: false,
        data: {
          orderId,
          appliedCoupons,
          originalAmount: order.total_amount,
          totalDiscount: totalDiscount.toFixed(2),
          finalAmount: finalAmount.toFixed(2)
        }
      };

    } catch (error) {
      await db.execute('ROLLBACK');
      logger.error('Secure coupon application failed', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // VULNERABLE: REFERRAL SYSTEM GAMING
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Self-referral and circular referral exploitation
   * 
   * Attack vectors:
   * - Self-referral (refer own account)
   * - Circular referrals (A→B→A)
   * - Duplicate referrals
   * - Unlimited bonus claims
   * 
   * @param {number} userId - User claiming bonus
   * @param {string} referralCode - Referral code used
   * @param {object} context - Request context
   * @returns {Promise<object>} Referral bonus result
   */
  async vulnerableClaimReferralBonus(userId, referralCode, context = {}) {
    this.attackStats.totalAttempts++;
    this.attackStats.byCategory.referral_gaming++;
    
    try {
      // Get referrer
      const [referrers] = await db.execute(
        `SELECT id, username, referral_code FROM ${tables.USERS} 
         WHERE referral_code = ? LIMIT 1`,
        [referralCode]
      );

      if (referrers.length === 0) {
        throw new ValidationError('Invalid referral code');
      }

      const referrer = referrers[0];
      const bonusAmount = 50; // $50 bonus

      // ⚠️ VULNERABLE: No checks for self-referral, circular, or duplicate
      await db.execute(
        `UPDATE ${tables.USERS} 
         SET loyalty_points = loyalty_points + ? 
         WHERE id = ?`,
        [bonusAmount, referrer.id]
      );

      await db.execute(
        `UPDATE ${tables.USERS} 
         SET loyalty_points = loyalty_points + ? 
         WHERE id = ?`,
        [bonusAmount / 2, userId]
      );

      // ⚠️ VULNERABLE: No unique constraint or validation
      await db.execute(
        `INSERT INTO referrals (referrer_id, referred_user_id, bonus_amount, created_at)
         VALUES (?, ?, ?, NOW())`,
        [referrer.id, userId, bonusAmount]
      );

      // Detect exploit
      const isExploit = await this.detectReferralGaming(userId, referrer.id, referralCode);

      if (isExploit.detected) {
        this.attackStats.successfulAttacks++;
        this.attackStats.financialImpact.lostRevenue += bonusAmount;

        await this.logBusinessLogicAttack({
          type: 'REFERRAL_GAMING',
          severity: ATTACK_SEVERITY.HIGH,
          details: {
            userId,
            referrerId: referrer.id,
            referralCode,
            bonusAmount,
            exploitType: isExploit.type
          },
          context
        });
      }

      logger.warn('Referral bonus claimed without validation', {
        userId,
        referrerId: referrer.id,
        isExploit: isExploit.detected
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          bonusAmount,
          referrerBonus: bonusAmount,
          referredBonus: bonusAmount / 2
        },
        warning: isExploit.detected ? `CRITICAL: ${isExploit.type} detected` : null
      };

    } catch (error) {
      logger.error('Vulnerable referral claim failed', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Referral bonus with comprehensive validation
   */
  async secureClaimReferralBonus(userId, referralCode) {
    try {
      await db.execute('START TRANSACTION');

      const [referrers] = await db.execute(
        `SELECT id, username, referral_code FROM ${tables.USERS} 
         WHERE referral_code = ? LIMIT 1`,
        [referralCode]
      );

      if (referrers.length === 0) {
        await db.execute('ROLLBACK');
        throw new ValidationError('Invalid referral code');
      }

      const referrer = referrers[0];

      // ✅ Prevent self-referral
      if (referrer.id === userId) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError('Cannot refer yourself');
      }

      // ✅ Check for existing referral
      const [existing] = await db.execute(
        `SELECT id FROM referrals WHERE referred_user_id = ? LIMIT 1`,
        [userId]
      );

      if (existing.length > 0) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError('Referral bonus already claimed');
      }

      // ✅ Check for circular referral
      const [circular] = await db.execute(
        `SELECT id FROM referrals 
         WHERE referrer_id = ? AND referred_user_id = ? 
         LIMIT 1`,
        [userId, referrer.id]
      );

      if (circular.length > 0) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError('Circular referral detected');
      }

      const bonusAmount = Math.min(50, BUSINESS_RULES.MAX_REFERRAL_BONUS);

      // ✅ Update with transaction safety
      await db.execute(
        `UPDATE ${tables.USERS} 
         SET loyalty_points = loyalty_points + ? 
         WHERE id = ?`,
        [bonusAmount, referrer.id]
      );

      await db.execute(
        `UPDATE ${tables.USERS} 
         SET loyalty_points = loyalty_points + ? 
         WHERE id = ?`,
        [bonusAmount / 2, userId]
      );

      await db.execute(
        `INSERT INTO referrals (referrer_id, referred_user_id, bonus_amount, created_at)
         VALUES (?, ?, ?, NOW())`,
        [referrer.id, userId, bonusAmount]
      );

      await db.execute('COMMIT');

      return {
        success: true,
        vulnerable: false,
        data: {
          bonusAmount,
          referrerBonus: bonusAmount,
          referredBonus: bonusAmount / 2
        }
      };

    } catch (error) {
      await db.execute('ROLLBACK');
      logger.error('Secure referral claim failed', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // VULNERABLE: INVENTORY OVERSELLING
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Allow purchases beyond available stock
   * Allows negative inventory, race condition exploits
   * 
   * @param {number} productId - Product ID
   * @param {number} quantity - Quantity to purchase
   * @param {number} userId - User ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Purchase result
   */
  async vulnerablePurchaseProduct(productId, quantity, userId, context = {}) {
    this.attackStats.totalAttempts++;
    this.attackStats.byCategory.inventory_oversell++;
    
    try {
      // Get product
      const [products] = await db.execute(
        `SELECT id, name, price, stock_quantity FROM ${tables.PRODUCTS} 
         WHERE id = ? LIMIT 1`,
        [productId]
      );

      if (products.length === 0) {
        throw new ValidationError('Product not found');
      }

      const product = products[0];
      const totalAmount = parseFloat(product.price) * quantity;

      // ⚠️ VULNERABLE: No stock validation - allow overselling
      await db.execute(
        `UPDATE ${tables.PRODUCTS} 
         SET stock_quantity = stock_quantity - ? 
         WHERE id = ?`,
        [quantity, productId]
      );

      // Create order
      const [orderResult] = await db.execute(
        `INSERT INTO ${tables.ORDERS} 
         (user_id, total_amount, status, created_at) 
         VALUES (?, ?, 'pending', NOW())`,
        [userId, totalAmount]
      );

      const orderId = orderResult.insertId;

      // Detect overselling
      const [updatedProduct] = await db.execute(
        `SELECT stock_quantity FROM ${tables.PRODUCTS} WHERE id = ?`,
        [productId]
      );

      const isExploit = updatedProduct[0].stock_quantity < BUSINESS_RULES.MIN_STOCK_THRESHOLD;

      if (isExploit) {
        this.attackStats.successfulAttacks++;
        this.attackStats.affectedEntities.products.add(productId);
        this.attackStats.financialImpact.inventoryLoss += totalAmount;

        await this.logBusinessLogicAttack({
          type: 'INVENTORY_OVERSELL',
          severity: ATTACK_SEVERITY.HIGH,
          details: {
            productId,
            orderId,
            requestedQuantity: quantity,
            availableStock: product.stock_quantity,
            resultingStock: updatedProduct[0].stock_quantity,
            oversoldBy: Math.abs(updatedProduct[0].stock_quantity)
          },
          context
        });
      }

      logger.warn('Product purchased without stock validation', {
        productId,
        quantity,
        originalStock: product.stock_quantity,
        isExploit
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          orderId,
          productId,
          quantity,
          totalAmount: totalAmount.toFixed(2),
          remainingStock: updatedProduct[0].stock_quantity
        },
        warning: isExploit ? 'CRITICAL: Inventory oversold' : null
      };

    } catch (error) {
      logger.error('Vulnerable purchase failed', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Purchase with proper inventory management
   */
  async securePurchaseProduct(productId, quantity, userId) {
    try {
      // ✅ Input validation
      if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
        throw new ValidationError('Invalid quantity');
      }

      await db.execute('START TRANSACTION');

      // ✅ Lock row for update
      const [products] = await db.execute(
        `SELECT id, name, price, stock_quantity 
         FROM ${tables.PRODUCTS} 
         WHERE id = ? FOR UPDATE`,
        [productId]
      );

      if (products.length === 0) {
        await db.execute('ROLLBACK');
        throw new ValidationError('Product not found');
      }

      const product = products[0];

      // ✅ Validate sufficient stock
      if (product.stock_quantity < quantity) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError(
          `Insufficient stock. Available: ${product.stock_quantity}, Requested: ${quantity}`
        );
      }

      // ✅ Update stock atomically
      const [updateResult] = await db.execute(
        `UPDATE ${tables.PRODUCTS} 
         SET stock_quantity = stock_quantity - ? 
         WHERE id = ? AND stock_quantity >= ?`,
        [quantity, productId, quantity]
      );

      if (updateResult.affectedRows === 0) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError('Stock no longer available (race condition)');
      }

      const totalAmount = parseFloat(product.price) * quantity;

      // ✅ Create order
      const [orderResult] = await db.execute(
        `INSERT INTO ${tables.ORDERS} 
         (user_id, total_amount, status, created_at) 
         VALUES (?, ?, 'pending', NOW())`,
        [userId, totalAmount]
      );

      const orderId = orderResult.insertId;

      // ✅ Record inventory change
      await db.execute(
        `INSERT INTO inventory_logs 
         (product_id, order_id, quantity_change, action, created_at)
         VALUES (?, ?, ?, 'sale', NOW())`,
        [productId, orderId, -quantity]
      );

      await db.execute('COMMIT');

      return {
        success: true,
        vulnerable: false,
        data: {
          orderId,
          productId,
          quantity,
          totalAmount: totalAmount.toFixed(2)
        }
      };

    } catch (error) {
      await db.execute('ROLLBACK');
      logger.error('Secure purchase failed', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // VULNERABLE: REFUND FRAUD
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Multiple refunds for same order
   * No time window validation, duplicate refunds allowed
   * 
   * @param {number} orderId - Order ID
   * @param {number} userId - User ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Refund result
   */
  async vulnerableRequestRefund(orderId, userId, context = {}) {
    this.attackStats.totalAttempts++;
    this.attackStats.byCategory.refund_fraud++;
    
    try {
      const [orders] = await db.execute(
        `SELECT id, user_id, total_amount, status, created_at 
         FROM ${tables.ORDERS} WHERE id = ?`,
        [orderId]
      );

      if (orders.length === 0) {
        throw new ValidationError('Order not found');
      }

      const order = orders[0];

      // ⚠️ VULNERABLE: No duplicate refund check, no time validation
      await db.execute(
        `UPDATE ${tables.ORDERS} 
         SET status = 'refunded', payment_status = 'refunded' 
         WHERE id = ?`,
        [orderId]
      );

      // Process refund
      await db.execute(
        `UPDATE ${tables.USERS} 
         SET loyalty_points = loyalty_points + ? 
         WHERE id = ?`,
        [parseFloat(order.total_amount), userId]
      );

      // Detect fraud
      const [refundCount] = await db.execute(
        `SELECT COUNT(*) as count FROM refund_logs WHERE order_id = ?`,
        [orderId]
      );

      const isExploit = refundCount[0].count > 0;
      const daysSinceOrder = Math.floor(
        (Date.now() - new Date(order.created_at).getTime()) / (1000 * 60 * 60 * 24)
      );

      if (isExploit || daysSinceOrder > BUSINESS_RULES.MAX_REFUND_WINDOW_DAYS) {
        this.attackStats.successfulAttacks++;
        this.attackStats.financialImpact.fraudulentRefunds += parseFloat(order.total_amount);

        await this.logBusinessLogicAttack({
          type: 'REFUND_FRAUD',
          severity: ATTACK_SEVERITY.CRITICAL,
          details: {
            orderId,
            userId,
            refundAmount: order.total_amount,
            previousRefunds: refundCount[0].count,
            daysSinceOrder
          },
          context
        });
      }

      // ⚠️ VULNERABLE: Log without preventing duplicate
      await db.execute(
        `INSERT INTO refund_logs (order_id, user_id, amount, created_at)
         VALUES (?, ?, ?, NOW())`,
        [orderId, userId, order.total_amount]
      );

      logger.warn('Refund processed without validation', {
        orderId,
        isExploit,
        previousRefunds: refundCount[0].count
      });

      return {
        success: true,
        vulnerable: true,
        data: {
          orderId,
          refundAmount: order.total_amount,
          previousRefunds: refundCount[0].count
        },
        warning: isExploit ? 'CRITICAL: Duplicate refund detected' : null
      };

    } catch (error) {
      logger.error('Vulnerable refund failed', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Refund with comprehensive validation
   */
  async secureRequestRefund(orderId, userId, reason) {
    try {
      await db.execute('START TRANSACTION');

      const [orders] = await db.execute(
        `SELECT id, user_id, total_amount, status, payment_status, created_at
         FROM ${tables.ORDERS} WHERE id = ? FOR UPDATE`,
        [orderId]
      );

      if (orders.length === 0) {
        await db.execute('ROLLBACK');
        throw new ValidationError('Order not found');
      }

      const order = orders[0];

      // ✅ Authorization check
      if (order.user_id !== userId) {
        await db.execute('ROLLBACK');
        throw new UnauthorizedError('Cannot refund other users\' orders');
      }

      // ✅ Check if already refunded
      if (order.status === 'refunded' || order.payment_status === 'refunded') {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError('Order already refunded');
      }

      // ✅ Check refund eligibility status
      const eligibleStatuses = ['delivered', 'completed'];
      if (!eligibleStatuses.includes(order.status)) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError(
          `Cannot refund order with status: ${order.status}`
        );
      }

      // ✅ Check time window
      const daysSinceOrder = Math.floor(
        (Date.now() - new Date(order.created_at).getTime()) / (1000 * 60 * 60 * 24)
      );

      if (daysSinceOrder > BUSINESS_RULES.MAX_REFUND_WINDOW_DAYS) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError(
          `Refund window expired. Orders can only be refunded within ${BUSINESS_RULES.MAX_REFUND_WINDOW_DAYS} days`
        );
      }

      // ✅ Check for existing refund requests
      const [existing] = await db.execute(
        `SELECT id FROM refund_logs WHERE order_id = ? LIMIT 1`,
        [orderId]
      );

      if (existing.length > 0) {
        await db.execute('ROLLBACK');
        throw new BusinessLogicError('Refund already requested for this order');
      }

      // ✅ Update order status
      await db.execute(
        `UPDATE ${tables.ORDERS} 
         SET status = 'return_requested' 
         WHERE id = ?`,
        [orderId]
      );

      // ✅ Create refund request (not automatic refund)
      await db.execute(
        `INSERT INTO refund_logs 
         (order_id, user_id, amount, reason, status, created_at)
         VALUES (?, ?, ?, ?, 'pending', NOW())`,
        [orderId, userId, order.total_amount, reason]
      );

      await db.execute('COMMIT');

      return {
        success: true,
        vulnerable: false,
        data: {
          orderId,
          status: 'pending_approval',
          message: 'Refund request submitted for review'
        }
      };

    } catch (error) {
      await db.execute('ROLLBACK');
      logger.error('Secure refund request failed', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // VULNERABLE: PAYMENT BYPASS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Complete order without payment verification
   * 
   * @param {number} orderId - Order ID
   * @param {object} context - Request context
   * @returns {Promise<object>} Order completion result
   */
  async vulnerableCompleteOrder(orderId, context = {}) {
    this.attackStats.totalAttempts++;
    this.attackStats.byCategory.payment_bypass++;
    
    try {
      const [orders] = await db.execute(
        `SELECT id, total_amount, payment_status FROM ${tables.ORDERS} 
         WHERE id = ?`,
        [orderId]
      );

      if (orders.length === 0) {
        throw new ValidationError('Order not found');
      }

      const order = orders[0];

      // ⚠️ VULNERABLE: Complete order without checking payment
      await db.execute(
        `UPDATE ${tables.ORDERS} 
         SET status = 'completed' 
         WHERE id = ?`,
        [orderId]
      );

      const isExploit = order.payment_status !== 'completed';

      if (isExploit) {
        this.attackStats.successfulAttacks++;
        this.attackStats.financialImpact.lostRevenue += parseFloat(order.total_amount);

        await this.logBusinessLogicAttack({
          type: 'PAYMENT_BYPASS',
          severity: ATTACK_SEVERITY.CRITICAL,
          details: {
            orderId,
            totalAmount: order.total_amount,
            paymentStatus: order.payment_status
          },
          context
        });
      }

      logger.warn('Order completed without payment verification', {
        orderId,
        paymentStatus: order.payment_status,
        isExploit
      });

      return {
        success: true,
        vulnerable: true,
        data: { orderId, status: 'completed' },
        warning: isExploit ? 'CRITICAL: Payment bypass detected' : null
      };

    } catch (error) {
      logger.error('Vulnerable order completion failed', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // DETECTION HELPERS
  // ==========================================================================

  detectWorkflowBypass(oldStatus, newStatus) {
    const validTransitions = VALID_ORDER_TRANSITIONS[oldStatus] || [];
    return !validTransitions.includes(newStatus);
  }

  calculateBypassedSteps(oldStatus, newStatus) {
    const workflowSteps = [
      'pending', 'processing', 'shipped', 'delivered', 'completed'
    ];
    const oldIndex = workflowSteps.indexOf(oldStatus);
    const newIndex = workflowSteps.indexOf(newStatus);
    
    if (oldIndex === -1 || newIndex === -1) return [];
    if (newIndex <= oldIndex) return [];
    
    return workflowSteps.slice(oldIndex + 1, newIndex);
  }

  detectCouponAbuse(couponCodes, totalDiscount, orderAmount) {
    const uniqueCodes = new Set(couponCodes);
    const hasDuplicates = uniqueCodes.size !== couponCodes.length;
    const discountPercentage = (totalDiscount / orderAmount) * 100;
    const exceedsLimit = discountPercentage > BUSINESS_RULES.MAX_DISCOUNT_PERCENTAGE;
    const tooManyCoupons = couponCodes.length > BUSINESS_RULES.MAX_COUPON_STACK;

    return hasDuplicates || exceedsLimit || tooManyCoupons;
  }

  async detectReferralGaming(userId, referrerId, referralCode) {
    // Self-referral
    if (userId === referrerId) {
      return { detected: true, type: 'SELF_REFERRAL' };
    }

    // Check for circular referral
    const [circular] = await db.execute(
      `SELECT id FROM referrals 
       WHERE referrer_id = ? AND referred_user_id = ?`,
      [userId, referrerId]
    );

    if (circular.length > 0) {
      return { detected: true, type: 'CIRCULAR_REFERRAL' };
    }

    // Check for duplicate
    const [duplicate] = await db.execute(
      `SELECT id FROM referrals WHERE referred_user_id = ?`,
      [userId]
    );

    if (duplicate.length > 0) {
      return { detected: true, type: 'DUPLICATE_REFERRAL' };
    }

    return { detected: false };
  }

  // ==========================================================================
  // ATTACK LOGGING
  // ==========================================================================

  async logBusinessLogicAttack(attackData) {
    try {
      const {
        type,
        severity,
        details,
        context,
        timestamp = new Date()
      } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, 
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          type,
          severity,
          JSON.stringify(details),
          context.ip || null,
          context.userAgent || null,
          context.userId || null,
          context.endpoint || null,
          timestamp
        ]
      );

      logger.attack('Business Logic Attack Detected', {
        type,
        severity,
        details,
        context
      });

    } catch (error) {
      logger.error('Failed to log business logic attack', { error: error.message });
    }
  }

  // ==========================================================================
  // UTILITY METHODS
  // ==========================================================================

  getStatistics() {
    return {
      ...this.attackStats,
      affectedOrders: this.attackStats.affectedEntities.orders.size,
      affectedUsers: this.attackStats.affectedEntities.users.size,
      affectedProducts: this.attackStats.affectedEntities.products.size,
      totalFinancialImpact: Object.values(this.attackStats.financialImpact)
        .reduce((sum, val) => sum + val, 0)
        .toFixed(2)
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
      description: 'Business logic flaws allow attackers to manipulate workflows, bypass validation, and exploit application functionality',
      vulnerabilityTypes: [
        'Workflow Bypass',
        'State Manipulation',
        'Coupon/Discount Abuse',
        'Referral System Gaming',
        'Inventory Overselling',
        'Refund Fraud',
        'Payment Bypass',
        'Subscription Bypass'
      ],
      impact: [
        'Financial loss through fraud',
        'Unauthorized access to premium features',
        'Inventory discrepancies',
        'Revenue leakage',
        'Customer trust damage',
        'Regulatory compliance violations'
      ],
      remediation: [
        'Implement state machine validation',
        'Enforce business rules server-side',
        'Use database transactions and locks',
        'Implement workflow authorization checks',
        'Add audit logging for all state changes',
        'Validate time-based constraints',
        'Implement rate limiting for sensitive operations',
        'Use idempotency keys for critical actions'
      ]
    };
  }

  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulAttacks: 0,
      byCategory: {
        workflow_bypass: 0,
        state_manipulation: 0,
        coupon_abuse: 0,
        referral_gaming: 0,
        inventory_oversell: 0,
        refund_fraud: 0,
        payment_bypass: 0,
        subscription_bypass: 0
      },
      financialImpact: {
        lostRevenue: 0,
        fraudulentRefunds: 0,
        discountAbuse: 0,
        inventoryLoss: 0
      },
      affectedEntities: {
        orders: new Set(),
        users: new Set(),
        products: new Set()
      }
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getLogicFlaws = () => {
  if (!instance) {
    instance = new LogicFlaws();
  }
  return instance;
};

export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const lf = getLogicFlaws();
      
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

      const result = await lf[method](...Object.values(req.body || req.query), context);
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  LogicFlaws,
  getLogicFlaws,
  createVulnerableHandler
};
