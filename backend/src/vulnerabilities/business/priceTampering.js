/**
 * ============================================================================
 * PRICE TAMPERING VULNERABILITY - MILITARY-GRADE ENTERPRISE EDITION
 * ============================================================================
 * 
 * Advanced Price Manipulation & E-commerce Exploit Demonstration Platform
 * Implements client-side price trust and financial fraud vulnerabilities
 * 
 * @module vulnerabilities/business/priceTampering
 * @category Security Training - OWASP A04:2021 (Insecure Design)
 * @version 3.0.0
 * @license MIT
 * @author Elite Security Research Team
 * 
 * @requires Database
 * @requires Logger
 * @requires Cache
 */

import { Database } from '../../core/Database.js';
import { Logger } from '../../core/Logger.js';
import { Cache } from '../../core/Cache.js';
import { Config } from '../../config/environment.js';
import { tables } from '../../config/database.js';
import {
  HTTP_STATUS,
  ATTACK_SEVERITY,
  ERROR_CODES
} from '../../config/constants.js';
import { ValidationError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// PRICE TAMPERING & BUSINESS LOGIC FLAWS CLASS
// ============================================================================

export class PriceTamperingAndLogicFlaws {
  constructor() {
    this.name = 'Price Tampering & Business Logic Flaws';
    this.category = 'Business Logic';
    this.cvssScore = 8.6;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A04:2021';
    this.cweId = 'CWE-840';
    
    this.attackStats = {
      totalAttempts: 0,
      successfulAttacks: 0,
      financialLoss: 0,
      affectedTransactions: new Set(),
      ipAddresses: new Set()
    };
  }

  // ==========================================================================
  // VULNERABLE: PRICE TAMPERING
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Client-side price validation
   * Trusts price from client request
   */
  async vulnerableCheckoutWithClientPrice(cartItems, context = {}) {
    this.attackStats.totalAttempts++;
    
    try {
      // ⚠️ VULNERABLE: Accept price from client
      const total = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
      
      const [result] = await db.execute(
        `INSERT INTO orders (user_id, total_amount, status, created_at) 
         VALUES (?, ?, 'pending', NOW())`,
        [context.userId, total]
      );
      
      if (total < 1) {
        this.attackStats.successfulAttacks++;
        this.attackStats.financialLoss += 100; // Estimated loss
      }
      
      return {
        success: true,
        vulnerable: true,
        data: { orderId: result.insertId, total },
        warning: total < 1 ? 'CRITICAL: Price tampering detected' : null
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * ✅ SECURE: Server-side price validation
   */
  async secureCheckout(cartItems, userId) {
    try {
      // ✅ Fetch prices from database
      const productIds = cartItems.map(item => item.productId);
      const [products] = await db.execute(
        `SELECT id, price FROM products WHERE id IN (?)`,
        [productIds]
      );
      
      const priceMap = Object.fromEntries(products.map(p => [p.id, p.price]));
      
      // ✅ Calculate total using server-side prices
      const total = cartItems.reduce((sum, item) => {
        const serverPrice = priceMap[item.productId] || 0;
        return sum + (serverPrice * item.quantity);
      }, 0);
      
      const [result] = await db.execute(
        `INSERT INTO orders (user_id, total_amount, status, created_at) 
         VALUES (?, ?, 'pending', NOW())`,
        [userId, total]
      );
      
      return {
        success: true,
        vulnerable: false,
        data: { orderId: result.insertId, total }
      };
    } catch (error) {
      throw error;
    }
  }

  // ==========================================================================
  // VULNERABLE: NEGATIVE QUANTITY
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Accept negative quantities
   */
  async vulnerableAddToCart(productId, quantity, userId, context = {}) {
    this.attackStats.totalAttempts++;
    
    try {
      // ⚠️ VULNERABLE: No validation on quantity
      await db.execute(
        `INSERT INTO cart_items (user_id, product_id, quantity, created_at)
         VALUES (?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE quantity = quantity + ?`,
        [userId, productId, quantity, quantity]
      );
      
      if (quantity < 0) {
        this.attackStats.successfulAttacks++;
      }
      
      return {
        success: true,
        vulnerable: true,
        data: { productId, quantity },
        warning: quantity < 0 ? 'CRITICAL: Negative quantity exploited' : null
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * ✅ SECURE: Validate quantity
   */
  async secureAddToCart(productId, quantity, userId) {
    try {
      // ✅ Validate quantity
      if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
        throw new ValidationError('Invalid quantity');
      }
      
      await db.execute(
        `INSERT INTO cart_items (user_id, product_id, quantity, created_at)
         VALUES (?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE quantity = ?`,
        [userId, productId, quantity, quantity]
      );
      
      return {
        success: true,
        vulnerable: false,
        data: { productId, quantity }
      };
    } catch (error) {
      throw error;
    }
  }

  // ==========================================================================
  // UTILITY METHODS
  // ==========================================================================

  getStatistics() {
    return {
      ...this.attackStats,
      affectedTransactions: this.attackStats.affectedTransactions.size,
      ipAddresses: this.attackStats.ipAddresses.size
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
      description: 'Price tampering and business logic flaws allow attackers to manipulate transaction values and bypass business rules',
      impact: [
        'Financial loss through price manipulation',
        'Free products through negative pricing',
        'Inventory manipulation',
        'Coupon abuse',
        'Refund fraud'
      ],
      remediation: [
        'Always validate prices server-side',
        'Never trust client-side calculations',
        'Implement quantity limits',
        'Use database-stored prices',
        'Validate all business logic server-side'
      ]
    };
  }

  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulAttacks: 0,
      financialLoss: 0,
      affectedTransactions: new Set(),
      ipAddresses: new Set()
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getPriceTamperingAndLogicFlaws = () => {
  if (!instance) {
    instance = new PriceTamperingAndLogicFlaws();
  }
  return instance;
};

export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const pt = getPriceTamperingAndLogicFlaws();
      
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

      const result = await pt[method](...Object.values(req.body || req.query), context);
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  PriceTamperingAndLogicFlaws,
  getPriceTamperingAndLogicFlaws,
  createVulnerableHandler
};
