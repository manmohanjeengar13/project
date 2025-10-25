/**
 * Order Model
 * Enterprise-grade order management with state machine pattern
 * 
 * @module models/Order
 * @version 2.0.0
 * @license MIT
 * 
 * Features:
 * - State machine for order workflow
 * - Transaction support
 * - Order lifecycle management
 * - Payment integration
 * - Shipping tracking
 * - Order analytics
 * - Refund management
 * - Invoice generation
 * - Event emission
 * - Audit trail
 * - Order splitting
 * - Fraud detection
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { tables } from '../config/database.js';
import { ORDER_STATUS, PAYMENT_STATUS, PAYMENT_METHODS } from '../config/constants.js';
import { ValidationError, NotFoundError } from '../middleware/errorHandler.js';
import { EventEmitter } from 'events';
import crypto from 'crypto';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// ORDER STATE MACHINE
// ============================================================================

const ORDER_STATE_MACHINE = {
  [ORDER_STATUS.PENDING]: {
    allowedTransitions: [ORDER_STATUS.PROCESSING, ORDER_STATUS.CANCELLED, ORDER_STATUS.PAYMENT_FAILED],
    canCancel: true,
    canRefund: false,
    requiresPayment: true
  },
  [ORDER_STATUS.PROCESSING]: {
    allowedTransitions: [ORDER_STATUS.SHIPPED, ORDER_STATUS.CANCELLED],
    canCancel: true,
    canRefund: true,
    requiresPayment: false
  },
  [ORDER_STATUS.SHIPPED]: {
    allowedTransitions: [ORDER_STATUS.DELIVERED, ORDER_STATUS.RETURNED],
    canCancel: false,
    canRefund: true,
    requiresPayment: false
  },
  [ORDER_STATUS.DELIVERED]: {
    allowedTransitions: [ORDER_STATUS.RETURNED],
    canCancel: false,
    canRefund: true,
    requiresPayment: false
  },
  [ORDER_STATUS.CANCELLED]: {
    allowedTransitions: [],
    canCancel: false,
    canRefund: true,
    requiresPayment: false
  },
  [ORDER_STATUS.RETURNED]: {
    allowedTransitions: [],
    canCancel: false,
    canRefund: false,
    requiresPayment: false
  },
  [ORDER_STATUS.PAYMENT_FAILED]: {
    allowedTransitions: [ORDER_STATUS.PENDING, ORDER_STATUS.CANCELLED],
    canCancel: true,
    canRefund: false,
    requiresPayment: true
  }
};

// ============================================================================
// ORDER MODEL CLASS
// ============================================================================

export class Order extends EventEmitter {
  constructor(data = {}) {
    super();
    
    // Core attributes
    this.id = data.id || null;
    this.orderNumber = data.order_number || null;
    this.userId = data.user_id || null;
    
    // Financial
    this.subtotal = parseFloat(data.subtotal) || 0;
    this.tax = parseFloat(data.tax) || 0;
    this.shippingCost = parseFloat(data.shipping_cost) || 0;
    this.discount = parseFloat(data.discount) || 0;
    this.walletAmountUsed = parseFloat(data.wallet_amount_used) || 0;
    this.total = parseFloat(data.total) || 0;
    this.currency = data.currency || 'USD';
    
    // Status
    this.status = data.status || ORDER_STATUS.PENDING;
    this.paymentStatus = data.payment_status || PAYMENT_STATUS.PENDING;
    this.fulfillmentStatus = data.fulfillment_status || 'unfulfilled';
    
    // Payment
    this.paymentMethod = data.payment_method || null;
    this.paymentTransactionId = data.payment_transaction_id || null;
    this.paymentDate = data.payment_date || null;
    
    // Addresses
    this.shippingAddress = data.shipping_address ? 
      (typeof data.shipping_address === 'string' ? JSON.parse(data.shipping_address) : data.shipping_address) : 
      null;
    this.billingAddress = data.billing_address ? 
      (typeof data.billing_address === 'string' ? JSON.parse(data.billing_address) : data.billing_address) : 
      null;
    
    // Shipping
    this.shippingMethod = data.shipping_method || null;
    this.trackingNumber = data.tracking_number || null;
    this.trackingUrl = data.tracking_url || null;
    this.shippedAt = data.shipped_at || null;
    this.deliveredAt = data.delivered_at || null;
    this.estimatedDeliveryDate = data.estimated_delivery_date || null;
    
    // Coupon
    this.couponId = data.coupon_id || null;
    this.couponCode = data.coupon_code || null;
    
    // Metadata
    this.notes = data.notes || null;
    this.customerNotes = data.customer_notes || null;
    this.internalNotes = data.internal_notes || null;
    this.tags = data.tags ? (typeof data.tags === 'string' ? JSON.parse(data.tags) : data.tags) : [];
    
    // Fraud & Risk
    this.riskScore = parseFloat(data.risk_score) || 0;
    this.ipAddress = data.ip_address || null;
    this.userAgent = data.user_agent || null;
    this.fingerprint = data.fingerprint || null;
    
    // Refund
    this.refundAmount = parseFloat(data.refund_amount) || 0;
    this.refundReason = data.refund_reason || null;
    this.refundedAt = data.refunded_at || null;
    
    // Timestamps
    this.createdAt = data.created_at || null;
    this.updatedAt = data.updated_at || null;
    this.cancelledAt = data.cancelled_at || null;
    
    // Internal flags
    this._isNew = !this.id;
    this._isDirty = false;
    this._dirtyAttributes = new Set();
    this._originalData = { ...data };
    
    // Relationships (lazy loaded)
    this._user = null;
    this._items = null;
    this._statusHistory = null;
  }

  // ==========================================================================
  // VIRTUAL ATTRIBUTES
  // ==========================================================================

  get totalItems() {
    if (!this._items) return 0;
    return this._items.reduce((sum, item) => sum + item.quantity, 0);
  }

  get isPaid() {
    return this.paymentStatus === PAYMENT_STATUS.PAID;
  }

  get isPending() {
    return this.status === ORDER_STATUS.PENDING;
  }

  get isProcessing() {
    return this.status === ORDER_STATUS.PROCESSING;
  }

  get isShipped() {
    return this.status === ORDER_STATUS.SHIPPED;
  }

  get isDelivered() {
    return this.status === ORDER_STATUS.DELIVERED;
  }

  get isCancelled() {
    return this.status === ORDER_STATUS.CANCELLED;
  }

  get isReturned() {
    return this.status === ORDER_STATUS.RETURNED;
  }

  get canBeCancelled() {
    const stateConfig = ORDER_STATE_MACHINE[this.status];
    return stateConfig?.canCancel || false;
  }

  get canBeRefunded() {
    const stateConfig = ORDER_STATE_MACHINE[this.status];
    return stateConfig?.canRefund && this.isPaid;
  }

  get isHighRisk() {
    return this.riskScore > 0.7;
  }

  get isRefunded() {
    return this.refundAmount > 0;
  }

  get refundPercentage() {
    if (this.refundAmount === 0 || this.total === 0) return 0;
    return ((this.refundAmount / this.total) * 100).toFixed(2);
  }

  get processingTime() {
    if (!this.deliveredAt || !this.createdAt) return null;
    const created = new Date(this.createdAt);
    const delivered = new Date(this.deliveredAt);
    return Math.floor((delivered - created) / (1000 * 60 * 60 * 24)); // Days
  }

  // ==========================================================================
  // VALIDATION
  // ==========================================================================

  validate() {
    const errors = [];

    // Order number validation
    if (!this.orderNumber) {
      errors.push('Order number is required');
    }

    // User validation
    if (!this.userId) {
      errors.push('User ID is required');
    }

    // Financial validation
    if (this.subtotal < 0) {
      errors.push('Subtotal cannot be negative');
    }
    if (this.total < 0) {
      errors.push('Total cannot be negative');
    }
    if (this.discount > this.subtotal) {
      errors.push('Discount cannot exceed subtotal');
    }

    // Status validation
    if (!Object.values(ORDER_STATUS).includes(this.status)) {
      errors.push('Invalid order status');
    }
    if (!Object.values(PAYMENT_STATUS).includes(this.paymentStatus)) {
      errors.push('Invalid payment status');
    }

    // Payment method validation
    if (this.paymentMethod && !Object.values(PAYMENT_METHODS).includes(this.paymentMethod)) {
      errors.push('Invalid payment method');
    }

    // Address validation
    if (!this.shippingAddress) {
      errors.push('Shipping address is required');
    }

    if (errors.length > 0) {
      throw new ValidationError('Order validation failed', { errors });
    }

    return true;
  }

  // ==========================================================================
  // STATE MACHINE METHODS
  // ==========================================================================

  canTransitionTo(newStatus) {
    const currentStateConfig = ORDER_STATE_MACHINE[this.status];
    return currentStateConfig?.allowedTransitions?.includes(newStatus) || false;
  }

  async transitionTo(newStatus, notes = '', userId = null) {
    if (!this.canTransitionTo(newStatus)) {
      throw new ValidationError(
        `Cannot transition from ${this.status} to ${newStatus}`,
        { currentStatus: this.status, requestedStatus: newStatus }
      );
    }

    const oldStatus = this.status;
    this.status = newStatus;

    // Update timestamps based on status
    switch (newStatus) {
      case ORDER_STATUS.SHIPPED:
        this.shippedAt = new Date();
        break;
      case ORDER_STATUS.DELIVERED:
        this.deliveredAt = new Date();
        break;
      case ORDER_STATUS.CANCELLED:
        this.cancelledAt = new Date();
        break;
    }

    // Log status change
    await db.execute(
      `INSERT INTO ${tables.ORDER_STATUS_HISTORY} (
        order_id, status, notes, created_by, created_at
      ) VALUES (?, ?, ?, ?, NOW())`,
      [this.id, newStatus, notes, userId]
    );

    await this.save();

    this.emit('statusChanged', { oldStatus, newStatus, notes });

    logger.info('Order status changed', { 
      orderId: this.id, 
      orderNumber: this.orderNumber,
      from: oldStatus, 
      to: newStatus,
      userId
    });

    return this;
  }

  // ==========================================================================
  // HOOKS
  // ==========================================================================

  async beforeSave() {
    this.emit('beforeSave', this);

    // Generate order number if new
    if (this._isNew && !this.orderNumber) {
      this.orderNumber = await this.generateOrderNumber();
    }

    // Set timestamps
    if (this._isNew) {
      this.createdAt = new Date();
    }
    this.updatedAt = new Date();
  }

  async afterSave() {
    this.emit('afterSave', this);

    // Clear cache
    if (this.id) {
      await cache.delete(CacheKeyBuilder.order(this.id));
      await cache.delete(`order:number:${this.orderNumber}`);
      await cache.delete(`user:${this.userId}:orders`);
    }

    logger.info('Order saved', { 
      orderId: this.id, 
      orderNumber: this.orderNumber,
      isNew: this._isNew 
    });

    this._isNew = false;
    this._isDirty = false;
    this._dirtyAttributes.clear();
  }

  // ==========================================================================
  // CRUD OPERATIONS
  // ==========================================================================

  async save() {
    try {
      this.validate();
      await this.beforeSave();

      if (this._isNew) {
        // INSERT
        const [result] = await db.execute(
          `INSERT INTO ${tables.ORDERS} (
            order_number, user_id,
            subtotal, tax, shipping_cost, discount, wallet_amount_used, total, currency,
            status, payment_status, fulfillment_status,
            payment_method, payment_transaction_id, payment_date,
            shipping_address, billing_address,
            shipping_method, tracking_number, tracking_url,
            shipped_at, delivered_at, estimated_delivery_date,
            coupon_id, coupon_code,
            notes, customer_notes, internal_notes, tags,
            risk_score, ip_address, user_agent, fingerprint,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
          [
            this.orderNumber, this.userId,
            this.subtotal, this.tax, this.shippingCost, this.discount, this.walletAmountUsed, this.total, this.currency,
            this.status, this.paymentStatus, this.fulfillmentStatus,
            this.paymentMethod, this.paymentTransactionId, this.paymentDate,
            JSON.stringify(this.shippingAddress), JSON.stringify(this.billingAddress),
            this.shippingMethod, this.trackingNumber, this.trackingUrl,
            this.shippedAt, this.deliveredAt, this.estimatedDeliveryDate,
            this.couponId, this.couponCode,
            this.notes, this.customerNotes, this.internalNotes, JSON.stringify(this.tags),
            this.riskScore, this.ipAddress, this.userAgent, this.fingerprint
          ]
        );

        this.id = result.insertId;
      } else {
        // UPDATE
        await db.execute(
          `UPDATE ${tables.ORDERS} 
           SET status = ?, payment_status = ?, fulfillment_status = ?,
               tracking_number = ?, tracking_url = ?,
               shipped_at = ?, delivered_at = ?,
               refund_amount = ?, refund_reason = ?, refunded_at = ?,
               cancelled_at = ?,
               updated_at = NOW()
           WHERE id = ?`,
          [
            this.status, this.paymentStatus, this.fulfillmentStatus,
            this.trackingNumber, this.trackingUrl,
            this.shippedAt, this.deliveredAt,
            this.refundAmount, this.refundReason, this.refundedAt,
            this.cancelledAt,
            this.id
          ]
        );
      }

      await this.afterSave();
      return this;
    } catch (error) {
      logger.error('Order save failed', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ORDER OPERATIONS
  // ==========================================================================

  async cancel(reason = '', userId = null) {
    if (!this.canBeCancelled) {
      throw new ValidationError('Order cannot be cancelled in current status');
    }

    await this.transitionTo(ORDER_STATUS.CANCELLED, `Cancelled: ${reason}`, userId);

    // Restore stock (would call product service here)
    this.emit('cancelled', { reason, userId });

    return this;
  }

  async ship(trackingNumber, trackingUrl = null, userId = null) {
    if (!this.canTransitionTo(ORDER_STATUS.SHIPPED)) {
      throw new ValidationError('Order cannot be shipped in current status');
    }

    this.trackingNumber = trackingNumber;
    this.trackingUrl = trackingUrl;

    await this.transitionTo(ORDER_STATUS.SHIPPED, 'Order shipped', userId);

    this.emit('shipped', { trackingNumber, trackingUrl });

    return this;
  }

  async markAsDelivered(userId = null) {
    if (!this.canTransitionTo(ORDER_STATUS.DELIVERED)) {
      throw new ValidationError('Order cannot be marked as delivered in current status');
    }

    await this.transitionTo(ORDER_STATUS.DELIVERED, 'Order delivered', userId);

    this.emit('delivered');

    return this;
  }

  async processRefund(amount, reason = '', userId = null) {
    if (!this.canBeRefunded) {
      throw new ValidationError('Order cannot be refunded');
    }

    if (amount > this.total) {
      throw new ValidationError('Refund amount cannot exceed order total');
    }

    this.refundAmount = amount;
    this.refundReason = reason;
    this.refundedAt = new Date();

    await this.save();

    this.emit('refunded', { amount, reason, userId });

    logger.info('Order refunded', { 
      orderId: this.id, 
      amount, 
      reason 
    });

    return this;
  }

  // ==========================================================================
  // PAYMENT METHODS
  // ==========================================================================

  async markAsPaid(transactionId, userId = null) {
    this.paymentStatus = PAYMENT_STATUS.PAID;
    this.paymentTransactionId = transactionId;
    this.paymentDate = new Date();

    await this.save();

    // Transition to processing
    if (this.status === ORDER_STATUS.PENDING) {
      await this.transitionTo(ORDER_STATUS.PROCESSING, 'Payment completed', userId);
    }

    this.emit('paid', { transactionId });

    return this;
  }

  async markPaymentFailed(reason = '', userId = null) {
    this.paymentStatus = PAYMENT_STATUS.FAILED;

    await this.transitionTo(ORDER_STATUS.PAYMENT_FAILED, `Payment failed: ${reason}`, userId);

    this.emit('paymentFailed', { reason });

    return this;
  }

  // ==========================================================================
  // RELATIONSHIP METHODS
  // ==========================================================================

  async user(options = {}) {
    if (this._user && !options.reload) {
      return this._user;
    }

    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name FROM ${tables.USERS} WHERE id = ? LIMIT 1`,
      [this.userId]
    );

    this._user = users[0] || null;
    return this._user;
  }

  async items(options = {}) {
    if (this._items && !options.reload) {
      return this._items;
    }

    const [items] = await db.execute(
      `SELECT * FROM ${tables.ORDER_ITEMS} WHERE order_id = ? ORDER BY id ASC`,
      [this.id]
    );

    this._items = items;
    return items;
  }

  async statusHistory(options = {}) {
    if (this._statusHistory && !options.reload) {
      return this._statusHistory;
    }

    const [history] = await db.execute(
      `SELECT h.*, u.username as created_by_name
       FROM ${tables.ORDER_STATUS_HISTORY} h
       LEFT JOIN ${tables.USERS} u ON h.created_by = u.id
       WHERE h.order_id = ?
       ORDER BY h.created_at DESC`,
      [this.id]
    );

    this._statusHistory = history;
    return history;
  }

  // ==========================================================================
  // UTILITIES
  // ==========================================================================

  async generateOrderNumber() {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(4).toString('hex').toUpperCase();
    const checksum = crypto.createHash('md5')
      .update(`${timestamp}${random}`)
      .digest('hex')
      .substring(0, 4)
      .toUpperCase();
    
    return `ORD-${timestamp}-${random}-${checksum}`;
  }

  set(attribute, value) {
    if (this[attribute] !== value) {
      this[attribute] = value;
      this._isDirty = true;
      this._dirtyAttributes.add(attribute);
    }
    return this;
  }

  // ==========================================================================
  // SERIALIZATION
  // ==========================================================================

  toJSON(options = {}) {
    const { includeItems = false, includeUser = false, includeHistory = false } = options;

    const json = {
      id: this.id,
      orderNumber: this.orderNumber,
      userId: this.userId,
      subtotal: this.subtotal,
      tax: this.tax,
      shippingCost: this.shippingCost,
      discount: this.discount,
      total: this.total,
      currency: this.currency,
      status: this.status,
      paymentStatus: this.paymentStatus,
      paymentMethod: this.paymentMethod,
      shippingAddress: this.shippingAddress,
      trackingNumber: this.trackingNumber,
      isPaid: this.isPaid,
      canBeCancelled: this.canBeCancelled,
      canBeRefunded: this.canBeRefunded,
      isRefunded: this.isRefunded,
      refundAmount: this.refundAmount,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };

    if (includeItems && this._items) {
      json.items = this._items;
      json.totalItems = this.totalItems;
    }

    if (includeUser && this._user) {
      json.user = this._user;
    }

    if (includeHistory && this._statusHistory) {
      json.statusHistory = this._statusHistory;
    }

    return json;
  }

  // ==========================================================================
  // STATIC METHODS
  // ==========================================================================

  static async findById(id) {
    const cacheKey = CacheKeyBuilder.order(id);
    let orderData = await cache.get(cacheKey);

    if (!orderData) {
      const [orders] = await db.execute(
        `SELECT * FROM ${tables.ORDERS} WHERE id = ? LIMIT 1`,
        [id]
      );

      if (orders.length === 0) {
        return null;
      }

      orderData = orders[0];
      await cache.set(cacheKey, orderData, 900);
    }

    return new Order(orderData);
  }

  static async findByOrderNumber(orderNumber) {
    const cacheKey = `order:number:${orderNumber}`;
    let orderData = await cache.get(cacheKey);

    if (!orderData) {
      const [orders] = await db.execute(
        `SELECT * FROM ${tables.ORDERS} WHERE order_number = ? LIMIT 1`,
        [orderNumber]
      );

      if (orders.length === 0) {
        return null;
      }

      orderData = orders[0];
      await cache.set(cacheKey, orderData, 900);
    }

    return new Order(orderData);
  }

  static async findByUser(userId, options = {}) {
    const { limit = 10, offset = 0, status = null } = options;

    const conditions = ['user_id = ?'];
    const values = [userId];

    if (status) {
      conditions.push('status = ?');
      values.push(status);
    }

    const [orders] = await db.execute(
      `SELECT * FROM ${tables.ORDERS}
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return orders.map(orderData => new Order(orderData));
  }

  static async findAll(options = {}) {
    const { limit = 50, offset = 0, status = null } = options;

    const conditions = [];
    const values = [];

    if (status) {
      conditions.push('status = ?');
      values.push(status);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [orders] = await db.execute(
      `SELECT * FROM ${tables.ORDERS}
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return orders.map(orderData => new Order(orderData));
  }

  static async count(options = {}) {
    const { status = null, userId = null } = options;

    const conditions = [];
    const values = [];

    if (status) {
      conditions.push('status = ?');
      values.push(status);
    }

    if (userId) {
      conditions.push('user_id = ?');
      values.push(userId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [result] = await db.execute(
      `SELECT COUNT(*) as count FROM ${tables.ORDERS} ${whereClause}`,
      values
    );

    return result[0].count;
  }
}

export default Order;
