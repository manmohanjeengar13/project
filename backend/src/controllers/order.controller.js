/**
 * Order Controller
 * Handles order creation, management, and processing
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Email } from '../core/Email.js';
import { 
  HTTP_STATUS, 
  ORDER_STATUS,
  PAYMENT_STATUS,
  USER_ROLES,
  PAGINATION 
} from '../config/constants.js';
import { NotFoundError, ValidationError, AuthorizationError } from '../middleware/errorHandler.js';
import crypto from 'crypto';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();
const email = Email.getInstance();

/**
 * Create new order
 */
export const createOrder = async (req, res, next) => {
  const connection = await db.beginTransaction();
  
  try {
    const {
      items,
      shippingAddress,
      paymentMethod,
      couponCode
    } = req.body;
    
    const userId = req.user.id;

    if (!items || items.length === 0) {
      throw new ValidationError('Order must contain at least one item');
    }

    // Validate products and calculate total
    let subtotal = 0;
    const orderItems = [];

    for (const item of items) {
      const [products] = await connection.execute(
        'SELECT id, name, price, stock FROM products WHERE id = ? AND is_active = TRUE LIMIT 1',
        [item.product_id]
      );

      if (products.length === 0) {
        throw new ValidationError(`Product ${item.product_id} not found or inactive`);
      }

      const product = products[0];

      // Check stock
      if (product.stock < item.quantity) {
        throw new ValidationError(`Insufficient stock for ${product.name}. Available: ${product.stock}`);
      }

      const itemTotal = product.price * item.quantity;
      subtotal += itemTotal;

      orderItems.push({
        product_id: product.id,
        product_name: product.name,
        quantity: item.quantity,
        price: product.price,
        total: itemTotal
      });

      // Update stock
      await connection.execute(
        'UPDATE products SET stock = stock - ? WHERE id = ?',
        [item.quantity, product.id]
      );
    }

    // Apply coupon if provided
    let discount = 0;
    let couponId = null;
    if (couponCode) {
      const [coupons] = await connection.execute(
        `SELECT id, discount_type, discount_value, min_order_value, max_uses, times_used
         FROM coupons 
         WHERE code = ? AND is_active = TRUE 
         AND valid_from <= NOW() AND valid_until >= NOW()
         LIMIT 1`,
        [couponCode]
      );

      if (coupons.length > 0) {
        const coupon = coupons[0];

        if (coupon.max_uses && coupon.times_used >= coupon.max_uses) {
          throw new ValidationError('Coupon usage limit exceeded');
        }

        if (coupon.min_order_value && subtotal < coupon.min_order_value) {
          throw new ValidationError(`Minimum order value for this coupon is ${coupon.min_order_value}`);
        }

        // Calculate discount
        if (coupon.discount_type === 'percentage') {
          discount = (subtotal * coupon.discount_value) / 100;
        } else {
          discount = coupon.discount_value;
        }

        couponId = coupon.id;

        // Update coupon usage
        await connection.execute(
          'UPDATE coupons SET times_used = times_used + 1 WHERE id = ?',
          [coupon.id]
        );
      }
    }

    // Calculate shipping (simplified)
    const shippingCost = subtotal > 100 ? 0 : 10;

    // Calculate final total
    const total = subtotal - discount + shippingCost;

    // Generate order number
    const orderNumber = `ORD-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    // Create order
    const [orderResult] = await connection.execute(
      `INSERT INTO orders (
        user_id, order_number, subtotal, discount, shipping_cost, total,
        shipping_address, payment_method, payment_status, status, 
        coupon_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        userId,
        orderNumber,
        subtotal,
        discount,
        shippingCost,
        total,
        shippingAddress,
        paymentMethod,
        PAYMENT_STATUS.PENDING,
        ORDER_STATUS.PENDING,
        couponId
      ]
    );

    const orderId = orderResult.insertId;

    // Insert order items
    const itemValues = orderItems.map(item => [
      orderId,
      item.product_id,
      item.product_name,
      item.quantity,
      item.price,
      item.total
    ]);

    await connection.execute(
      `INSERT INTO order_items (order_id, product_id, product_name, quantity, price, total) VALUES ?`,
      [itemValues]
    );

    // Log order status
    await connection.execute(
      `INSERT INTO order_status_history (order_id, status, notes, created_at)
       VALUES (?, ?, ?, NOW())`,
      [orderId, ORDER_STATUS.PENDING, 'Order created']
    );

    await db.commit(connection);

    // Clear product cache
    for (const item of orderItems) {
      await cache.delete(CacheKeyBuilder.product(item.product_id));
    }

    // Send order confirmation email
    if (email) {
      const [users] = await db.execute(
        'SELECT username, email FROM users WHERE id = ? LIMIT 1',
        [userId]
      );
      
      if (users.length > 0) {
        await email.sendOrderConfirmation(users[0], {
          id: orderId,
          order_number: orderNumber,
          total,
          created_at: new Date()
        });
      }
    }

    logger.info('Order created', { orderId, orderNumber, userId, total });

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Order placed successfully',
      data: {
        id: orderId,
        orderNumber,
        total,
        status: ORDER_STATUS.PENDING,
        items: orderItems
      }
    });
  } catch (error) {
    await db.rollback(connection);
    next(error);
  }
};

/**
 * Get user orders
 */
export const getOrders = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      status = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = ['user_id = ?'];
    const values = [userId];

    if (status) {
      conditions.push('status = ?');
      values.push(status);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM orders ${whereClause}`,
      values
    );

    // Get orders
    const [orders] = await db.execute(
      `SELECT id, order_number, subtotal, discount, shipping_cost, total,
              payment_method, payment_status, status, created_at, updated_at
       FROM orders
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    // Get items for each order
    for (const order of orders) {
      const [items] = await db.execute(
        'SELECT * FROM order_items WHERE order_id = ?',
        [order.id]
      );
      order.items = items;
    }

    res.json({
      success: true,
      data: orders,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get order by ID
 */
export const getOrderById = async (req, res, next) => {
  try {
    const orderId = req.params.id;
    const userId = req.user.id;

    const [orders] = await db.execute(
      `SELECT * FROM orders WHERE id = ? LIMIT 1`,
      [orderId]
    );

    if (orders.length === 0) {
      throw new NotFoundError('Order');
    }

    const order = orders[0];

    // Check authorization
    if (order.user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only view your own orders');
    }

    // Get order items
    const [items] = await db.execute(
      'SELECT * FROM order_items WHERE order_id = ?',
      [orderId]
    );
    order.items = items;

    // Get status history
    const [history] = await db.execute(
      'SELECT * FROM order_status_history WHERE order_id = ? ORDER BY created_at DESC',
      [orderId]
    );
    order.statusHistory = history;

    res.json({
      success: true,
      data: order
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update order status (Admin only)
 */
export const updateOrderStatus = async (req, res, next) => {
  try {
    const orderId = req.params.id;
    const { status, notes = '' } = req.body;

    // Validate status
    const validStatuses = Object.values(ORDER_STATUS);
    if (!validStatuses.includes(status)) {
      throw new ValidationError('Invalid order status');
    }

    // Get current order
    const [orders] = await db.execute(
      'SELECT user_id, status as current_status FROM orders WHERE id = ? LIMIT 1',
      [orderId]
    );

    if (orders.length === 0) {
      throw new NotFoundError('Order');
    }

    // Update order
    await db.execute(
      'UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?',
      [status, orderId]
    );

    // Log status change
    await db.execute(
      `INSERT INTO order_status_history (order_id, status, notes, created_by, created_at)
       VALUES (?, ?, ?, ?, NOW())`,
      [orderId, status, notes, req.user.id]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.order(orderId));

    // Send notification email for certain statuses
    if ([ORDER_STATUS.SHIPPED, ORDER_STATUS.DELIVERED].includes(status)) {
      const [users] = await db.execute(
        'SELECT username, email FROM users WHERE id = ? LIMIT 1',
        [orders[0].user_id]
      );

      if (users.length > 0 && email) {
        const emailMethod = status === ORDER_STATUS.SHIPPED 
          ? 'sendOrderShipped' 
          : 'sendOrderDelivered';
        
        await email[emailMethod](users[0], { id: orderId }, 'TRACK123');
      }
    }

    logger.info('Order status updated', { orderId, status, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Order status updated successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Cancel order
 */
export const cancelOrder = async (req, res, next) => {
  const connection = await db.beginTransaction();

  try {
    const orderId = req.params.id;
    const userId = req.user.id;
    const { reason = '' } = req.body;

    // Get order
    const [orders] = await connection.execute(
      'SELECT user_id, status FROM orders WHERE id = ? LIMIT 1',
      [orderId]
    );

    if (orders.length === 0) {
      throw new NotFoundError('Order');
    }

    const order = orders[0];

    // Check authorization
    if (order.user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only cancel your own orders');
    }

    // Check if order can be cancelled
    if ([ORDER_STATUS.SHIPPED, ORDER_STATUS.DELIVERED, ORDER_STATUS.CANCELLED].includes(order.status)) {
      throw new ValidationError(`Cannot cancel order with status: ${order.status}`);
    }

    // Get order items to restore stock
    const [items] = await connection.execute(
      'SELECT product_id, quantity FROM order_items WHERE order_id = ?',
      [orderId]
    );

    // Restore stock
    for (const item of items) {
      await connection.execute(
        'UPDATE products SET stock = stock + ? WHERE id = ?',
        [item.quantity, item.product_id]
      );

      await cache.delete(CacheKeyBuilder.product(item.product_id));
    }

    // Update order
    await connection.execute(
      'UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?',
      [ORDER_STATUS.CANCELLED, orderId]
    );

    // Log cancellation
    await connection.execute(
      `INSERT INTO order_status_history (order_id, status, notes, created_at)
       VALUES (?, ?, ?, NOW())`,
      [orderId, ORDER_STATUS.CANCELLED, `Cancelled: ${reason}`]
    );

    await db.commit(connection);

    logger.info('Order cancelled', { orderId, userId });

    res.json({
      success: true,
      message: 'Order cancelled successfully'
    });
  } catch (error) {
    await db.rollback(connection);
    next(error);
  }
};

/**
 * Get all orders (Admin only)
 */
export const getAllOrders = async (req, res, next) => {
  try {
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      status = '',
      paymentStatus = '',
      search = '',
      startDate = '',
      endDate = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = [];
    const values = [];

    if (status) {
      conditions.push('o.status = ?');
      values.push(status);
    }

    if (paymentStatus) {
      conditions.push('o.payment_status = ?');
      values.push(paymentStatus);
    }

    if (search) {
      conditions.push('(o.order_number LIKE ? OR u.username LIKE ? OR u.email LIKE ?)');
      const searchPattern = `%${search}%`;
      values.push(searchPattern, searchPattern, searchPattern);
    }

    if (startDate) {
      conditions.push('o.created_at >= ?');
      values.push(startDate);
    }

    if (endDate) {
      conditions.push('o.created_at <= ?');
      values.push(endDate);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total 
       FROM orders o 
       JOIN users u ON o.user_id = u.id 
       ${whereClause}`,
      values
    );

    // Get orders
    const [orders] = await db.execute(
      `SELECT o.*, u.username, u.email
       FROM orders o
       JOIN users u ON o.user_id = u.id
       ${whereClause}
       ORDER BY o.created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: orders,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get order statistics
 */
export const getOrderStatistics = async (req, res, next) => {
  try {
    const { startDate = '', endDate = '' } = req.query;

    const conditions = [];
    const values = [];

    if (startDate) {
      conditions.push('created_at >= ?');
      values.push(startDate);
    }

    if (endDate) {
      conditions.push('created_at <= ?');
      values.push(endDate);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Overall statistics
    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total_orders,
        COALESCE(SUM(total), 0) as total_revenue,
        COALESCE(AVG(total), 0) as avg_order_value,
        COUNT(CASE WHEN status = '${ORDER_STATUS.PENDING}' THEN 1 END) as pending_orders,
        COUNT(CASE WHEN status = '${ORDER_STATUS.PROCESSING}' THEN 1 END) as processing_orders,
        COUNT(CASE WHEN status = '${ORDER_STATUS.SHIPPED}' THEN 1 END) as shipped_orders,
        COUNT(CASE WHEN status = '${ORDER_STATUS.DELIVERED}' THEN 1 END) as delivered_orders,
        COUNT(CASE WHEN status = '${ORDER_STATUS.CANCELLED}' THEN 1 END) as cancelled_orders
       FROM orders ${whereClause}`,
      values
    );

    // Revenue by day (last 7 days)
    const [dailyRevenue] = await db.execute(
      `SELECT DATE(created_at) as date, COUNT(*) as orders, COALESCE(SUM(total), 0) as revenue
       FROM orders
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
       GROUP BY DATE(created_at)
       ORDER BY date DESC`
    );

    // Top selling products
    const [topProducts] = await db.execute(
      `SELECT oi.product_name, SUM(oi.quantity) as total_sold, SUM(oi.total) as revenue
       FROM order_items oi
       JOIN orders o ON oi.order_id = o.id
       WHERE o.status != '${ORDER_STATUS.CANCELLED}'
       GROUP BY oi.product_id, oi.product_name
       ORDER BY total_sold DESC
       LIMIT 10`
    );

    res.json({
      success: true,
      data: {
        overview: stats[0],
        dailyRevenue,
        topProducts
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Apply coupon
 */
export const applyCoupon = async (req, res, next) => {
  try {
    const { code, subtotal } = req.body;

    const [coupons] = await db.execute(
      `SELECT id, code, discount_type, discount_value, min_order_value, max_uses, times_used
       FROM coupons 
       WHERE code = ? AND is_active = TRUE 
       AND valid_from <= NOW() AND valid_until >= NOW()
       LIMIT 1`,
      [code]
    );

    if (coupons.length === 0) {
      throw new ValidationError('Invalid or expired coupon code');
    }

    const coupon = coupons[0];

    if (coupon.max_uses && coupon.times_used >= coupon.max_uses) {
      throw new ValidationError('Coupon usage limit exceeded');
    }

    if (coupon.min_order_value && subtotal < coupon.min_order_value) {
      throw new ValidationError(`Minimum order value for this coupon is ${coupon.min_order_value}`);
    }

    // Calculate discount
    let discount = 0;
    if (coupon.discount_type === 'percentage') {
      discount = (subtotal * coupon.discount_value) / 100;
    } else {
      discount = coupon.discount_value;
    }

    res.json({
      success: true,
      data: {
        coupon: {
          code: coupon.code,
          discountType: coupon.discount_type,
          discountValue: coupon.discount_value
        },
        discount,
        newTotal: subtotal - discount
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Calculate shipping cost
 */
export const calculateShipping = async (req, res, next) => {
  try {
    const { subtotal, address } = req.body;

    // Simplified shipping calculation
    let shippingCost = 0;

    if (subtotal < 50) {
      shippingCost = 15;
    } else if (subtotal < 100) {
      shippingCost = 10;
    } else {
      shippingCost = 0; // Free shipping
    }

    // Could add logic based on address/location here

    res.json({
      success: true,
      data: {
        shippingCost,
        freeShippingThreshold: 100,
        freeShipping: subtotal >= 100
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get order invoice
 */
export const getOrderInvoice = async (req, res, next) => {
  try {
    const orderId = req.params.id;
    const userId = req.user.id;

    const [orders] = await db.execute(
      `SELECT o.*, u.username, u.email, u.first_name, u.last_name
       FROM orders o
       JOIN users u ON o.user_id = u.id
       WHERE o.id = ? LIMIT 1`,
      [orderId]
    );

    if (orders.length === 0) {
      throw new NotFoundError('Order');
    }

    const order = orders[0];

    // Check authorization
    if (order.user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only view your own order invoices');
    }

    // Get order items
    const [items] = await db.execute(
      'SELECT * FROM order_items WHERE order_id = ?',
      [orderId]
    );

    res.json({
      success: true,
      data: {
        order,
        items,
        invoice: {
          number: `INV-${order.order_number}`,
          date: order.created_at,
          dueDate: order.created_at
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Reorder (place order again)
 */
export const reorder = async (req, res, next) => {
  try {
    const orderId = req.params.id;
    const userId = req.user.id;

    // Get original order
    const [orders] = await db.execute(
      'SELECT * FROM orders WHERE id = ? AND user_id = ? LIMIT 1',
      [orderId, userId]
    );

    if (orders.length === 0) {
      throw new NotFoundError('Order');
    }

    // Get order items
    const [items] = await db.execute(
      'SELECT product_id, quantity FROM order_items WHERE order_id = ?',
      [orderId]
    );

    // Prepare items for new order
    const orderItems = items.map(item => ({
      product_id: item.product_id,
      quantity: item.quantity
    }));

    // Create new order with same items
    req.body = {
      items: orderItems,
      shippingAddress: orders[0].shipping_address,
      paymentMethod: orders[0].payment_method
    };

    return createOrder(req, res, next);
  } catch (error) {
    next(error);
  }
};

/**
 * Export orders (Admin only)
 */
export const exportOrders = async (req, res, next) => {
  try {
    const { format = 'json', status = '', startDate = '', endDate = '' } = req.query;

    const conditions = [];
    const values = [];

    if (status) {
      conditions.push('o.status = ?');
      values.push(status);
    }

    if (startDate) {
      conditions.push('o.created_at >= ?');
      values.push(startDate);
    }

    if (endDate) {
      conditions.push('o.created_at <= ?');
      values.push(endDate);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [orders] = await db.execute(
      `SELECT o.*, u.username, u.email
       FROM orders o
       JOIN users u ON o.user_id = u.id
       ${whereClause}
       ORDER BY o.created_at DESC`,
      values
    );

    if (format === 'csv') {
      const csv = [
        ['Order Number', 'Customer', 'Total', 'Status', 'Payment Status', 'Created At'].join(','),
        ...orders.map(o => [
          o.order_number,
          o.username,
          o.total,
          o.status,
          o.payment_status,
          o.created_at
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=orders.csv');
      return res.send(csv);
    }

    res.json({
      success: true,
      data: orders,
      count: orders.length
    });
  } catch (error) {
    next(error);
  }
};

export default {
  createOrder,
  getOrders,
  getOrderById,
  updateOrderStatus,
  cancelOrder,
  getAllOrders,
  getOrderStatistics,
  applyCoupon,
  calculateShipping,
  getOrderInvoice,
  reorder,
  exportOrders
};
