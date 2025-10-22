/**
 * Analytics Controller
 * Handles platform analytics, metrics, and reporting
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { HTTP_STATUS } from '../config/constants.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Get platform overview
 */
export const getOverview = async (req, res, next) => {
  try {
    const { startDate, endDate, period = '30d' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;
    else if (period === '365d') daysBack = 365;

    // Try cache first
    const cacheKey = `analytics:overview:${period}`;
    let overview = await cache.get(cacheKey);

    if (!overview) {
      const dateFilter = startDate && endDate
        ? 'o.created_at BETWEEN ? AND ?'
        : 'o.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)';
      
      const params = startDate && endDate ? [startDate, endDate] : [daysBack];

      // Overall metrics
      const [metrics] = await db.execute(
        `SELECT 
          COUNT(DISTINCT o.id) as total_orders,
          COALESCE(SUM(o.total), 0) as total_revenue,
          COUNT(DISTINCT o.user_id) as total_customers,
          COALESCE(AVG(o.total), 0) as avg_order_value,
          COALESCE(SUM(o.total) / COUNT(DISTINCT o.user_id), 0) as customer_lifetime_value
         FROM orders o
         WHERE ${dateFilter}`,
        params
      );

      // Growth metrics (compare with previous period)
      const prevParams = startDate && endDate 
        ? [startDate, endDate] 
        : [daysBack * 2, daysBack];

      const [prevMetrics] = await db.execute(
        `SELECT 
          COUNT(DISTINCT o.id) as prev_orders,
          COALESCE(SUM(o.total), 0) as prev_revenue
         FROM orders o
         WHERE o.created_at BETWEEN DATE_SUB(NOW(), INTERVAL ? DAY) AND DATE_SUB(NOW(), INTERVAL ? DAY)`,
        prevParams
      );

      // Calculate growth rates
      const orderGrowth = prevMetrics[0].prev_orders > 0
        ? ((metrics[0].total_orders - prevMetrics[0].prev_orders) / prevMetrics[0].prev_orders * 100).toFixed(2)
        : 0;

      const revenueGrowth = prevMetrics[0].prev_revenue > 0
        ? ((metrics[0].total_revenue - prevMetrics[0].prev_revenue) / prevMetrics[0].prev_revenue * 100).toFixed(2)
        : 0;

      // User metrics
      const [userMetrics] = await db.execute(
        `SELECT 
          COUNT(*) as total_users,
          COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL ? DAY) THEN 1 END) as new_users,
          COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_users
         FROM users`,
        [daysBack]
      );

      // Product metrics
      const [productMetrics] = await db.execute(
        `SELECT 
          COUNT(*) as total_products,
          COUNT(CASE WHEN stock = 0 THEN 1 END) as out_of_stock,
          COUNT(CASE WHEN stock < 10 AND stock > 0 THEN 1 END) as low_stock
         FROM products
         WHERE is_active = TRUE`
      );

      overview = {
        orders: {
          ...metrics[0],
          growth: parseFloat(orderGrowth)
        },
        revenue: {
          total: metrics[0].total_revenue,
          growth: parseFloat(revenueGrowth)
        },
        users: userMetrics[0],
        products: productMetrics[0],
        period
      };

      // Cache for 10 minutes
      await cache.set(cacheKey, overview, 600);
    }

    res.json({
      success: true,
      data: userData
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get product analytics
 */
export const getProductAnalytics = async (req, res, next) => {
  try {
    const { period = '30d', limit = 10 } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    const cacheKey = `analytics:products:${period}:${limit}`;
    let productData = await cache.get(cacheKey);

    if (!productData) {
      // Top selling products
      const [topProducts] = await db.execute(
        `SELECT p.id, p.name, p.price,
                SUM(oi.quantity) as units_sold,
                SUM(oi.total) as revenue,
                COUNT(DISTINCT o.user_id) as unique_buyers
         FROM order_items oi
         JOIN products p ON oi.product_id = p.id
         JOIN orders o ON oi.order_id = o.id
         WHERE o.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND o.status != 'cancelled'
         GROUP BY p.id, p.name, p.price
         ORDER BY revenue DESC
         LIMIT ?`,
        [daysBack, parseInt(limit)]
      );

      // Products by category performance
      const [byCategory] = await db.execute(
        `SELECT c.id, c.name,
                COUNT(DISTINCT p.id) as product_count,
                COALESCE(SUM(oi.quantity), 0) as units_sold,
                COALESCE(SUM(oi.total), 0) as revenue
         FROM categories c
         LEFT JOIN products p ON c.id = p.category_id
         LEFT JOIN order_items oi ON p.id = oi.product_id
         LEFT JOIN orders o ON oi.order_id = o.id 
           AND o.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND o.status != 'cancelled'
         GROUP BY c.id, c.name
         ORDER BY revenue DESC`,
        [daysBack]
      );

      // Product views vs sales conversion
      const [conversion] = await db.execute(
        `SELECT p.id, p.name, p.views,
                COUNT(DISTINCT oi.order_id) as orders,
                SUM(oi.quantity) as units_sold,
                CASE WHEN p.views > 0 THEN (COUNT(DISTINCT oi.order_id) / p.views * 100) ELSE 0 END as conversion_rate
         FROM products p
         LEFT JOIN order_items oi ON p.id = oi.product_id
         LEFT JOIN orders o ON oi.order_id = o.id 
           AND o.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND o.status != 'cancelled'
         WHERE p.views > 0
         GROUP BY p.id, p.name, p.views
         ORDER BY conversion_rate DESC
         LIMIT ?`,
        [daysBack, parseInt(limit)]
      );

      // Low stock alerts
      const [lowStock] = await db.execute(
        `SELECT id, name, sku, stock, price
         FROM products
         WHERE stock < 10 AND stock > 0 AND is_active = TRUE
         ORDER BY stock ASC
         LIMIT ?`,
        [parseInt(limit)]
      );

      // Products never sold
      const [neverSold] = await db.execute(
        `SELECT p.id, p.name, p.price, p.stock, p.created_at
         FROM products p
         LEFT JOIN order_items oi ON p.id = oi.product_id
         WHERE oi.id IS NULL 
           AND p.is_active = TRUE
           AND p.created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
         LIMIT ?`,
        [parseInt(limit)]
      );

      productData = {
        topProducts,
        byCategory,
        conversion,
        lowStock,
        neverSold,
        period
      };

      // Cache for 30 minutes
      await cache.set(cacheKey, productData, 1800);
    }

    res.json({
      success: true,
      data: productData
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get traffic analytics
 */
export const getTrafficAnalytics = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    // Page views over time
    const [pageViews] = await db.execute(
      `SELECT DATE(created_at) as date, COUNT(*) as views
       FROM page_views
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY DATE(created_at)
       ORDER BY date ASC`,
      [daysBack]
    );

    // Most viewed pages
    const [topPages] = await db.execute(
      `SELECT page_url, page_type, COUNT(*) as views
       FROM page_views
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY page_url, page_type
       ORDER BY views DESC
       LIMIT 10`,
      [daysBack]
    );

    // Traffic sources
    const [sources] = await db.execute(
      `SELECT source, COUNT(*) as visits
       FROM page_views
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY source
       ORDER BY visits DESC`,
      [daysBack]
    );

    // Bounce rate (simplified - sessions with only 1 page view)
    const [bounceRate] = await db.execute(
      `SELECT 
        COUNT(DISTINCT session_id) as total_sessions,
        COUNT(DISTINCT CASE WHEN page_count = 1 THEN session_id END) as bounced_sessions
       FROM (
         SELECT session_id, COUNT(*) as page_count
         FROM page_views
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         GROUP BY session_id
       ) session_data`,
      [daysBack]
    );

    const bounceRatePercent = bounceRate[0].total_sessions > 0
      ? (bounceRate[0].bounced_sessions / bounceRate[0].total_sessions * 100).toFixed(2)
      : 0;

    res.json({
      success: true,
      data: {
        pageViews,
        topPages,
        sources,
        bounceRate: {
          ...bounceRate[0],
          percentage: parseFloat(bounceRatePercent)
        },
        period
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get conversion rates
 */
export const getConversionRates = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    // Overall conversion funnel
    const [views] = await db.execute(
      'SELECT COUNT(*) as total FROM page_views WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)',
      [daysBack]
    );

    const [productViews] = await db.execute(
      `SELECT COUNT(*) as total FROM page_views 
       WHERE page_type = 'product' AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [daysBack]
    );

    const [carts] = await db.execute(
      'SELECT COUNT(DISTINCT user_id) as total FROM cart_items WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)',
      [daysBack]
    );

    const [orders] = await db.execute(
      'SELECT COUNT(*) as total FROM orders WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)',
      [daysBack]
    );

    const [completedOrders] = await db.execute(
      `SELECT COUNT(*) as total FROM orders 
       WHERE status IN ('delivered', 'completed') 
       AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [daysBack]
    );

    // Calculate conversion rates
    const viewToProductRate = views[0].total > 0 
      ? (productViews[0].total / views[0].total * 100).toFixed(2) 
      : 0;

    const productToCartRate = productViews[0].total > 0 
      ? (carts[0].total / productViews[0].total * 100).toFixed(2) 
      : 0;

    const cartToOrderRate = carts[0].total > 0 
      ? (orders[0].total / carts[0].total * 100).toFixed(2) 
      : 0;

    const orderCompletionRate = orders[0].total > 0 
      ? (completedOrders[0].total / orders[0].total * 100).toFixed(2) 
      : 0;

    const overallConversionRate = views[0].total > 0 
      ? (completedOrders[0].total / views[0].total * 100).toFixed(2) 
      : 0;

    // Conversion by day
    const [daily] = await db.execute(
      `SELECT DATE(o.created_at) as date,
              COUNT(DISTINCT pv.session_id) as sessions,
              COUNT(DISTINCT o.id) as orders,
              CASE WHEN COUNT(DISTINCT pv.session_id) > 0 
                THEN (COUNT(DISTINCT o.id) / COUNT(DISTINCT pv.session_id) * 100) 
                ELSE 0 
              END as conversion_rate
       FROM page_views pv
       LEFT JOIN orders o ON DATE(pv.created_at) = DATE(o.created_at)
       WHERE pv.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       GROUP BY DATE(o.created_at)
       ORDER BY date ASC`,
      [daysBack]
    );

    res.json({
      success: true,
      data: {
        funnel: {
          totalViews: views[0].total,
          productViews: productViews[0].total,
          addedToCarts: carts[0].total,
          orders: orders[0].total,
          completedOrders: completedOrders[0].total
        },
        rates: {
          viewToProduct: parseFloat(viewToProductRate),
          productToCart: parseFloat(productToCartRate),
          cartToOrder: parseFloat(cartToOrderRate),
          orderCompletion: parseFloat(orderCompletionRate),
          overall: parseFloat(overallConversionRate)
        },
        daily,
        period
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get revenue report
 */
export const getRevenueReport = async (req, res, next) => {
  try {
    const { period = '30d', groupBy = 'day' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;
    else if (period === '365d') daysBack = 365;

    let dateFormat = 'DATE(created_at)';
    if (groupBy === 'week') dateFormat = 'YEARWEEK(created_at)';
    else if (groupBy === 'month') dateFormat = 'DATE_FORMAT(created_at, "%Y-%m")';

    // Revenue breakdown
    const [revenue] = await db.execute(
      `SELECT ${dateFormat} as period,
              COALESCE(SUM(subtotal), 0) as subtotal,
              COALESCE(SUM(discount), 0) as discounts,
              COALESCE(SUM(shipping_cost), 0) as shipping,
              COALESCE(SUM(total), 0) as total_revenue,
              COUNT(*) as order_count,
              COALESCE(AVG(total), 0) as avg_order_value
       FROM orders
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         AND status != 'cancelled'
       GROUP BY ${dateFormat}
       ORDER BY period ASC`,
      [daysBack]
    );

    // Revenue by payment method
    const [byPayment] = await db.execute(
      `SELECT payment_method,
              COUNT(*) as order_count,
              COALESCE(SUM(total), 0) as revenue
       FROM orders
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         AND status != 'cancelled'
       GROUP BY payment_method`,
      [daysBack]
    );

    // Revenue by product category
    const [byCategory] = await db.execute(
      `SELECT c.name as category,
              COALESCE(SUM(oi.total), 0) as revenue,
              SUM(oi.quantity) as units_sold
       FROM order_items oi
       JOIN products p ON oi.product_id = p.id
       JOIN categories c ON p.category_id = c.id
       JOIN orders o ON oi.order_id = o.id
       WHERE o.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         AND o.status != 'cancelled'
       GROUP BY c.id, c.name
       ORDER BY revenue DESC`,
      [daysBack]
    );

    // Summary statistics
    const [summary] = await db.execute(
      `SELECT 
        COALESCE(SUM(total), 0) as total_revenue,
        COALESCE(SUM(discount), 0) as total_discounts,
        COALESCE(SUM(shipping_cost), 0) as total_shipping,
        COALESCE(AVG(total), 0) as avg_order_value,
        COUNT(*) as total_orders
       FROM orders
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         AND status != 'cancelled'`,
      [daysBack]
    );

    res.json({
      success: true,
      data: {
        timeline: revenue,
        byPaymentMethod: byPayment,
        byCategory,
        summary: summary[0],
        period,
        groupBy
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Export analytics data
 */
export const exportAnalytics = async (req, res, next) => {
  try {
    const { type = 'sales', format = 'json', period = '30d' } = req.query;

    let data = {};

    if (type === 'sales' || type === 'all') {
      const salesReq = { query: { period } };
      await getSalesAnalytics(salesReq, { json: (d) => { data.sales = d.data; } }, () => {});
    }

    if (type === 'users' || type === 'all') {
      const userReq = { query: { period } };
      await getUserAnalytics(userReq, { json: (d) => { data.users = d.data; } }, () => {});
    }

    if (type === 'products' || type === 'all') {
      const productReq = { query: { period } };
      await getProductAnalytics(productReq, { json: (d) => { data.products = d.data; } }, () => {});
    }

    if (format === 'csv') {
      // Convert to CSV (simplified)
      let csv = 'Type,Metric,Value\n';
      
      if (data.sales) {
        data.sales.timeline.forEach(row => {
          csv += `Sales,${row.date},${row.revenue}\n`;
        });
      }

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=analytics_${type}_${period}.csv`);
      return res.send(csv);
    }

    res.json({
      success: true,
      data,
      exportedAt: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get real-time statistics
 */
export const getRealTimeStats = async (req, res, next) => {
  try {
    // Orders in last hour
    const [recentOrders] = await db.execute(
      `SELECT COUNT(*) as count, COALESCE(SUM(total), 0) as revenue
       FROM orders
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)`
    );

    // Active users (last 15 minutes)
    const [activeUsers] = await db.execute(
      `SELECT COUNT(DISTINCT user_id) as count
       FROM user_sessions
       WHERE updated_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)`
    );

    // Recent page views
    const [recentViews] = await db.execute(
      `SELECT COUNT(*) as count
       FROM page_views
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)`
    );

    // Pending orders
    const [pendingOrders] = await db.execute(
      'SELECT COUNT(*) as count FROM orders WHERE status = "pending"'
    );

    res.json({
      success: true,
      data: {
        recentOrders: recentOrders[0],
        activeUsers: activeUsers[0].count,
        recentViews: recentViews[0].count,
        pendingOrders: pendingOrders[0].count,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    next(error);
  }
};

export default {
  getOverview,
  getSalesAnalytics,
  getUserAnalytics,
  getProductAnalytics,
  getTrafficAnalytics,
  getConversionRates,
  getRevenueReport,
  exportAnalytics,
  getRealTimeStats
};
: true,
      data: overview
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get sales analytics
 */
export const getSalesAnalytics = async (req, res, next) => {
  try {
    const { period = '30d', groupBy = 'day' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;
    else if (period === '365d') daysBack = 365;

    const cacheKey = `analytics:sales:${period}:${groupBy}`;
    let salesData = await cache.get(cacheKey);

    if (!salesData) {
      let dateFormat = 'DATE(created_at)';
      if (groupBy === 'week') dateFormat = 'YEARWEEK(created_at)';
      else if (groupBy === 'month') dateFormat = 'DATE_FORMAT(created_at, "%Y-%m")';

      // Sales over time
      const [daily] = await db.execute(
        `SELECT ${dateFormat} as date, 
                COUNT(*) as orders,
                COALESCE(SUM(total), 0) as revenue,
                COALESCE(AVG(total), 0) as avg_order_value,
                COUNT(DISTINCT user_id) as customers
         FROM orders
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND status != 'cancelled'
         GROUP BY ${dateFormat}
         ORDER BY date ASC`,
        [daysBack]
      );

      // Sales by status
      const [byStatus] = await db.execute(
        `SELECT status, 
                COUNT(*) as count,
                COALESCE(SUM(total), 0) as revenue
         FROM orders
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         GROUP BY status`,
        [daysBack]
      );

      // Sales by payment method
      const [byPayment] = await db.execute(
        `SELECT payment_method, 
                COUNT(*) as count,
                COALESCE(SUM(total), 0) as revenue
         FROM orders
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND status != 'cancelled'
         GROUP BY payment_method`,
        [daysBack]
      );

      // Top selling hours
      const [byHour] = await db.execute(
        `SELECT HOUR(created_at) as hour,
                COUNT(*) as orders,
                COALESCE(SUM(total), 0) as revenue
         FROM orders
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND status != 'cancelled'
         GROUP BY HOUR(created_at)
         ORDER BY hour ASC`,
        [daysBack]
      );

      salesData = {
        timeline: daily,
        byStatus,
        byPaymentMethod: byPayment,
        byHour,
        period,
        groupBy
      };

      // Cache for 30 minutes
      await cache.set(cacheKey, salesData, 1800);
    }

    res.json({
      success: true,
      data: salesData
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get user analytics
 */
export const getUserAnalytics = async (req, res, next) => {
  try {
    const { period = '30d' } = req.query;

    let daysBack = 30;
    if (period === '7d') daysBack = 7;
    else if (period === '90d') daysBack = 90;

    const cacheKey = `analytics:users:${period}`;
    let userData = await cache.get(cacheKey);

    if (!userData) {
      // User growth
      const [growth] = await db.execute(
        `SELECT DATE(created_at) as date, COUNT(*) as new_users
         FROM users
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
         GROUP BY DATE(created_at)
         ORDER BY date ASC`,
        [daysBack]
      );

      // User retention (users who made repeat purchases)
      const [retention] = await db.execute(
        `SELECT 
          COUNT(DISTINCT u.id) as total_users,
          COUNT(DISTINCT CASE WHEN order_count > 1 THEN u.id END) as repeat_customers,
          COALESCE(COUNT(DISTINCT CASE WHEN order_count > 1 THEN u.id END) / COUNT(DISTINCT u.id) * 100, 0) as retention_rate
         FROM users u
         LEFT JOIN (
           SELECT user_id, COUNT(*) as order_count
           FROM orders
           WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           GROUP BY user_id
         ) o ON u.id = o.user_id`,
        [daysBack]
      );

      // User activity
      const [activity] = await db.execute(
        `SELECT 
          COUNT(DISTINCT CASE WHEN last_login_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN id END) as active_7d,
          COUNT(DISTINCT CASE WHEN last_login_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN id END) as active_30d,
          COUNT(DISTINCT CASE WHEN last_login_at < DATE_SUB(NOW(), INTERVAL 30 DAY) THEN id END) as inactive
         FROM users
         WHERE is_active = TRUE`
      );

      // User segments by order value
      const [segments] = await db.execute(
        `SELECT 
          CASE 
            WHEN total_spent = 0 THEN 'No Purchase'
            WHEN total_spent < 100 THEN 'Low Value'
            WHEN total_spent < 500 THEN 'Medium Value'
            ELSE 'High Value'
          END as segment,
          COUNT(*) as user_count
         FROM (
           SELECT u.id, COALESCE(SUM(o.total), 0) as total_spent
           FROM users u
           LEFT JOIN orders o ON u.id = o.user_id AND o.status != 'cancelled'
           GROUP BY u.id
         ) user_totals
         GROUP BY segment`
      );

      // Top customers
      const [topCustomers] = await db.execute(
        `SELECT u.id, u.username, u.email,
                COUNT(o.id) as order_count,
                COALESCE(SUM(o.total), 0) as total_spent
         FROM users u
         JOIN orders o ON u.id = o.user_id
         WHERE o.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
           AND o.status != 'cancelled'
         GROUP BY u.id, u.username, u.email
         ORDER BY total_spent DESC
         LIMIT 10`,
        [daysBack]
      );

      userData = {
        growth,
        retention: retention[0],
        activity: activity[0],
        segments,
        topCustomers,
        period
      };

      // Cache for 30 minutes
      await cache.set(cacheKey, userData, 1800);
    }

    res.json({
      success
