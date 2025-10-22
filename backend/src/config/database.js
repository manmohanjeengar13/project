/**
 * Database Configuration Module
 * Handles all database-related settings and connection options
 */

import { Config } from './environment.js';

/**
 * Database Connection Configuration
 */
export const databaseConfig = {
  // Connection Settings
  connection: {
    host: Config.database.host,
    port: Config.database.port,
    user: Config.database.user,
    password: Config.database.password,
    database: Config.database.name,
    charset: Config.database.charset,
    timezone: Config.database.timezone,
    multipleStatements: false, // Security: Prevent SQL injection via multiple statements
    dateStrings: true,
    supportBigNumbers: true,
    bigNumberStrings: true,
    decimalNumbers: true
  },

  // Pool Configuration
  pool: {
    waitForConnections: Config.database.waitForConnections,
    connectionLimit: Config.database.connectionLimit,
    queueLimit: Config.database.queueLimit,
    enableKeepAlive: Config.database.enableKeepAlive,
    keepAliveInitialDelay: Config.database.keepAliveInitialDelay,
    maxIdle: 10, // Maximum idle connections
    idleTimeout: 60000, // Idle timeout in milliseconds
    acquireTimeout: 30000, // Timeout for acquiring connection
    timeout: 60000 // Timeout for queries
  },

  // SSL Configuration
  ssl: Config.database.ssl.enabled ? {
    ca: Config.database.ssl.ca,
    cert: Config.database.ssl.cert,
    key: Config.database.ssl.key,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2'
  } : false,

  // Query Settings
  query: {
    // Parameterized query settings
    namedPlaceholders: true,
    nestTables: false,
    rowsAsArray: false,
    
    // Query timeout (ms)
    timeout: 30000,
    
    // Query logging (only in development)
    logQueries: Config.app.env === 'development',
    
    // Slow query threshold (ms)
    slowQueryThreshold: 1000
  },

  // Migration Settings
  migrations: {
    directory: './database/migrations',
    tableName: 'migrations',
    schemaName: Config.database.name,
    disableTransactions: false
  },

  // Seed Settings
  seeds: {
    directory: './database/seeds',
    loadExtensions: ['.js'],
    timestampFilenamePrefix: true
  },

  // Backup Settings
  backup: {
    enabled: Config.backup.enabled,
    schedule: Config.backup.schedule,
    retentionDays: Config.backup.retentionDays,
    directory: Config.backup.directory,
    compression: true,
    includeViews: true,
    includeProcedures: true,
    includeTriggers: true
  },

  // Replication (for production)
  replication: {
    enabled: false,
    master: {
      host: Config.database.host,
      port: Config.database.port,
      user: Config.database.user,
      password: Config.database.password
    },
    slaves: [
      // Add slave configurations here
    ]
  },

  // Health Check
  healthCheck: {
    enabled: true,
    interval: 30000, // Check every 30 seconds
    timeout: 5000,
    retries: 3
  }
};

/**
 * Get database connection string (for logging/display)
 */
export const getDatabaseConnectionString = () => {
  return `mysql://${Config.database.user}@${Config.database.host}:${Config.database.port}/${Config.database.name}`;
};

/**
 * Validate database configuration
 */
export const validateDatabaseConfig = () => {
  const errors = [];

  if (!Config.database.host) {
    errors.push('Database host is required');
  }

  if (!Config.database.user) {
    errors.push('Database user is required');
  }

  if (!Config.database.name) {
    errors.push('Database name is required');
  }

  if (Config.database.connectionLimit < 1) {
    errors.push('Connection limit must be at least 1');
  }

  if (Config.database.port < 1 || Config.database.port > 65535) {
    errors.push('Invalid database port');
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

/**
 * Database table names (centralized)
 */
export const tables = {
  // User Management
  USERS: 'users',
  USER_SESSIONS: 'user_sessions',
  LOGIN_HISTORY: 'login_history',
  
  // Products
  CATEGORIES: 'categories',
  PRODUCTS: 'products',
  PRODUCT_VARIANTS: 'product_variants',
  PRODUCT_IMAGES: 'product_images',
  
  // Reviews
  REVIEWS: 'reviews',
  REVIEW_VOTES: 'review_votes',
  
  // Orders
  ORDERS: 'orders',
  ORDER_ITEMS: 'order_items',
  ORDER_STATUS_HISTORY: 'order_status_history',
  
  // Cart & Wishlist
  CART_ITEMS: 'cart_items',
  WISHLISTS: 'wishlists',
  
  // Coupons
  COUPONS: 'coupons',
  COUPON_USAGE: 'coupon_usage',
  
  // Admin
  ADMIN_NOTES: 'admin_notes',
  SETTINGS: 'settings',
  
  // Files
  FILES: 'files',
  
  // Notifications
  NOTIFICATIONS: 'notifications',
  
  // API
  API_TOKENS: 'api_tokens',
  WEBHOOKS: 'webhooks',
  WEBHOOK_LOGS: 'webhook_logs',
  
  // Security
  ATTACK_LOGS: 'attack_logs',
  SECURITY_EVENTS: 'security_events',
  AUDIT_LOGS: 'audit_logs',
  RATE_LIMITS: 'rate_limits',
  IP_BLACKLIST: 'ip_blacklist',
  
  // Analytics
  PAGE_VIEWS: 'page_views',
  SEARCH_QUERIES: 'search_queries'
};

/**
 * Database views
 */
export const views = {
  ADMIN_DASHBOARD: 'admin_dashboard_view',
  PRODUCT_STATS: 'product_stats_view',
  USER_ACTIVITY: 'user_activity_view',
  ATTACK_SUMMARY: 'attack_summary_view'
};

/**
 * Stored procedures
 */
export const procedures = {
  CREATE_ORDER: 'sp_create_order',
  PROCESS_PAYMENT: 'sp_process_payment',
  APPLY_COUPON: 'sp_apply_coupon',
  CALCULATE_SHIPPING: 'sp_calculate_shipping'
};

/**
 * Common SQL queries (for reuse)
 */
export const commonQueries = {
  // User queries
  findUserByUsername: `SELECT * FROM ${tables.USERS} WHERE username = ? LIMIT 1`,
  findUserByEmail: `SELECT * FROM ${tables.USERS} WHERE email = ? LIMIT 1`,
  findUserById: `SELECT * FROM ${tables.USERS} WHERE id = ? LIMIT 1`,
  
  // Product queries
  findProductById: `SELECT * FROM ${tables.PRODUCTS} WHERE id = ? LIMIT 1`,
  findProductBySlug: `SELECT * FROM ${tables.PRODUCTS} WHERE slug = ? LIMIT 1`,
  searchProducts: `SELECT * FROM ${tables.PRODUCTS} WHERE name LIKE ? OR description LIKE ?`,
  
  // Order queries
  findOrderById: `SELECT * FROM ${tables.ORDERS} WHERE id = ? LIMIT 1`,
  findOrdersByUser: `SELECT * FROM ${tables.ORDERS} WHERE user_id = ? ORDER BY created_at DESC`,
  
  // Review queries
  findReviewsByProduct: `SELECT r.*, u.username FROM ${tables.REVIEWS} r JOIN ${tables.USERS} u ON r.user_id = u.id WHERE r.product_id = ? ORDER BY r.created_at DESC`,
  
  // Attack log queries
  findRecentAttacks: `SELECT * FROM ${tables.ATTACK_LOGS} ORDER BY created_at DESC LIMIT ?`,
  findAttacksByType: `SELECT * FROM ${tables.ATTACK_LOGS} WHERE attack_type = ? ORDER BY created_at DESC LIMIT ?`,
  findAttacksByIP: `SELECT * FROM ${tables.ATTACK_LOGS} WHERE ip_address = ? ORDER BY created_at DESC LIMIT ?`
};

/**
 * Transaction isolation levels
 */
export const isolationLevels = {
  READ_UNCOMMITTED: 'READ UNCOMMITTED',
  READ_COMMITTED: 'READ COMMITTED',
  REPEATABLE_READ: 'REPEATABLE READ',
  SERIALIZABLE: 'SERIALIZABLE'
};

/**
 * Default transaction options
 */
export const transactionOptions = {
  isolationLevel: isolationLevels.REPEATABLE_READ,
  timeout: 30000
};

export default databaseConfig;
