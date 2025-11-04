/**
 * ============================================================================
 * FORCE BROWSING VULNERABILITY MODULE - MILITARY-GRADE ENTERPRISE EDITION
 * ============================================================================
 * 
 * Advanced Force Browsing (Forced Directory Browsing) Demonstration Platform
 * Implements sophisticated directory traversal and unauthorized resource access
 * 
 * @module vulnerabilities/access/forceBrowsing
 * @category Security Training - OWASP A01:2021 (Broken Access Control)
 * @version 3.0.0
 * @license MIT
 * @author Elite Security Research Team
 * 
 * ============================================================================
 * SECURITY WARNING - CRITICAL:
 * ============================================================================
 * This module contains INTENTIONAL SEVERE security vulnerabilities:
 * - Unrestricted file system access
 * - Missing authentication checks
 * - Direct object reference without validation
 * - Path traversal vulnerabilities
 * - Information disclosure through directory listing
 * - Predictable resource locations
 * - No access control enforcement
 * - Session-less sensitive operations
 * 
 * ⚠️  EXTREME DANGER: NEVER use these patterns in production
 * ⚠️  FOR CONTROLLED SECURITY TRAINING ONLY
 * ⚠️  Must be deployed in isolated sandbox environments
 * ⚠️  Requires strict network segmentation
 * 
 * ============================================================================
 * VULNERABILITY TYPES DEMONSTRATED:
 * ============================================================================
 * 1. Forced Directory Browsing
 * 2. Predictable Resource Locations (/admin, /config, /backup)
 * 3. Missing Function-Level Access Control
 * 4. Unrestricted File Access
 * 5. Information Disclosure via Directory Listings
 * 6. Hidden Administrative Interfaces
 * 7. Debug/Development Endpoints in Production
 * 8. API Endpoint Enumeration
 * 9. Resource Discovery Through Guessing
 * 10. Backup File Access (.bak, .old, .backup)
 * 11. Configuration File Exposure
 * 12. Git/SVN Metadata Exposure
 * 13. Server-Side Include (SSI) Exposure
 * 14. Log File Access
 * 15. Database Backup Access
 * 
 * ============================================================================
 * ATTACK VECTORS SUPPORTED:
 * ============================================================================
 * - /admin/dashboard
 * - /api/internal/users
 * - /config/database.php
 * - /backup/db_backup.sql
 * - /.git/config
 * - /.env
 * - /logs/error.log
 * - /uploads/private/
 * - /temp/debug.log
 * - /api/v1/admin/
 * - /test/phpinfo.php
 * - /server-status
 * - /.htaccess
 * - /web.config
 * 
 * ============================================================================
 * COMPLIANCE & STANDARDS:
 * ============================================================================
 * - OWASP Top 10 2021: A01 - Broken Access Control
 * - CWE-425: Direct Request (Forced Browsing)
 * - CWE-425: Direct Request ('Force Browsing')
 * - CWE-552: Files or Directories Accessible to External Parties
 * - NIST 800-53: AC-3 Access Enforcement
 * - PCI-DSS: Requirement 6.5.8
 * - ISO 27001: A.9.4.1 Information Access Restriction
 * 
 * @requires Database
 * @requires Logger
 * @requires FileSystem
 * @requires Cache
 */

import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
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
  ERROR_MESSAGES,
  USER_ROLES
} from '../../config/constants.js';
import { AppError, AccessDeniedError } from '../../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

const readdir = promisify(fs.readdir);
const readFile = promisify(fs.readFile);
const stat = promisify(fs.stat);
const access = promisify(fs.access);

// ============================================================================
// VULNERABILITY CONSTANTS & PATTERNS
// ============================================================================

const FORCE_BROWSING_PATTERNS = {
  // Administrative paths
  ADMIN_PATHS: [
    '/admin',
    '/administrator',
    '/admin/dashboard',
    '/admin/users',
    '/admin/settings',
    '/admin/config',
    '/admin/logs',
    '/cpanel',
    '/control-panel',
    '/wp-admin',
    '/phpmyadmin',
    '/adminer',
    '/manager',
    '/console'
  ],

  // API endpoints
  API_PATHS: [
    '/api/internal',
    '/api/admin',
    '/api/v1/admin',
    '/api/debug',
    '/api/test',
    '/graphql',
    '/api-docs',
    '/swagger',
    '/api/private'
  ],

  // Configuration files
  CONFIG_FILES: [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/config/database.php',
    '/config/config.php',
    '/app/config.json',
    '/web.config',
    '/.htaccess',
    '/config.ini',
    '/settings.json'
  ],

  // Backup files
  BACKUP_FILES: [
    '/backup/db_backup.sql',
    '/backup/site_backup.zip',
    '/db_backup.sql',
    '/backup.sql',
    '/.backup',
    '/backups/',
    '/old/',
    '/temp/',
    '/.old',
    '/.bak'
  ],

  // Version control
  VCS_PATHS: [
    '/.git',
    '/.git/config',
    '/.git/HEAD',
    '/.svn',
    '/.hg',
    '/CVS'
  ],

  // Debug/Test paths
  DEBUG_PATHS: [
    '/debug',
    '/test',
    '/phpinfo.php',
    '/info.php',
    '/test.php',
    '/debug.log',
    '/trace.log',
    '/error.log'
  ],

  // Log files
  LOG_FILES: [
    '/logs/error.log',
    '/logs/access.log',
    '/logs/debug.log',
    '/log/error.log',
    '/var/log/apache2/error.log',
    '/var/log/nginx/error.log'
  ],

  // Sensitive directories
  SENSITIVE_DIRS: [
    '/private',
    '/internal',
    '/restricted',
    '/confidential',
    '/uploads/private',
    '/storage/private',
    '/data/sensitive'
  ]
};

const SENSITIVE_FILE_EXTENSIONS = [
  '.env',
  '.config',
  '.ini',
  '.conf',
  '.cfg',
  '.sql',
  '.bak',
  '.backup',
  '.old',
  '.save',
  '.swp',
  '.log',
  '.key',
  '.pem',
  '.crt',
  '.pfx',
  '.p12'
];

const PREDICTABLE_PATTERNS = {
  ADMIN_USERNAMES: ['admin', 'administrator', 'root', 'superuser', 'sa', 'sysadmin'],
  COMMON_PORTS: [80, 443, 8080, 8443, 3000, 5000, 8000, 9000],
  COMMON_SUBDOMAINS: ['admin', 'api', 'dev', 'staging', 'test', 'internal', 'vpn'],
  FILE_SEQUENCES: ['file1', 'file2', 'doc1', 'doc2', 'backup1', 'backup2']
};

// ============================================================================
// FORCE BROWSING VULNERABILITY CLASS - MILITARY-GRADE
// ============================================================================

export class ForceBrowsing {
  constructor() {
    this.name = 'Force Browsing / Forced Directory Browsing';
    this.category = 'Access Control';
    this.cvssScore = 8.6;
    this.severity = ATTACK_SEVERITY.HIGH;
    this.owaspId = 'A01:2021';
    this.cweId = 'CWE-425';
    
    // Attack statistics with advanced metrics
    this.attackStats = {
      totalAttempts: 0,
      successfulAccess: 0,
      blockedAttempts: 0,
      uniquePaths: new Set(),
      pathsByType: {},
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      discoveredResources: new Set(),
      sensitiveFileAccess: 0,
      directoryListings: 0,
      configFileAccess: 0,
      backupFileAccess: 0,
      apiEndpointAccess: 0,
      adminPathAccess: 0,
      attackVectors: {},
      timeDistribution: {},
      ipAddresses: new Set(),
      userAgents: new Set()
    };

    // Resource cache for predictable patterns
    this.knownResources = new Map();
    this.hiddenEndpoints = new Map();
    this.initializeHiddenResources();
  }

  // ==========================================================================
  // INITIALIZATION & SETUP
  // ==========================================================================

  /**
   * Initialize hidden resources and endpoints
   * Simulates commonly exposed but should-be-protected resources
   */
  initializeHiddenResources() {
    // Admin endpoints
    this.hiddenEndpoints.set('/admin/dashboard', {
      type: 'admin',
      severity: ATTACK_SEVERITY.CRITICAL,
      requiresAuth: true,
      requiredRole: USER_ROLES.ADMIN,
      description: 'Administrative Dashboard',
      sensitiveData: true
    });

    this.hiddenEndpoints.set('/admin/users', {
      type: 'admin',
      severity: ATTACK_SEVERITY.CRITICAL,
      requiresAuth: true,
      requiredRole: USER_ROLES.ADMIN,
      description: 'User Management Panel',
      sensitiveData: true
    });

    // API endpoints
    this.hiddenEndpoints.set('/api/internal/metrics', {
      type: 'api',
      severity: ATTACK_SEVERITY.HIGH,
      requiresAuth: true,
      description: 'Internal System Metrics',
      sensitiveData: true
    });

    this.hiddenEndpoints.set('/api/debug/logs', {
      type: 'debug',
      severity: ATTACK_SEVERITY.HIGH,
      requiresAuth: true,
      description: 'Debug Log Access',
      sensitiveData: true
    });

    // Configuration files
    this.hiddenEndpoints.set('/.env', {
      type: 'config',
      severity: ATTACK_SEVERITY.CRITICAL,
      requiresAuth: false,
      description: 'Environment Configuration',
      sensitiveData: true
    });

    this.hiddenEndpoints.set('/config/database.json', {
      type: 'config',
      severity: ATTACK_SEVERITY.CRITICAL,
      requiresAuth: false,
      description: 'Database Configuration',
      sensitiveData: true
    });

    // Backup files
    this.hiddenEndpoints.set('/backup/db_backup.sql', {
      type: 'backup',
      severity: ATTACK_SEVERITY.CRITICAL,
      requiresAuth: false,
      description: 'Database Backup',
      sensitiveData: true
    });

    // Log files
    this.hiddenEndpoints.set('/logs/error.log', {
      type: 'log',
      severity: ATTACK_SEVERITY.MEDIUM,
      requiresAuth: false,
      description: 'Error Log File',
      sensitiveData: true
    });

    // Version control
    this.hiddenEndpoints.set('/.git/config', {
      type: 'vcs',
      severity: ATTACK_SEVERITY.HIGH,
      requiresAuth: false,
      description: 'Git Configuration',
      sensitiveData: true
    });

    logger.info('Hidden resources initialized', {
      count: this.hiddenEndpoints.size
    });
  }

  // ==========================================================================
  // VULNERABLE IMPLEMENTATIONS
  // ==========================================================================

  /**
   * ⚠️ VULNERABLE: Access Admin Dashboard Without Authentication
   * 
   * Demonstrates missing authentication on administrative interface
   * Attack: Direct URL access to /admin/dashboard
   * 
   * @param {object} req - Request object (no auth check)
   * @param {object} context - Attack context
   * @returns {Promise<object>} Dashboard data (EXPOSED)
   */
  async vulnerableAccessAdminDashboard(req, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.adminPathAccess++;

    try {
      // ⚠️ VULNERABLE: No authentication or authorization check
      logger.warn('🚨 ADMIN DASHBOARD ACCESSED WITHOUT AUTH', {
        path: '/admin/dashboard',
        ip: context.ip,
        userAgent: context.userAgent,
        mode: Config.security.mode
      });

      // Detect attack
      const detection = this.detectForceBrowsing('/admin/dashboard', context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'ADMIN_PATH_ACCESS',
          severity: ATTACK_SEVERITY.CRITICAL,
          path: '/admin/dashboard',
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Retrieve sensitive admin data without checks
      const [stats] = await db.execute(`
        SELECT 
          (SELECT COUNT(*) FROM ${tables.USERS}) as total_users,
          (SELECT COUNT(*) FROM ${tables.ORDERS}) as total_orders,
          (SELECT SUM(total_amount) FROM ${tables.ORDERS}) as total_revenue,
          (SELECT COUNT(*) FROM ${tables.PRODUCTS}) as total_products,
          (SELECT COUNT(*) FROM ${tables.ATTACK_LOGS}) as total_attacks,
          (SELECT COUNT(*) FROM ${tables.USERS} WHERE is_active = 1) as active_users,
          (SELECT COUNT(*) FROM ${tables.USERS} WHERE role = 'admin') as admin_users
      `);

      // ⚠️ VULNERABLE: Expose recent user registrations
      const [recentUsers] = await db.execute(`
        SELECT id, username, email, role, created_at, last_login_at, last_login_ip
        FROM ${tables.USERS}
        ORDER BY created_at DESC
        LIMIT 50
      `);

      // ⚠️ VULNERABLE: Expose recent attacks
      const [recentAttacks] = await db.execute(`
        SELECT attack_type, severity, ip_address, user_agent, timestamp
        FROM ${tables.ATTACK_LOGS}
        ORDER BY timestamp DESC
        LIMIT 100
      `);

      // ⚠️ VULNERABLE: Expose system configuration
      const [systemConfig] = await db.execute(`
        SELECT setting_key, setting_value, updated_at
        FROM ${tables.SETTINGS}
        WHERE setting_key IN ('maintenance_mode', 'allow_registration', 'security_mode')
      `);

      this.attackStats.successfulAccess++;
      this.attackStats.discoveredResources.add('/admin/dashboard');

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          statistics: stats[0],
          recentUsers: recentUsers,
          recentAttacks: recentAttacks,
          systemConfiguration: systemConfig,
          serverInfo: {
            nodeVersion: process.version,
            platform: process.platform,
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            env: process.env.NODE_ENV
          }
        },
        metadata: {
          path: '/admin/dashboard',
          accessedWithoutAuth: true,
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      logger.error('Force browsing error', { error: error.message });
      return this.handleVulnerableError(error, '/admin/dashboard', Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Access API Internal Endpoints
   * 
   * Exposes internal API endpoints without authentication
   * Attack: /api/internal/users, /api/internal/metrics
   * 
   * @param {string} endpoint - Internal endpoint path
   * @param {object} context - Attack context
   * @returns {Promise<object>} Internal API data (EXPOSED)
   */
  async vulnerableAccessInternalAPI(endpoint, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.apiEndpointAccess++;

    try {
      // ⚠️ VULNERABLE: No API key or authentication check
      logger.warn('🚨 INTERNAL API ACCESSED WITHOUT AUTH', {
        endpoint,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectForceBrowsing(endpoint, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'INTERNAL_API_ACCESS',
          severity: ATTACK_SEVERITY.HIGH,
          path: endpoint,
          detection,
          context
        });
      }

      let responseData = {};

      // Route to different internal endpoints
      switch (endpoint) {
        case '/api/internal/users':
          // ⚠️ VULNERABLE: Expose complete user database
          const [users] = await db.execute(`
            SELECT id, username, email, password, role, 
                   is_active, is_email_verified, two_factor_secret,
                   last_login_at, last_login_ip, failed_login_attempts,
                   created_at, updated_at
            FROM ${tables.USERS}
            ORDER BY created_at DESC
            LIMIT 1000
          `);
          responseData = { users, count: users.length };
          break;

        case '/api/internal/metrics':
          // ⚠️ VULNERABLE: Expose system metrics
          const [metrics] = await db.execute(`
            SELECT 
              (SELECT COUNT(*) FROM ${tables.USERS}) as users,
              (SELECT COUNT(*) FROM ${tables.ORDERS}) as orders,
              (SELECT COUNT(*) FROM ${tables.ATTACK_LOGS}) as attacks,
              (SELECT AVG(total_amount) FROM ${tables.ORDERS}) as avg_order
          `);
          responseData = {
            metrics: metrics[0],
            system: {
              uptime: process.uptime(),
              memory: process.memoryUsage(),
              cpu: process.cpuUsage(),
              pid: process.pid
            }
          };
          break;

        case '/api/internal/tokens':
          // ⚠️ VULNERABLE: Expose active API tokens
          const [tokens] = await db.execute(`
            SELECT user_id, token, expires_at, created_at, last_used
            FROM ${tables.API_TOKENS}
            WHERE expires_at > NOW()
            LIMIT 100
          `);
          responseData = { tokens };
          break;

        case '/api/internal/sessions':
          // ⚠️ VULNERABLE: Expose active user sessions
          const [sessions] = await db.execute(`
            SELECT user_id, session_id, ip_address, user_agent, 
                   created_at, expires_at, last_activity
            FROM ${tables.USER_SESSIONS}
            WHERE expires_at > NOW()
            LIMIT 200
          `);
          responseData = { sessions };
          break;

        default:
          responseData = { 
            message: 'Internal API endpoint',
            availableEndpoints: [
              '/api/internal/users',
              '/api/internal/metrics',
              '/api/internal/tokens',
              '/api/internal/sessions'
            ]
          };
      }

      this.attackStats.successfulAccess++;
      this.attackStats.discoveredResources.add(endpoint);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: responseData,
        metadata: {
          endpoint,
          accessedWithoutAuth: true,
          executionTime: duration,
          severity: ATTACK_SEVERITY.HIGH,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, endpoint, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Access Configuration Files
   * 
   * Exposes configuration files containing sensitive credentials
   * Attack: /.env, /config/database.json, /web.config
   * 
   * @param {string} filePath - Configuration file path
   * @param {object} context - Attack context
   * @returns {Promise<object>} Configuration file contents (EXPOSED)
   */
  async vulnerableAccessConfigFile(filePath, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.configFileAccess++;

    try {
      logger.warn('🚨 CONFIG FILE ACCESS ATTEMPT', {
        filePath,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectForceBrowsing(filePath, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'CONFIG_FILE_ACCESS',
          severity: ATTACK_SEVERITY.CRITICAL,
          path: filePath,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Simulate config file content exposure
      let configContent = {};

      switch (filePath) {
        case '/.env':
          configContent = {
            DB_HOST: Config.database.host,
            DB_PORT: Config.database.port,
            DB_USER: Config.database.user,
            DB_PASSWORD: Config.database.password,
            DB_NAME: Config.database.name,
            JWT_SECRET: Config.jwt.secret,
            JWT_REFRESH_SECRET: Config.jwt.refreshSecret,
            SESSION_SECRET: Config.session.secret,
            REDIS_HOST: Config.redis.host,
            REDIS_PASSWORD: Config.redis.password,
            EMAIL_HOST: Config.email.host,
            EMAIL_USER: Config.email.user,
            EMAIL_PASSWORD: Config.email.password,
            AWS_ACCESS_KEY: process.env.AWS_ACCESS_KEY || 'AKIAIOSFODNN7EXAMPLE',
            AWS_SECRET_KEY: process.env.AWS_SECRET_KEY || 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY || 'sk_test_example123',
            API_KEY: process.env.API_KEY || 'api_key_1234567890abcdef'
          };
          break;

        case '/config/database.json':
          configContent = {
            production: {
              host: Config.database.host,
              port: Config.database.port,
              user: Config.database.user,
              password: Config.database.password,
              database: Config.database.name,
              connectionLimit: Config.database.connectionLimit
            },
            development: {
              host: 'localhost',
              port: 3306,
              user: 'dev_user',
              password: 'dev_password_123',
              database: 'dev_database'
            }
          };
          break;

        case '/config/secrets.json':
          configContent = {
            jwtSecret: Config.jwt.secret,
            sessionSecret: Config.session.secret,
            encryptionKey: 'encryption_key_example_1234567890',
            apiKeys: {
              internal: 'internal_api_key_123',
              external: 'external_api_key_456',
              admin: 'admin_api_key_789'
            }
          };
          break;

        default:
          configContent = { 
            message: 'Configuration file', 
            file: filePath,
            warning: 'This file contains sensitive information'
          };
      }

      this.attackStats.successfulAccess++;
      this.attackStats.discoveredResources.add(filePath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          filePath,
          content: configContent,
          fileType: 'configuration',
          warning: 'CRITICAL: Configuration file exposed'
        },
        metadata: {
          path: filePath,
          accessedWithoutAuth: true,
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, filePath, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Access Backup Files
   * 
   * Exposes database backups and site archives
   * Attack: /backup/db_backup.sql, /backup/site.zip
   * 
   * @param {string} backupPath - Backup file path
   * @param {object} context - Attack context
   * @returns {Promise<object>} Backup file information (EXPOSED)
   */
  async vulnerableAccessBackupFile(backupPath, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.backupFileAccess++;

    try {
      logger.warn('🚨 BACKUP FILE ACCESS ATTEMPT', {
        backupPath,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectForceBrowsing(backupPath, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'BACKUP_FILE_ACCESS',
          severity: ATTACK_SEVERITY.CRITICAL,
          path: backupPath,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Expose backup file contents
      let backupData = {};

      if (backupPath.includes('.sql')) {
        // Database backup exposure
        const [sampleUsers] = await db.execute(`
          SELECT id, username, email, password, role, created_at
          FROM ${tables.USERS}
          LIMIT 10
        `);

        backupData = {
          type: 'database_backup',
          format: 'SQL',
          tables: ['users', 'orders', 'products', 'payments', 'sessions'],
          sampleData: sampleUsers,
          sqlDump: `
-- Database Backup
-- Date: ${new Date().toISOString()}
-- Database: ${Config.database.name}

CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) UNIQUE,
  email VARCHAR(100) UNIQUE,
  password VARCHAR(255),
  role VARCHAR(20),
  created_at TIMESTAMP
);

INSERT INTO users VALUES ${sampleUsers.map(u => 
  `(${u.id}, '${u.username}', '${u.email}', '${u.password}', '${u.role}', '${u.created_at}')`
).join(',\n')};
          `.trim(),
          recordCount: sampleUsers.length
        };
      } else {
        // File backup exposure
        backupData = {
          type: 'file_backup',
          format: 'ZIP/TAR',
          contents: [
            '/src/',
            '/config/',
            '/.env',
            '/database/',
            '/uploads/',
            '/logs/'
          ],
          size: '1.2 GB',
          createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
        };
      }

      this.attackStats.successfulAccess++;
      this.attackStats.discoveredResources.add(backupPath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          backupPath,
          backupData,
          downloadUrl: `/download${backupPath}`,
          warning: 'CRITICAL: Backup file accessible without authentication'
        },
        metadata: {
          path: backupPath,
          accessedWithoutAuth: true,
          executionTime: duration,
          severity: ATTACK_SEVERITY.CRITICAL,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, backupPath, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Directory Listing
   * 
   * Lists directory contents without authorization
   * Attack: /uploads/, /backup/, /logs/
   * 
   * @param {string} dirPath - Directory path
   * @param {object} context - Attack context
   * @returns {Promise<object>} Directory contents (EXPOSED)
   */
  async vulnerableDirectoryListing(dirPath, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;
    this.attackStats.directoryListings++;

    try {
      logger.warn('🚨 DIRECTORY LISTING ATTEMPT', {
        dirPath,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectForceBrowsing(dirPath, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'DIRECTORY_LISTING',
          severity: ATTACK_SEVERITY.HIGH,
          path: dirPath,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: List directory contents without checks
      let files = [];

      // Simulate directory contents based on path
      if (dirPath.includes('/uploads')) {
        files = [
          { name: 'user_123_profile.jpg', size: '245 KB', modified: new Date() },
          { name: 'invoice_456.pdf', size: '89 KB', modified: new Date() },
          { name: 'private_document.docx', size: '156 KB', modified: new Date() },
          { name: 'id_card_scan.jpg', size: '1.2 MB', modified: new Date() },
          { name: 'payment_receipt.pdf', size: '67 KB', modified: new Date() }
        ];
      } else if (dirPath.includes('/logs')) {
        files = [
          { name: 'error.log', size: '5.6 MB', modified: new Date(), type: 'log' },
          { name: 'access.log', size: '28.3 MB', modified: new Date(), type: 'log' },
          { name: 'debug.log', size: '2.1 MB', modified: new Date(), type: 'log' },
          { name: 'attack.log', size: '892 KB', modified: new Date(), type: 'log' },
          { name: 'audit.log', size: '1.4 MB', modified: new Date(), type: 'log' }
        ];
      } else if (dirPath.includes('/backup')) {
        files = [
          { name: 'db_backup_20240115.sql', size: '156 MB', modified: new Date(), type: 'sql' },
          { name: 'site_backup_20240120.tar.gz', size: '1.2 GB', modified: new Date(), type: 'archive' },
          { name: 'config_backup.zip', size: '2.3 MB', modified: new Date(), type: 'archive' },
          { name: 'users_export.csv', size: '45 KB', modified: new Date(), type: 'csv' }
        ];
      } else if (dirPath.includes('/config')) {
        files = [
          { name: 'database.json', size: '1.2 KB', modified: new Date(), type: 'json' },
          { name: 'secrets.json', size: '856 B', modified: new Date(), type: 'json' },
          { name: 'app.config', size: '3.4 KB', modified: new Date(), type: 'config' },
          { name: '.env.backup', size: '2.1 KB', modified: new Date(), type: 'env' }
        ];
      } else {
        files = [
          { name: 'index.html', size: '12 KB', modified: new Date(), type: 'html' },
          { name: 'styles.css', size: '45 KB', modified: new Date(), type: 'css' },
          { name: 'script.js', size: '89 KB', modified: new Date(), type: 'js' }
        ];
      }

      this.attackStats.successfulAccess++;
      this.attackStats.discoveredResources.add(dirPath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          directory: dirPath,
          files: files,
          totalFiles: files.length,
          parentDirectory: path.dirname(dirPath),
          warning: 'Directory listing exposed without authentication'
        },
        metadata: {
          path: dirPath,
          accessedWithoutAuth: true,
          executionTime: duration,
          severity: ATTACK_SEVERITY.HIGH,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, dirPath, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Access Log Files
   * 
   * Exposes application and server logs
   * Attack: /logs/error.log, /logs/debug.log
   * 
   * @param {string} logPath - Log file path
   * @param {object} context - Attack context
   * @returns {Promise<object>} Log file contents (EXPOSED)
   */
  async vulnerableAccessLogFile(logPath, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 LOG FILE ACCESS ATTEMPT', {
        logPath,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectForceBrowsing(logPath, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'LOG_FILE_ACCESS',
          severity: ATTACK_SEVERITY.MEDIUM,
          path: logPath,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Retrieve recent log entries
      const [logs] = await db.execute(`
        SELECT attack_type, severity, payload, ip_address, user_agent, timestamp
        FROM ${tables.ATTACK_LOGS}
        ORDER BY timestamp DESC
        LIMIT 100
      `);

      const logContent = logs.map(log => 
        `[${log.timestamp}] [${log.severity}] ${log.attack_type} - IP: ${log.ip_address} - ${JSON.stringify(log.payload)}`
      ).join('\n');

      this.attackStats.successfulAccess++;
      this.attackStats.discoveredResources.add(logPath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: {
          logPath,
          logContent,
          entries: logs.length,
          warning: 'Log file contains sensitive information'
        },
        metadata: {
          path: logPath,
          accessedWithoutAuth: true,
          executionTime: duration,
          severity: ATTACK_SEVERITY.MEDIUM,
          attackDetected: detection.isAttack
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, logPath, Date.now() - startTime);
    }
  }

  /**
   * ⚠️ VULNERABLE: Git Repository Access
   * 
   * Exposes .git directory contents
   * Attack: /.git/config, /.git/HEAD
   * 
   * @param {string} gitPath - Git file path
   * @param {object} context - Attack context
   * @returns {Promise<object>} Git repository information (EXPOSED)
   */
  async vulnerableAccessGitRepo(gitPath, context = {}) {
    const startTime = Date.now();
    this.attackStats.totalAttempts++;

    try {
      logger.warn('🚨 GIT REPOSITORY ACCESS ATTEMPT', {
        gitPath,
        ip: context.ip,
        mode: Config.security.mode
      });

      const detection = this.detectForceBrowsing(gitPath, context);
      
      if (detection.isAttack) {
        await this.logAttack({
          type: 'VCS_ACCESS',
          severity: ATTACK_SEVERITY.HIGH,
          path: gitPath,
          detection,
          context
        });
      }

      // ⚠️ VULNERABLE: Expose Git configuration
      let gitData = {};

      if (gitPath === '/.git/config') {
        gitData = {
          file: '/.git/config',
          content: `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/company/sqli-demo-platform.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = Developer
\temail = dev@company.com`,
          exposedInfo: ['Repository URL', 'Developer email', 'Branch information']
        };
      } else if (gitPath === '/.git/HEAD') {
        gitData = {
          file: '/.git/HEAD',
          content: 'ref: refs/heads/main',
          currentBranch: 'main'
        };
      } else {
        gitData = {
          availableFiles: [
            '/.git/config',
            '/.git/HEAD',
            '/.git/index',
            '/.git/logs/',
            '/.git/refs/'
          ]
        };
      }

      this.attackStats.successfulAccess++;
      this.attackStats.discoveredResources.add(gitPath);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: true,
        data: gitData,
        metadata: {
          path: gitPath,
          accessedWithoutAuth: true,
          executionTime: duration,
          severity: ATTACK_SEVERITY.HIGH,
          attackDetected: detection.isAttack,
          warning: 'Git repository metadata exposed'
        }
      };

    } catch (error) {
      return this.handleVulnerableError(error, gitPath, Date.now() - startTime);
    }
  }

  // ==========================================================================
  // SECURE IMPLEMENTATIONS (REFERENCE)
  // ==========================================================================

  /**
   * ✅ SECURE: Access Admin Dashboard with Authentication
   * 
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} Dashboard data (PROTECTED)
   */
  async secureAccessAdminDashboard(req) {
    const startTime = Date.now();

    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AccessDeniedError('Authentication required');
      }

      // ✅ Authorization check
      if (req.user.role !== USER_ROLES.ADMIN) {
        throw new AccessDeniedError('Admin privileges required');
      }

      // ✅ Retrieve sanitized statistics
      const [stats] = await db.execute(`
        SELECT 
          (SELECT COUNT(*) FROM ${tables.USERS}) as total_users,
          (SELECT COUNT(*) FROM ${tables.ORDERS}) as total_orders,
          (SELECT SUM(total_amount) FROM ${tables.ORDERS}) as total_revenue
      `);

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: {
          statistics: stats[0]
        },
        metadata: {
          executionTime: duration,
          authenticated: true,
          authorized: true
        }
      };

    } catch (error) {
      logger.error('Secure admin access error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: Access API with Authentication
   * 
   * @param {string} endpoint - API endpoint
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} API data (PROTECTED)
   */
  async secureAccessInternalAPI(endpoint, req) {
    const startTime = Date.now();

    try {
      // ✅ API key validation
      const apiKey = req.headers['x-api-key'];
      if (!apiKey) {
        throw new AccessDeniedError('API key required');
      }

      // ✅ Validate API key
      const [keys] = await db.execute(
        `SELECT user_id, permissions FROM ${tables.API_TOKENS} 
         WHERE token = ? AND expires_at > NOW() LIMIT 1`,
        [apiKey]
      );

      if (keys.length === 0) {
        throw new AccessDeniedError('Invalid API key');
      }

      // ✅ Check permissions
      const permissions = JSON.parse(keys[0].permissions || '[]');
      if (!permissions.includes('internal_api')) {
        throw new AccessDeniedError('Insufficient permissions');
      }

      // Return limited data based on permissions
      const responseData = { message: 'Secure API access granted' };

      const duration = Date.now() - startTime;

      return {
        success: true,
        vulnerable: false,
        data: responseData,
        metadata: {
          executionTime: duration,
          authenticated: true,
          authorized: true
        }
      };

    } catch (error) {
      logger.error('Secure API access error', { error: error.message });
      throw error;
    }
  }

  /**
   * ✅ SECURE: File Access with Authorization
   * 
   * @param {string} filePath - File path
   * @param {object} req - Request with authentication
   * @returns {Promise<object>} File data (PROTECTED)
   */
  async secureFileAccess(filePath, req) {
    try {
      // ✅ Authentication check
      if (!req.user) {
        throw new AccessDeniedError('Authentication required');
      }

      // ✅ Path traversal prevention
      const normalizedPath = path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');

      // ✅ Whitelist check
      const allowedPaths = ['/uploads/public/', '/downloads/'];
      const isAllowed = allowedPaths.some(allowed => normalizedPath.startsWith(allowed));

      if (!isAllowed) {
        throw new AccessDeniedError('Access denied');
      }

      // ✅ File ownership check
      const [files] = await db.execute(
        `SELECT id, user_id FROM ${tables.FILES} WHERE file_path = ? LIMIT 1`,
        [normalizedPath]
      );

      if (files.length === 0 || files[0].user_id !== req.user.id) {
        throw new AccessDeniedError('File not found or access denied');
      }

      return {
        success: true,
        vulnerable: false,
        data: { filePath: normalizedPath }
      };

    } catch (error) {
      logger.error('Secure file access error', { error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTACK DETECTION & LOGGING
  // ==========================================================================

  /**
   * Detect force browsing patterns
   * 
   * @param {string} path - Requested path
   * @param {object} context - Request context
   * @returns {object} Detection results
   */
  detectForceBrowsing(path, context = {}) {
    const detectedPatterns = [];
    let severity = ATTACK_SEVERITY.LOW;
    let score = 0;

    // Check against known sensitive paths
    for (const [category, paths] of Object.entries(FORCE_BROWSING_PATTERNS)) {
      for (const pattern of paths) {
        if (path.toLowerCase().includes(pattern.toLowerCase())) {
          detectedPatterns.push({
            category,
            pattern,
            matched: true
          });
          score += this.getPathScore(category);
        }
      }
    }

    // Check file extensions
    for (const ext of SENSITIVE_FILE_EXTENSIONS) {
      if (path.toLowerCase().endsWith(ext)) {
        detectedPatterns.push({
          category: 'SENSITIVE_FILE_EXTENSION',
          extension: ext,
          matched: true
        });
        score += 5;
      }
    }

    // Check for predictable patterns
    if (this.checkPredictablePattern(path)) {
      detectedPatterns.push({
        category: 'PREDICTABLE_RESOURCE',
        matched: true
      });
      score += 3;
    }

    // Determine severity
    if (score >= 15) severity = ATTACK_SEVERITY.CRITICAL;
    else if (score >= 10) severity = ATTACK_SEVERITY.HIGH;
    else if (score >= 5) severity = ATTACK_SEVERITY.MEDIUM;

    const isAttack = detectedPatterns.length > 0;

    if (isAttack) {
      this.updateAttackStats(severity, path);
    }

    return {
      isAttack,
      severity,
      score,
      patterns: detectedPatterns,
      path,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Check for predictable resource patterns
   */
  checkPredictablePattern(path) {
    const predictableIndicators = [
      /\d{1,3}$/, // Numeric sequences (file1, file2)
      /backup/i,
      /old/i,
      /temp/i,
      /test/i,
      /dev/i,
      /admin/i,
      /private/i,
      /internal/i
    ];

    return predictableIndicators.some(pattern => pattern.test(path));
  }

  /**
   * Get path category score
   */
  getPathScore(category) {
    const scores = {
      ADMIN_PATHS: 10,
      CONFIG_FILES: 15,
      BACKUP_FILES: 15,
      VCS_PATHS: 10,
      API_PATHS: 8,
      LOG_FILES: 5,
      DEBUG_PATHS: 8,
      SENSITIVE_DIRS: 12
    };
    return scores[category] || 1;
  }

  /**
   * Update attack statistics
   */
  updateAttackStats(severity, path) {
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

    this.attackStats.uniquePaths.add(path);
    this.attackStats.blockedAttempts++;
  }

  /**
   * Log attack attempt
   */
  async logAttack(attackData) {
    try {
      const { type, severity, path, detection, context } = attackData;

      await db.execute(
        `INSERT INTO ${tables.ATTACK_LOGS} (
          attack_type, severity, payload, patterns,
          ip_address, user_agent, user_id, endpoint,
          timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [
          type,
          severity,
          JSON.stringify({ path }),
          JSON.stringify(detection.patterns),
          context.ip || null,
          context.userAgent || null,
          context.userId || null,
          path
        ]
      );

      // Cache attack for rate limiting
      const cacheKey = CacheKeyBuilder.custom('force_browse_attacks:', context.ip);
      const recentAttacks = await cache.get(cacheKey) || [];
      recentAttacks.push({
        type,
        severity,
        path,
        timestamp: new Date().toISOString()
      });
      await cache.set(cacheKey, recentAttacks, 3600);

      logger.attack('Force Browsing Attack Detected', {
        type,
        severity,
        path,
        patterns: detection.patterns.map(p => p.category),
        context
      });

    } catch (error) {
      logger.error('Failed to log attack', { error: error.message });
    }
  }

  /**
   * Handle vulnerable errors
   */
  handleVulnerableError(error, path, duration) {
    logger.error('Force browsing error', {
      message: error.message,
      path,
      duration
    });

    return {
      success: false,
      vulnerable: true,
      error: {
        message: error.message,
        code: error.code,
        path
      },
      metadata: {
        executionTime: duration,
        errorType: 'FORCE_BROWSING_ERROR'
      }
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
      uniquePaths: this.attackStats.uniquePaths.size,
      discoveredResources: this.attackStats.discoveredResources.size,
      ipAddresses: this.attackStats.ipAddresses.size,
      userAgents: this.attackStats.userAgents.size,
      successRate: this.attackStats.totalAttempts > 0
        ? (this.attackStats.successfulAccess / this.attackStats.totalAttempts * 100).toFixed(2) + '%'
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
      description: 'Force Browsing allows attackers to access unauthorized resources by guessing or enumerating URLs',
      impact: [
        'Unauthorized access to administrative interfaces',
        'Exposure of sensitive configuration files',
        'Access to backup files and databases',
        'Information disclosure through directory listings',
        'Access to internal API endpoints',
        'Exposure of version control metadata'
      ],
      attackVectors: [
        '/admin/dashboard',
        '/.env',
        '/backup/db_backup.sql',
        '/.git/config',
        '/api/internal/users',
        '/logs/error.log'
      ],
      remediation: [
        'Implement proper authentication and authorization',
        'Use role-based access control (RBAC)',
        'Remove or secure development/debug endpoints',
        'Disable directory listings',
        'Implement Web Application Firewall (WAF)',
        'Use security headers (X-Frame-Options, CSP)',
        'Regular security audits and penetration testing'
      ]
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.attackStats = {
      totalAttempts: 0,
      successfulAccess: 0,
      blockedAttempts: 0,
      uniquePaths: new Set(),
      pathsByType: {},
      severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
      discoveredResources: new Set(),
      sensitiveFileAccess: 0,
      directoryListings: 0,
      configFileAccess: 0,
      backupFileAccess: 0,
      apiEndpointAccess: 0,
      adminPathAccess: 0,
      attackVectors: {},
      timeDistribution: {},
      ipAddresses: new Set(),
      userAgents: new Set()
    };
  }
}

// ============================================================================
// FACTORY & EXPORT
// ============================================================================

let instance = null;

export const getForceBrowsing = () => {
  if (!instance) {
    instance = new ForceBrowsing();
  }
  return instance;
};

export const createVulnerableHandler = (method) => {
  return async (req, res, next) => {
    try {
      const fb = getForceBrowsing();
      
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

      const result = await fb[method](req, context);
      res.json(result);

    } catch (error) {
      next(error);
    }
  };
};

export default {
  ForceBrowsing,
  getForceBrowsing,
  createVulnerableHandler
};
