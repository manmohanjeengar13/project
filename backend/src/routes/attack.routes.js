/**
 * Attack Routes - MILITARY-GRADE Vulnerability Testing & Attack Simulation
 * Educational platform for demonstrating security vulnerabilities
 * 
 * @module routes/attack
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ⚠️  WARNING: FOR EDUCATIONAL PURPOSES ONLY
 * ============================================================================
 * This module contains intentionally vulnerable endpoints for security
 * training and penetration testing practice. 
 * 
 * DO NOT use in production environments!
 * ============================================================================
 * 
 * VULNERABILITY CATEGORIES:
 * ============================================================================
 * - SQL Injection (SQLi)
 *   - Classic SQLi
 *   - Union-based SQLi
 *   - Blind SQLi
 *   - Time-based Blind SQLi
 *   - Second-order SQLi
 * 
 * - Cross-Site Scripting (XSS)
 *   - Stored XSS
 *   - Reflected XSS
 *   - DOM-based XSS
 * 
 * - Injection Attacks
 *   - Command Injection
 *   - LDAP Injection
 *   - XML Injection (XXE)
 *   - Template Injection
 * 
 * - Access Control
 *   - IDOR (Insecure Direct Object Reference)
 *   - Path Traversal
 *   - Privilege Escalation
 *   - Forced Browsing
 * 
 * - Authentication/Authorization
 *   - Brute Force
 *   - Session Fixation
 *   - JWT Bypass
 *   - OAuth Vulnerabilities
 * 
 * - Business Logic
 *   - Race Conditions
 *   - Mass Assignment
 *   - Price Tampering
 *   - Logic Flaws
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import express from 'express';
import { body, param, query, validationResult } from 'express-validator';

// Core imports
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';

// Controller
import attackController from '../controllers/attack.controller.js';

// Middleware
import { authenticate, optionalAuth } from '../middleware/authentication.js';
import { requireAdmin, requireModerator } from '../middleware/authorization.js';
import { 
  apiRateLimit, 
  createEndpointLimiter 
} from '../middleware/rateLimit.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { attackLogger } from '../middleware/attackLogger.js';
import { 
  getCurrentMode, 
  requireVulnerableMode,
  includeModeInfo 
} from '../middleware/modeSwitch.js';

// Config & Constants
import { Config } from '../config/environment.js';
import { 
  HTTP_STATUS, 
  ERROR_CODES,
  ATTACK_TYPES,
  ATTACK_SEVERITY 
} from '../config/constants.js';

const router = express.Router();
const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// RATE LIMITERS
// ============================================================================

const attackTestLimit = createEndpointLimiter({
  windowMs: 60 * 1000,
  max: 100, // Allow many tests
  message: 'Too many attack tests'
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

// Include security mode in all responses
router.use(includeModeInfo);

// Log all attack attempts
router.use(attackLogger);

const enhancedValidate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: ERROR_CODES.VALIDATION_ERROR,
      message: 'Validation failed',
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }
  next();
};

// ============================================================================
// ATTACK INFORMATION & DOCUMENTATION
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks:
 *   get:
 *     summary: Get list of available vulnerabilities
 *     tags: [Attacks, Documentation]
 *     responses:
 *       200:
 *         description: List of vulnerability categories
 */
router.get('/',
  apiRateLimit,
  asyncHandler(async (req, res) => {
    const vulnerabilities = {
      success: true,
      mode: getCurrentMode().mode,
      message: 'Available vulnerability categories for testing',
      categories: {
        sqli: {
          name: 'SQL Injection',
          count: 5,
          endpoints: [
            '/api/v1/attacks/sqli/classic',
            '/api/v1/attacks/sqli/union',
            '/api/v1/attacks/sqli/blind',
            '/api/v1/attacks/sqli/time-based',
            '/api/v1/attacks/sqli/second-order'
          ],
          severity: 'CRITICAL'
        },
        xss: {
          name: 'Cross-Site Scripting',
          count: 3,
          endpoints: [
            '/api/v1/attacks/xss/stored',
            '/api/v1/attacks/xss/reflected',
            '/api/v1/attacks/xss/dom'
          ],
          severity: 'HIGH'
        },
        injection: {
          name: 'Injection Attacks',
          count: 4,
          endpoints: [
            '/api/v1/attacks/injection/command',
            '/api/v1/attacks/injection/ldap',
            '/api/v1/attacks/injection/xml',
            '/api/v1/attacks/injection/template'
          ],
          severity: 'CRITICAL'
        },
        access: {
          name: 'Access Control',
          count: 4,
          endpoints: [
            '/api/v1/attacks/access/idor',
            '/api/v1/attacks/access/path-traversal',
            '/api/v1/attacks/access/privilege-escalation',
            '/api/v1/attacks/access/forced-browsing'
          ],
          severity: 'HIGH'
        },
        auth: {
          name: 'Authentication/Authorization',
          count: 4,
          endpoints: [
            '/api/v1/attacks/auth/brute-force',
            '/api/v1/attacks/auth/session-fixation',
            '/api/v1/attacks/auth/jwt-bypass',
            '/api/v1/attacks/auth/oauth'
          ],
          severity: 'CRITICAL'
        },
        business: {
          name: 'Business Logic',
          count: 4,
          endpoints: [
            '/api/v1/attacks/business/race-condition',
            '/api/v1/attacks/business/mass-assignment',
            '/api/v1/attacks/business/price-tampering',
            '/api/v1/attacks/business/logic-flaws'
          ],
          severity: 'MEDIUM'
        }
      },
      documentation: '/api/docs',
      warning: '⚠️ Only use in VULNERABLE mode for educational purposes'
    };

    res.json(vulnerabilities);
  })
);

/**
 * @swagger
 * /api/v1/attacks/info/{category}:
 *   get:
 *     summary: Get detailed information about vulnerability category
 *     tags: [Attacks, Documentation]
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Vulnerability category details
 */
router.get('/info/:category',
  apiRateLimit,
  param('category').isIn(['sqli', 'xss', 'injection', 'access', 'auth', 'business']),
  enhancedValidate,
  attackController.getVulnerabilityInfo
);

// ============================================================================
// SQL INJECTION ENDPOINTS
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks/sqli/classic:
 *   get:
 *     summary: Classic SQL Injection (GET parameter)
 *     tags: [Attacks, SQL Injection]
 *     description: |
 *       Vulnerable endpoint for classic SQL injection testing.
 *       Try payloads like: `1' OR '1'='1`, `1' UNION SELECT...`
 *     parameters:
 *       - in: query
 *         name: id
 *         schema:
 *           type: string
 *         description: User ID (vulnerable to SQLi)
 *     responses:
 *       200:
 *         description: User data (potentially exploited)
 */
router.get('/sqli/classic',
  attackTestLimit,
  requireVulnerableMode,
  query('id').notEmpty().withMessage('ID parameter required'),
  attackController.classicSQLi
);

/**
 * @swagger
 * /api/v1/attacks/sqli/union:
 *   post:
 *     summary: Union-based SQL Injection
 *     tags: [Attacks, SQL Injection]
 *     description: |
 *       Test UNION-based SQL injection for data extraction.
 *       Try payloads like: `1' UNION SELECT username,password FROM users--`
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               search:
 *                 type: string
 *     responses:
 *       200:
 *         description: Search results (vulnerable)
 */
router.post('/sqli/union',
  attackTestLimit,
  requireVulnerableMode,
  body('search').notEmpty(),
  attackController.unionSQLi
);

/**
 * @swagger
 * /api/v1/attacks/sqli/blind:
 *   get:
 *     summary: Blind SQL Injection
 *     tags: [Attacks, SQL Injection]
 *     description: |
 *       Boolean-based blind SQL injection testing.
 *       Try: `1' AND 1=1--` vs `1' AND 1=2--`
 *     parameters:
 *       - in: query
 *         name: id
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Response differs based on condition
 */
router.get('/sqli/blind',
  attackTestLimit,
  requireVulnerableMode,
  query('id').notEmpty(),
  attackController.blindSQLi
);

/**
 * @swagger
 * /api/v1/attacks/sqli/time-based:
 *   get:
 *     summary: Time-based Blind SQL Injection
 *     tags: [Attacks, SQL Injection]
 *     description: |
 *       Time-based blind SQLi using SLEEP().
 *       Try: `1' AND SLEEP(5)--`
 *     parameters:
 *       - in: query
 *         name: id
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Response time varies based on payload
 */
router.get('/sqli/time-based',
  attackTestLimit,
  requireVulnerableMode,
  query('id').notEmpty(),
  attackController.timeBasedSQLi
);

/**
 * @swagger
 * /api/v1/attacks/sqli/second-order:
 *   post:
 *     summary: Second-Order SQL Injection
 *     tags: [Attacks, SQL Injection]
 *     description: |
 *       Test second-order SQLi where payload is stored and executed later.
 *     responses:
 *       200:
 *         description: Data stored (exploit triggers on retrieval)
 */
router.post('/sqli/second-order',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  body('data').notEmpty(),
  attackController.secondOrderSQLi
);

// ============================================================================
// CROSS-SITE SCRIPTING (XSS) ENDPOINTS
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks/xss/reflected:
 *   get:
 *     summary: Reflected XSS
 *     tags: [Attacks, XSS]
 *     description: |
 *       Test reflected XSS vulnerability.
 *       Try: `<script>alert('XSS')</script>`
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Search results with reflected input
 */
router.get('/xss/reflected',
  attackTestLimit,
  requireVulnerableMode,
  query('search').notEmpty(),
  attackController.reflectedXSS
);

/**
 * @swagger
 * /api/v1/attacks/xss/stored:
 *   post:
 *     summary: Stored XSS (Persistent)
 *     tags: [Attacks, XSS]
 *     description: |
 *       Test stored XSS by submitting malicious content.
 *       Payload persists in database and executes on retrieval.
 *     responses:
 *       201:
 *         description: Content stored (XSS payload persisted)
 */
router.post('/xss/stored',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  body('content').notEmpty(),
  body('title').optional(),
  attackController.storedXSS
);

/**
 * @swagger
 * /api/v1/attacks/xss/stored:
 *   get:
 *     summary: Retrieve stored XSS content
 *     tags: [Attacks, XSS]
 *     responses:
 *       200:
 *         description: Stored content (may contain XSS)
 */
router.get('/xss/stored',
  attackTestLimit,
  requireVulnerableMode,
  attackController.getStoredXSS
);

/**
 * @swagger
 * /api/v1/attacks/xss/dom:
 *   get:
 *     summary: DOM-based XSS
 *     tags: [Attacks, XSS]
 *     description: |
 *       Test DOM-based XSS (client-side vulnerability).
 *     responses:
 *       200:
 *         description: HTML page with DOM XSS vulnerability
 */
router.get('/xss/dom',
  attackTestLimit,
  requireVulnerableMode,
  attackController.domXSS
);

// ============================================================================
// INJECTION ATTACKS
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks/injection/command:
 *   post:
 *     summary: Command Injection
 *     tags: [Attacks, Injection]
 *     description: |
 *       Test OS command injection.
 *       Try: `; ls -la`, `| whoami`, `&& cat /etc/passwd`
 *     responses:
 *       200:
 *         description: Command output
 */
router.post('/injection/command',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  requireAdmin,
  body('command').notEmpty(),
  attackController.commandInjection
);

/**
 * @swagger
 * /api/v1/attacks/injection/ldap:
 *   post:
 *     summary: LDAP Injection
 *     tags: [Attacks, Injection]
 *     description: |
 *       Test LDAP injection vulnerability.
 *       Try: `*)(uid=*))(|(uid=*`, `admin)(&(password=*))`
 *     responses:
 *       200:
 *         description: LDAP query results
 */
router.post('/injection/ldap',
  attackTestLimit,
  requireVulnerableMode,
  body('username').notEmpty(),
  body('password').notEmpty(),
  attackController.ldapInjection
);

/**
 * @swagger
 * /api/v1/attacks/injection/xml:
 *   post:
 *     summary: XML External Entity (XXE) Injection
 *     tags: [Attacks, Injection]
 *     description: |
 *       Test XXE vulnerability.
 *       Try submitting XML with external entity references.
 *     responses:
 *       200:
 *         description: XML parsing results
 */
router.post('/injection/xml',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  body('xml').notEmpty(),
  attackController.xmlInjection
);

/**
 * @swagger
 * /api/v1/attacks/injection/template:
 *   post:
 *     summary: Server-Side Template Injection (SSTI)
 *     tags: [Attacks, Injection]
 *     description: |
 *       Test template injection vulnerability.
 *       Try: `{{7*7}}`, `{{config}}`, `{{self.__init__.__globals__}}`
 *     responses:
 *       200:
 *         description: Template rendered output
 */
router.post('/injection/template',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  body('template').notEmpty(),
  attackController.templateInjection
);

// ============================================================================
// ACCESS CONTROL VULNERABILITIES
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks/access/idor:
 *   get:
 *     summary: Insecure Direct Object Reference (IDOR)
 *     tags: [Attacks, Access Control]
 *     description: |
 *       Test IDOR vulnerability by accessing other users' data.
 *       Try changing user ID to access unauthorized data.
 *     parameters:
 *       - in: query
 *         name: userId
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User data (no authorization check)
 */
router.get('/access/idor',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  query('userId').isInt().toInt(),
  attackController.idorVulnerability
);

/**
 * @swagger
 * /api/v1/attacks/access/path-traversal:
 *   get:
 *     summary: Path Traversal / Directory Traversal
 *     tags: [Attacks, Access Control]
 *     description: |
 *       Test path traversal vulnerability.
 *       Try: `../../../etc/passwd`, `..\\..\\..\\windows\\system32\\config\\sam`
 *     parameters:
 *       - in: query
 *         name: file
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: File contents
 */
router.get('/access/path-traversal',
  attackTestLimit,
  requireVulnerableMode,
  query('file').notEmpty(),
  attackController.pathTraversal
);

/**
 * @swagger
 * /api/v1/attacks/access/privilege-escalation:
 *   post:
 *     summary: Privilege Escalation
 *     tags: [Attacks, Access Control]
 *     description: |
 *       Test privilege escalation by modifying user role.
 *     responses:
 *       200:
 *         description: User role updated (vulnerable)
 */
router.post('/access/privilege-escalation',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  body('userId').isInt().toInt(),
  body('newRole').notEmpty(),
  attackController.privilegeEscalation
);

/**
 * @swagger
 * /api/v1/attacks/access/forced-browsing:
 *   get:
 *     summary: Forced Browsing / Predictable Resource Location
 *     tags: [Attacks, Access Control]
 *     description: |
 *       Access admin pages without proper authorization.
 *     responses:
 *       200:
 *         description: Admin panel accessible
 */
router.get('/access/forced-browsing',
  attackTestLimit,
  requireVulnerableMode,
  attackController.forcedBrowsing
);

// ============================================================================
// AUTHENTICATION/AUTHORIZATION VULNERABILITIES
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks/auth/brute-force:
 *   post:
 *     summary: Brute Force Attack (No Rate Limiting)
 *     tags: [Attacks, Authentication]
 *     description: |
 *       Test brute force vulnerability (rate limiting disabled).
 *     responses:
 *       200:
 *         description: Login attempt result
 */
router.post('/auth/brute-force',
  // Intentionally NO rate limiting in vulnerable mode
  requireVulnerableMode,
  body('username').notEmpty(),
  body('password').notEmpty(),
  attackController.bruteForceVulnerable
);

/**
 * @swagger
 * /api/v1/attacks/auth/session-fixation:
 *   get:
 *     summary: Session Fixation
 *     tags: [Attacks, Authentication]
 *     description: |
 *       Test session fixation vulnerability.
 *     responses:
 *       200:
 *         description: Session created (vulnerable to fixation)
 */
router.get('/auth/session-fixation',
  attackTestLimit,
  requireVulnerableMode,
  query('sessionId').optional(),
  attackController.sessionFixation
);

/**
 * @swagger
 * /api/v1/attacks/auth/jwt-bypass:
 *   post:
 *     summary: JWT Security Bypass
 *     tags: [Attacks, Authentication]
 *     description: |
 *       Test JWT vulnerabilities (weak secret, no verification, etc.)
 *     responses:
 *       200:
 *         description: JWT validation result
 */
router.post('/auth/jwt-bypass',
  attackTestLimit,
  requireVulnerableMode,
  body('token').notEmpty(),
  attackController.jwtBypass
);

/**
 * @swagger
 * /api/v1/attacks/auth/oauth:
 *   get:
 *     summary: OAuth Implementation Flaws
 *     tags: [Attacks, Authentication]
 *     description: |
 *       Test OAuth security issues (open redirect, CSRF, etc.)
 *     responses:
 *       200:
 *         description: OAuth flow initiated
 */
router.get('/auth/oauth',
  attackTestLimit,
  requireVulnerableMode,
  query('redirect_uri').optional(),
  attackController.oauthVulnerability
);

// ============================================================================
// BUSINESS LOGIC VULNERABILITIES
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks/business/race-condition:
 *   post:
 *     summary: Race Condition Vulnerability
 *     tags: [Attacks, Business Logic]
 *     description: |
 *       Test race condition in balance/inventory management.
 *       Send multiple concurrent requests to exploit.
 *     responses:
 *       200:
 *         description: Operation result (vulnerable to race condition)
 */
router.post('/business/race-condition',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  body('amount').isFloat().toFloat(),
  attackController.raceCondition
);

/**
 * @swagger
 * /api/v1/attacks/business/mass-assignment:
 *   post:
 *     summary: Mass Assignment Vulnerability
 *     tags: [Attacks, Business Logic]
 *     description: |
 *       Test mass assignment by sending extra fields.
 *       Try: `{"username": "test", "role": "admin", "isVerified": true}`
 *     responses:
 *       200:
 *         description: User created (with extra fields assigned)
 */
router.post('/business/mass-assignment',
  attackTestLimit,
  requireVulnerableMode,
  attackController.massAssignment
);

/**
 * @swagger
 * /api/v1/attacks/business/price-tampering:
 *   post:
 *     summary: Price Tampering Vulnerability
 *     tags: [Attacks, Business Logic]
 *     description: |
 *       Test price manipulation in checkout process.
 *       Try modifying price in request body.
 *     responses:
 *       200:
 *         description: Order created with tampered price
 */
router.post('/business/price-tampering',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  body('productId').isInt().toInt(),
  body('quantity').isInt().toInt(),
  body('price').isFloat().toFloat(),
  attackController.priceTampering
);

/**
 * @swagger
 * /api/v1/attacks/business/logic-flaws:
 *   post:
 *     summary: Business Logic Flaws
 *     tags: [Attacks, Business Logic]
 *     description: |
 *       Test various business logic vulnerabilities.
 *     responses:
 *       200:
 *         description: Operation result
 */
router.post('/business/logic-flaws',
  attackTestLimit,
  requireVulnerableMode,
  authenticate,
  attackController.logicFlaws
);

// ============================================================================
// ATTACK LOGS & STATISTICS
// ============================================================================

/**
 * @swagger
 * /api/v1/attacks/logs:
 *   get:
 *     summary: Get attack logs
 *     tags: [Attacks, Logging]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Attack logs
 */
router.get('/logs',
  apiRateLimit,
  authenticate,
  requireModerator,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('attackType').optional().trim(),
  query('severity').optional().isIn(['low', 'medium', 'high', 'critical']),
  enhancedValidate,
  attackController.getAttackLogs
);

/**
 * @swagger
 * /api/v1/attacks/stats:
 *   get:
 *     summary: Get attack statistics
 *     tags: [Attacks, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Attack statistics
 */
router.get('/stats',
  apiRateLimit,
  authenticate,
  requireModerator,
  query('period').optional().isIn(['hour', 'day', 'week', 'month']),
  enhancedValidate,
  attackController.getAttackStats
);

/**
 * @swagger
 * /api/v1/attacks/clear-logs:
 *   delete:
 *     summary: Clear attack logs (admin only)
 *     tags: [Attacks, Logging]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logs cleared
 */
router.delete('/clear-logs',
  apiRateLimit,
  authenticate,
  requireAdmin,
  body('confirmation').equals('CLEAR_LOGS').withMessage('Confirmation required'),
  enhancedValidate,
  attackController.clearAttackLogs
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((error, req, res, next) => {
  logger.error('Attack route error', {
    error: error.message,
    path: req.path,
    method: req.method,
    userId: req.user?.id,
    payload: req.body
  });

  res.status(error.status || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: error.code || ERROR_CODES.INTERNAL_ERROR,
    message: Config.app.env === 'development' ? error.message : 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// EXPORTS
// ============================================================================

logger.info('✅ Attack routes loaded (MILITARY-GRADE - EDUCATIONAL ONLY)');
logger.warn('⚠️  Attack testing endpoints available in VULNERABLE mode only');

export default router;
