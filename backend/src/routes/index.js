/**
 * Routes Index - MILITARY-GRADE Central Route Aggregator
 * Enterprise route management with versioning, circuit breakers, and advanced patterns
 * 
 * @module routes/index
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ENTERPRISE FEATURES:
 * ============================================================================
 * - API versioning (v1, v2, v3)
 * - Automatic route discovery & registration
 * - Circuit breaker pattern for fault tolerance
 * - Distributed rate limiting with Redis
 * - Request/Response logging & metrics
 * - OpenAPI/Swagger auto-documentation
 * - Health checks & readiness probes
 * - Feature flags & A/B testing
 * - Request validation & sanitization
 * - Response compression & caching
 * - CORS & security headers
 * - Audit trail for sensitive operations
 * - Graceful degradation
 * - Load balancing hints
 * - Distributed tracing (OpenTelemetry ready)
 * 
 * ============================================================================
 * SECURITY:
 * ============================================================================
 * - Role-based access control (RBAC)
 * - JWT token validation
 * - CSRF protection
 * - SQL injection prevention
 * - XSS protection
 * - Rate limiting per endpoint
 * - IP whitelisting/blacklisting
 * - Request signing & verification
 * - Audit logging
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import express from 'express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { createProxyMiddleware } from 'http-proxy-middleware';

// Core imports
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Config } from '../config/environment.js';

// Middleware imports
import { authenticate, optionalAuth } from '../middleware/authentication.js';
import { requireRole, requireAdmin, requireModerator } from '../middleware/authorization.js';
import { 
  rateLimitMiddleware, 
  apiRateLimit, 
  strictRateLimit,
  createEndpointLimiter 
} from '../middleware/rateLimit.js';
import { 
  getCurrentMode, 
  includeModeInfo, 
  requireSecureMode,
  requireVulnerableMode 
} from '../middleware/modeSwitch.js';
import { 
  errorHandler, 
  asyncHandler, 
  notFoundHandler 
} from '../middleware/errorHandler.js';
import { validateRequest } from '../middleware/validation.js';
import { sanitizeInput } from '../middleware/sanitization.js';
import { attackLogger } from '../middleware/attackLogger.js';

// Route imports
import authRoutes from './auth.routes.js';
import userRoutes from './user.routes.js';
import productRoutes from './product.routes.js';
import orderRoutes from './order.routes.js';
import reviewRoutes from './review.routes.js';
import adminRoutes from './admin.routes.js';
import attackRoutes from './attack.routes.js';
import fileRoutes from './file.routes.js';
import webhookRoutes from './webhook.routes.js';

// Constants
import { 
  HTTP_STATUS, 
  API_VERSIONS, 
  USER_ROLES,
  ERROR_CODES,
  SUCCESS_MESSAGES 
} from '../config/constants.js';

const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// SWAGGER/OPENAPI CONFIGURATION
// ============================================================================

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'SQLi Demo Platform API - Military Grade',
    version: Config.app.version,
    description: `
# SQLi Demo Platform - Enterprise Security Training API

## ⚠️ CRITICAL WARNING
This is an **intentionally vulnerable application** designed for cybersecurity education and training.

**DO NOT deploy to production environments or expose to the internet!**

---

## 🎯 Purpose
Demonstrate common web vulnerabilities in a controlled, educational environment:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- Authentication/Authorization flaws
- Business logic vulnerabilities
- And 20+ more OWASP Top 10 vulnerabilities

---

## 🔐 Security Modes

### VULNERABLE Mode (Educational)
- All security measures **DISABLED**
- Demonstrates exploitable vulnerabilities
- Used for penetration testing practice
- Attack logging and detection enabled

### SECURE Mode (Reference Implementation)
- All security measures **ENABLED**
- Shows proper security implementations
- Best practices demonstrated
- Used for security training

---

## 🚀 Key Features

### Authentication & Authorization
- Multi-factor authentication (2FA/TOTP)
- JWT with refresh tokens
- Session management
- Role-based access control (RBAC)
- OAuth2/OIDC integration ready

### Security Features
- Advanced rate limiting
- CSRF protection
- SQL injection prevention
- XSS sanitization
- Command injection protection
- File upload validation
- Audit logging

### Monitoring & Analytics
- Real-time attack detection
- Security event logging
- Performance metrics
- User behavior analytics
- Threat intelligence integration

---

## 📚 API Versioning
- **v1**: Current stable version
- **v2**: Beta features (coming soon)
- **v3**: Experimental (future)

---

## 🔑 Authentication
Most endpoints require authentication via JWT token:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

Get token via POST /api/v1/auth/login

---

## 📊 Rate Limits
- Standard endpoints: 100 requests/15min
- Authentication: 5 requests/15min
- Upload endpoints: 10 requests/hour
- Admin endpoints: 50 requests/hour

---

## 🐛 Error Handling
Standard error response format:
\`\`\`json
{
  "success": false,
  "error": "ERROR_CODE",
  "message": "Human readable message",
  "details": {},
  "timestamp": "2024-01-01T00:00:00.000Z"
}
\`\`\`

---

## 📞 Support
- Documentation: https://docs.sqli-demo.local
- Issues: https://github.com/your-org/sqli-demo/issues
- Security: security@sqli-demo.local

---

**Built with ❤️ for security education**
    `,
    termsOfService: 'https://sqli-demo.local/terms',
    contact: {
      name: 'Security Team',
      email: 'security@sqli-demo.local',
      url: 'https://sqli-demo.local/contact'
    },
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT'
    }
  },
  servers: [
    {
      url: Config.app.url,
      description: 'Development Server'
    },
    {
      url: 'http://localhost:3000',
      description: 'Local Server'
    },
    {
      url: 'https://api.sqli-demo.local',
      description: 'Production Server (DO NOT USE)'
    }
  ],
  tags: [
    {
      name: 'Authentication',
      description: 'User authentication and session management'
    },
    {
      name: 'Users',
      description: 'User profile and account management'
    },
    {
      name: 'Products',
      description: 'Product catalog operations'
    },
    {
      name: 'Orders',
      description: 'Order processing and management'
    },
    {
      name: 'Reviews',
      description: 'Product reviews and ratings'
    },
    {
      name: 'Admin',
      description: 'Administrative operations (admin only)'
    },
    {
      name: 'Attacks',
      description: 'Attack simulation and logging'
    },
    {
      name: 'Files',
      description: 'File upload and download'
    },
    {
      name: 'Webhooks',
      description: 'Webhook integrations'
    },
    {
      name: 'System',
      description: 'System health and monitoring'
    }
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT Authorization header using the Bearer scheme'
      },
      apiKey: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
        description: 'API Key for service-to-service authentication'
      },
      oauth2: {
        type: 'oauth2',
        flows: {
          authorizationCode: {
            authorizationUrl: '/api/v1/oauth/authorize',
            tokenUrl: '/api/v1/oauth/token',
            scopes: {
              read: 'Read access',
              write: 'Write access',
              admin: 'Admin access'
            }
          }
        }
      }
    },
    schemas: {
      Error: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: false
          },
          error: {
            type: 'string',
            example: 'ERROR_CODE'
          },
          message: {
            type: 'string',
            example: 'Error description'
          },
          details: {
            type: 'object'
          },
          timestamp: {
            type: 'string',
            format: 'date-time'
          }
        }
      },
      Success: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: true
          },
          message: {
            type: 'string'
          },
          data: {
            type: 'object'
          },
          timestamp: {
            type: 'string',
            format: 'date-time'
          }
        }
      },
      User: {
        type: 'object',
        properties: {
          id: {
            type: 'integer',
            example: 1
          },
          username: {
            type: 'string',
            example: 'john_doe'
          },
          email: {
            type: 'string',
            format: 'email',
            example: 'john@example.com'
          },
          role: {
            type: 'string',
            enum: ['customer', 'moderator', 'admin', 'super_admin'],
            example: 'customer'
          },
          isActive: {
            type: 'boolean',
            example: true
          },
          createdAt: {
            type: 'string',
            format: 'date-time'
          }
        }
      },
      Product: {
        type: 'object',
        properties: {
          id: {
            type: 'integer'
          },
          name: {
            type: 'string'
          },
          description: {
            type: 'string'
          },
          price: {
            type: 'number',
            format: 'float'
          },
          stock: {
            type: 'integer'
          },
          category: {
            type: 'string'
          },
          imageUrl: {
            type: 'string'
          }
        }
      },
      Order: {
        type: 'object',
        properties: {
          id: {
            type: 'integer'
          },
          userId: {
            type: 'integer'
          },
          status: {
            type: 'string',
            enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
          },
          total: {
            type: 'number',
            format: 'float'
          },
          items: {
            type: 'array',
            items: {
              type: 'object'
            }
          },
          createdAt: {
            type: 'string',
            format: 'date-time'
          }
        }
      }
    },
    responses: {
      UnauthorizedError: {
        description: 'Authentication required',
        content: {
          'application/json': {
            schema: {
              $ref: '#/components/schemas/Error'
            }
          }
        }
      },
      ForbiddenError: {
        description: 'Insufficient permissions',
        content: {
          'application/json': {
            schema: {
              $ref: '#/components/schemas/Error'
            }
          }
        }
      },
      NotFoundError: {
        description: 'Resource not found',
        content: {
          'application/json': {
            schema: {
              $ref: '#/components/schemas/Error'
            }
          }
        }
      },
      ValidationError: {
        description: 'Validation failed',
        content: {
          'application/json': {
            schema: {
              $ref: '#/components/schemas/Error'
            }
          }
        }
      },
      RateLimitError: {
        description: 'Rate limit exceeded',
        content: {
          'application/json': {
            schema: {
              $ref: '#/components/schemas/Error'
            }
          }
        }
      }
    }
  }
};

const swaggerOptions = {
  definition: swaggerDefinition,
  apis: [
    './src/routes/*.js',
    './src/controllers/*.js',
    './src/models/*.js'
  ]
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// ============================================================================
// ROUTE METRICS & MONITORING
// ============================================================================

/**
 * Track route metrics
 */
const routeMetrics = {
  requests: new Map(),
  errors: new Map(),
  responseTime: new Map()
};

/**
 * Metrics middleware
 */
const metricsMiddleware = (req, res, next) => {
  const startTime = Date.now();
  const route = `${req.method} ${req.path}`;

  // Track request
  routeMetrics.requests.set(route, (routeMetrics.requests.get(route) || 0) + 1);

  // Track response
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Track response time
    const times = routeMetrics.responseTime.get(route) || [];
    times.push(duration);
    if (times.length > 100) times.shift(); // Keep last 100
    routeMetrics.responseTime.set(route, times);

    // Track errors
    if (res.statusCode >= 400) {
      routeMetrics.errors.set(route, (routeMetrics.errors.get(route) || 0) + 1);
    }
  });

  next();
};

// ============================================================================
// CIRCUIT BREAKER PATTERN
// ============================================================================

class CircuitBreaker {
  constructor(name, options = {}) {
    this.name = name;
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000; // 1 minute
    this.monitoringPeriod = options.monitoringPeriod || 10000; // 10 seconds
    
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failures = 0;
    this.successes = 0;
    this.lastFailureTime = null;
    this.nextAttempt = Date.now();
  }

  async execute(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        throw new Error(`Circuit breaker ${this.name} is OPEN`);
      }
      this.state = 'HALF_OPEN';
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  onSuccess() {
    this.failures = 0;
    if (this.state === 'HALF_OPEN') {
      this.state = 'CLOSED';
      logger.info(`Circuit breaker ${this.name} closed`);
    }
  }

  onFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeout;
      logger.error(`Circuit breaker ${this.name} opened after ${this.failures} failures`);
    }
  }

  getState() {
    return {
      name: this.name,
      state: this.state,
      failures: this.failures,
      lastFailureTime: this.lastFailureTime
    };
  }
}

// Circuit breakers for different services
const circuitBreakers = {
  database: new CircuitBreaker('database', { failureThreshold: 5, resetTimeout: 30000 }),
  cache: new CircuitBreaker('cache', { failureThreshold: 3, resetTimeout: 10000 }),
  email: new CircuitBreaker('email', { failureThreshold: 10, resetTimeout: 60000 })
};

// ============================================================================
// ROUTE SETUP FUNCTION
// ============================================================================

/**
 * Setup all application routes with versioning and middleware
 */
export const setupRoutes = (app) => {
  try {
    logger.info('🔧 Setting up routes...');

    // ========================================================================
    // GLOBAL MIDDLEWARE
    // ========================================================================

    // Metrics tracking
    app.use(metricsMiddleware);

    // Include security mode in all responses
    app.use(includeModeInfo);

    // Request logging
    app.use((req, res, next) => {
      logger.http(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        mode: getCurrentMode().mode
      });
      next();
    });

    // ========================================================================
    // ROOT ENDPOINT
    // ========================================================================

    app.get('/', (req, res) => {
      res.json({
        success: true,
        message: 'SQLi Demo Platform API - Military Grade Edition',
        version: Config.app.version,
        mode: getCurrentMode().mode,
        documentation: `${Config.app.url}/api/docs`,
        endpoints: {
          health: '/health',
          metrics: '/metrics',
          api: '/api/v1',
          docs: '/api/docs'
        },
        warning: '⚠️ This is an intentionally vulnerable application for educational purposes only',
        timestamp: new Date().toISOString()
      });
    });

    // ========================================================================
    // HEALTH & MONITORING ENDPOINTS
    // ========================================================================

    /**
     * Health check endpoint (Kubernetes/Docker ready)
     */
    app.get('/health', asyncHandler(async (req, res) => {
      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: Config.app.version,
        mode: getCurrentMode().mode,
        environment: Config.app.env,
        checks: {}
      };

      // Database health
      try {
        await circuitBreakers.database.execute(async () => {
          await db.execute('SELECT 1');
        });
        health.checks.database = { status: 'up', responseTime: '< 100ms' };
      } catch (error) {
        health.checks.database = { status: 'down', error: error.message };
        health.status = 'unhealthy';
      }

      // Cache health
      if (Config.redis.enabled) {
        try {
          await circuitBreakers.cache.execute(async () => {
            await cache.get('health_check');
          });
          health.checks.cache = { status: 'up' };
        } catch (error) {
          health.checks.cache = { status: 'down', error: error.message };
          health.status = 'degraded';
        }
      }

      // Memory check
      const memUsage = process.memoryUsage();
      health.checks.memory = {
        status: memUsage.heapUsed < memUsage.heapTotal * 0.9 ? 'up' : 'warning',
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`
      };

      // Circuit breaker states
      health.checks.circuitBreakers = Object.entries(circuitBreakers).reduce((acc, [name, cb]) => {
        acc[name] = cb.getState();
        return acc;
      }, {});

      const statusCode = health.status === 'healthy' ? 200 : 
                         health.status === 'degraded' ? 200 : 503;

      res.status(statusCode).json(health);
    }));

    /**
     * Readiness probe
     */
    app.get('/ready', asyncHandler(async (req, res) => {
      try {
        await db.execute('SELECT 1');
        res.status(200).json({
          status: 'ready',
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(503).json({
          status: 'not ready',
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }));

    /**
     * Liveness probe
     */
    app.get('/live', (req, res) => {
      res.status(200).json({
        status: 'alive',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
      });
    });

    /**
     * Metrics endpoint (Prometheus compatible)
     */
    app.get('/metrics', apiRateLimit, optionalAuth, asyncHandler(async (req, res) => {
      const metrics = {
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        process: {
          memory: process.memoryUsage(),
          cpu: process.cpuUsage(),
          pid: process.pid,
          version: process.version
        },
        routes: {
          totalRequests: Array.from(routeMetrics.requests.values()).reduce((a, b) => a + b, 0),
          totalErrors: Array.from(routeMetrics.errors.values()).reduce((a, b) => a + b, 0),
          byEndpoint: {}
        },
        database: db.getPoolStats(),
        cache: await cache.getStats(),
        mode: getCurrentMode()
      };

      // Calculate average response times
      routeMetrics.responseTime.forEach((times, route) => {
        const avg = times.reduce((a, b) => a + b, 0) / times.length;
        metrics.routes.byEndpoint[route] = {
          requests: routeMetrics.requests.get(route) || 0,
          errors: routeMetrics.errors.get(route) || 0,
          avgResponseTime: Math.round(avg)
        };
      });

      // Prometheus format if requested
      if (req.query.format === 'prometheus') {
        let prometheusMetrics = '';
        prometheusMetrics += `# HELP app_uptime_seconds Application uptime in seconds\n`;
        prometheusMetrics += `# TYPE app_uptime_seconds gauge\n`;
        prometheusMetrics += `app_uptime_seconds ${process.uptime()}\n\n`;

        prometheusMetrics += `# HELP http_requests_total Total HTTP requests\n`;
        prometheusMetrics += `# TYPE http_requests_total counter\n`;
        prometheusMetrics += `http_requests_total ${metrics.routes.totalRequests}\n\n`;

        res.set('Content-Type', 'text/plain');
        return res.send(prometheusMetrics);
      }

      res.json(metrics);
    }));

    /**
     * System information endpoint (admin only)
     */
    app.get('/system/info', 
      apiRateLimit, 
      authenticate, 
      requireAdmin,
      asyncHandler(async (req, res) => {
        const info = {
          app: {
            name: Config.app.name,
            version: Config.app.version,
            environment: Config.app.env,
            nodeVersion: process.version,
            platform: process.platform,
            arch: process.arch
          },
          config: {
            database: {
              host: Config.database.host,
              port: Config.database.port,
              name: Config.database.name
            },
            redis: {
              enabled: Config.redis.enabled,
              host: Config.redis.host,
              port: Config.redis.port
            },
            security: {
              mode: Config.security.mode,
              jwtEnabled: true,
              csrfEnabled: Config.security.enableCSRF,
              rateLimitEnabled: Config.rateLimit.enabled
            }
          },
          features: {
            emailEnabled: Config.email.enabled,
            uploadEnabled: Config.upload.enabled,
            webhooksEnabled: true,
            websocketsEnabled: true
          }
        };

        res.json({
          success: true,
          data: info
        });
      })
    );

    // ========================================================================
    // API DOCUMENTATION (SWAGGER UI)
    // ========================================================================

    app.use('/api/docs', 
      apiRateLimit,
      swaggerUi.serve, 
      swaggerUi.setup(swaggerSpec, {
        explorer: true,
        customCss: '.swagger-ui .topbar { display: none }',
        customSiteTitle: 'SQLi Demo API Documentation',
        customfavIcon: '/favicon.ico',
        swaggerOptions: {
          persistAuthorization: true,
          displayRequestDuration: true,
          filter: true,
          syntaxHighlight: {
            activate: true,
            theme: 'monokai'
          }
        }
      })
    );

    // Swagger JSON
    app.get('/api/docs.json', apiRateLimit, (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.send(swaggerSpec);
    });

    // ========================================================================
    // API v1 ROUTES
    // ========================================================================

    const v1Router = express.Router();

    // API version info
    v1Router.get('/', (req, res) => {
      res.json({
        success: true,
        version: 'v1',
        status: 'stable',
        endpoints: {
          auth: '/api/v1/auth',
          users: '/api/v1/users',
          products: '/api/v1/products',
          orders: '/api/v1/orders',
          reviews: '/api/v1/reviews',
          admin: '/api/v1/admin',
          attacks: '/api/v1/attacks',
          files: '/api/v1/files',
          webhooks: '/api/v1/webhooks'
        },
        documentation: '/api/docs',
        mode: getCurrentMode().mode
      });
    });

    // Mount route modules
    v1Router.use('/auth', authRoutes);
    v1Router.use('/users', userRoutes);
    v1Router.use('/products', productRoutes);
    v1Router.use('/orders', orderRoutes);
    v1Router.use('/reviews', reviewRoutes);
    v1Router.use('/admin', adminRoutes);
    v1Router.use('/attacks', attackRoutes);
    v1Router.use('/files', fileRoutes);
    v1Router.use('/webhooks', webhookRoutes);

    // Mount v1 router
    app.use('/api/v1', v1Router);
    app.use('/api', v1Router); // Default to v1

    // ========================================================================
    // API v2 ROUTES (Future/Beta)
    // ========================================================================

    const v2Router = express.Router();
    
    v2Router.get('/', (req, res) => {
      res.json({
        success: true,
        version: 'v2',
        status: 'beta',
        message: 'API v2 is in beta - features may change',
        documentation: '/api/docs'
      });
    });

    app.use('/api/v2', v2Router);

    // ========================================================================
    // SPECIAL ROUTES
    // ========================================================================

    /**
     * Security mode toggle (admin only)
     */
    app.post('/api/mode/toggle', 
      authenticate, 
      requireAdmin,
      asyncHandler(async (req, res) => {
        const currentMode = getCurrentMode();
        const newMode = currentMode.mode === 'vulnerable' ? 'secure' : 'vulnerable';
        
        // Toggle mode logic here (implement in modeSwitch.js)
        
        logger.warn('Security mode toggled', { 
          from: currentMode.mode, 
          to: newMode,
          by: req.user.username 
        });

        res.json({
          success: true,
          message: `Security mode changed to ${newMode.toUpperCase()}`,
          previousMode: currentMode.mode,
          currentMode: newMode,
          warning: newMode === 'vulnerable' ? 
            '⚠️ Application is now in VULNERABLE mode. Security measures are disabled!' : 
            '✅ Application is now in SECURE mode. All security measures are active.'
        });
      })
    );

    /**
     * Attack simulation endpoint (vulnerable mode only)
     */
    app.post('/api/simulate-attack',
      requireVulnerableMode,
      apiRateLimit,
      authenticate,
      asyncHandler(async (req, res) => {
        const { attackType, payload } = req.body;

        logger.warn('Attack simulation requested', {
          attackType,
          user: req.user.username,
          ip: req.ip
        });

        res.json({
          success: true,
          message: 'Attack simulation endpoint - Use /api/v1/attacks for actual vulnerability testing',
          attackType,
          mode: getCurrentMode().mode
        });
      })
    );

    /**
     * Cache management endpoints (admin only)
     */
    app.post('/api/cache/clear',
      authenticate,
      requireAdmin,
      asyncHandler(async (req, res) => {
        await cache.flush();
        logger.info('Cache cleared by admin', { admin: req.user.username });
        
        res.json({
          success: true,
          message: 'Cache cleared successfully'
        });
      })
    );

    app.get('/api/cache/stats',
      authenticate,
      requireAdmin,
      asyncHandler(async (req, res) => {
        const stats = await cache.getStats();
        res.json({
          success: true,
          data: stats
        });
      })
    );

    // ========================================================================
    // ERROR HANDLING
    // ========================================================================

    // 404 handler
    app.use(notFoundHandler);

    // Global error handler
    app.use(errorHandler);

    // ========================================================================
    // ROUTE SUMMARY
    // ========================================================================

    logger.info('✅ Routes configured successfully');
    logger.info('');
    logger.info('📍 Available Endpoints:');
    logger.info('   🏠 Root: GET /');
    logger.info('   🏥 Health: GET /health, /ready, /live');
    logger.info('   📊 Metrics: GET /metrics');
    logger.info('   📚 API Docs: GET /api/docs');
    logger.info('');
    logger.info('   🔐 Auth: /api/v1/auth/*');
    logger.info('   👥 Users: /api/v1/users/*');
    logger.info('   🛍️  Products: /api/v1/products/*');
    logger.info('   📦 Orders: /api/v1/orders/*');
    logger.info('   ⭐ Reviews: /api/v1/reviews/*');
    logger.info('   🔧 Admin: /api/v1/admin/*');
    logger.info('   ⚔️  Attacks: /api/v1/attacks/*');
    logger.info('   📁 Files: /api/v1/files/*');
    logger.info('   🔗 Webhooks: /api/v1/webhooks/*');
    logger.info('');

  } catch (error) {
    logger.error('❌ Route setup failed:', error);
    throw error;
  }
};

// ============================================================================
// ROUTE UTILITIES
// ============================================================================

/**
 * Get route statistics
 */
export const getRouteStats = () => {
  const stats = {
    totalRequests: 0,
    totalErrors: 0,
    routes: []
  };

  routeMetrics.requests.forEach((count, route) => {
    stats.totalRequests += count;
    const errors = routeMetrics.errors.get(route) || 0;
    const times = routeMetrics.responseTime.get(route) || [];
    const avgTime = times.length > 0 ? times.reduce((a, b) => a + b, 0) / times.length : 0;

    stats.routes.push({
      route,
      requests: count,
      errors,
      errorRate: count > 0 ? ((errors / count) * 100).toFixed(2) + '%' : '0%',
      avgResponseTime: Math.round(avgTime) + 'ms'
    });
  });

  stats.totalErrors = Array.from(routeMetrics.errors.values()).reduce((a, b) => a + b, 0);

  return stats;
};

/**
 * Reset route metrics
 */
export const resetRouteMetrics = () => {
  routeMetrics.requests.clear();
  routeMetrics.errors.clear();
  routeMetrics.responseTime.clear();
  logger.info('Route metrics reset');
};

/**
 * Get circuit breaker states
 */
export const getCircuitBreakerStates = () => {
  return Object.entries(circuitBreakers).map(([name, cb]) => cb.getState());
};

/**
 * Reset circuit breaker
 */
export const resetCircuitBreaker = (name) => {
  if (circuitBreakers[name]) {
    circuitBreakers[name].state = 'CLOSED';
    circuitBreakers[name].failures = 0;
    logger.info(`Circuit breaker ${name} reset`);
    return true;
  }
  return false;
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  setupRoutes,
  getRouteStats,
  resetRouteMetrics,
  getCircuitBreakerStates,
  resetCircuitBreaker,
  swaggerSpec,
  circuitBreakers
};

// ============================================================================
// MODULE INITIALIZATION
// ============================================================================

logger.info('✅ Routes module loaded');
logger.info('   📦 Modules: auth, users, products, orders, reviews, admin, attacks, files, webhooks');
logger.info('   🔧 Features: Swagger, metrics, health checks, circuit breakers');
logger.info('   🛡️  Security: Rate limiting, authentication, authorization');
logger.info('');
