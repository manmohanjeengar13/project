/**
 * Router Core Module
 * Advanced routing management with automatic route registration,
 * versioning, and middleware application
 */

import express from 'express';
import { readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Logger } from './Logger.js';
import { Config } from '../config/environment.js';
import { API_VERSIONS } from '../config/constants.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const logger = Logger.getInstance();

export class Router {
  constructor() {
    this.routes = new Map();
    this.middleware = [];
    this.versions = new Map();
    this.routeCount = 0;
  }

  /**
   * Register a route module
   */
  registerRoute(path, router, options = {}) {
    const {
      version = API_VERSIONS.CURRENT,
      middleware = [],
      description = '',
      deprecated = false
    } = options;

    // Create version prefix
    const versionPrefix = version ? `/api/${version}` : '/api';
    const fullPath = `${versionPrefix}${path}`;

    // Apply route-specific middleware
    const routerWithMiddleware = express.Router();
    if (middleware.length > 0) {
      routerWithMiddleware.use(middleware);
    }
    routerWithMiddleware.use(router);

    // Store route info
    this.routes.set(fullPath, {
      path: fullPath,
      version,
      description,
      deprecated,
      middleware: middleware.map(m => m.name || 'anonymous'),
      registeredAt: new Date()
    });

    this.routeCount++;

    if (deprecated) {
      logger.warn(`⚠️  Deprecated route registered: ${fullPath}`);
    } else {
      logger.debug(`✓ Route registered: ${fullPath}`);
    }

    return {
      path: fullPath,
      router: routerWithMiddleware
    };
  }

  /**
   * Auto-discover and register routes from directory
   */
  async autoRegisterRoutes(routesDir) {
    try {
      const files = readdirSync(routesDir);
      const routeFiles = files.filter(f => 
        f.endsWith('.routes.js') || 
        (f.endsWith('.js') && !f.includes('index'))
      );

      logger.info(`📁 Auto-registering ${routeFiles.length} route files...`);

      for (const file of routeFiles) {
        try {
          const routePath = join(routesDir, file);
          const routeModule = await import(`file://${routePath}`);
          
          if (routeModule.default) {
            // Extract route name from filename
            const routeName = file
              .replace('.routes.js', '')
              .replace('.js', '');
            
            const options = routeModule.routeConfig || {};
            const basePath = options.path || `/${routeName}`;
            
            const registered = this.registerRoute(
              basePath,
              routeModule.default,
              options
            );

            logger.info(`  ✓ ${file} → ${registered.path}`);
          }
        } catch (error) {
          logger.error(`  ✗ Failed to load ${file}:`, error.message);
        }
      }

      logger.info(`✅ Auto-registration complete: ${this.routeCount} routes loaded\n`);
    } catch (error) {
      logger.error('❌ Auto-registration failed:', error);
      throw error;
    }
  }

  /**
   * Apply global middleware to all routes
   */
  use(middleware) {
    this.middleware.push(middleware);
    return this;
  }

  /**
   * Get all registered routes
   */
  getRoutes() {
    return Array.from(this.routes.values());
  }

  /**
   * Get routes by version
   */
  getRoutesByVersion(version) {
    return Array.from(this.routes.values()).filter(
      route => route.version === version
    );
  }

  /**
   * Check if route exists
   */
  hasRoute(path) {
    return this.routes.has(path);
  }

  /**
   * Get route count
   */
  getRouteCount() {
    return this.routeCount;
  }

  /**
   * Generate route documentation
   */
  generateRouteMap() {
    const routeMap = {
      total: this.routeCount,
      versions: {},
      routes: []
    };

    for (const [path, info] of this.routes) {
      // Group by version
      if (!routeMap.versions[info.version]) {
        routeMap.versions[info.version] = [];
      }
      routeMap.versions[info.version].push(path);

      // Add to routes list
      routeMap.routes.push({
        path,
        version: info.version,
        description: info.description,
        deprecated: info.deprecated,
        middleware: info.middleware,
        registeredAt: info.registeredAt
      });
    }

    return routeMap;
  }

  /**
   * Print route table to console
   */
  printRoutes() {
    console.log('\n' + '='.repeat(80));
    console.log('  📋 Registered Routes');
    console.log('='.repeat(80));

    const routesByVersion = {};
    for (const [path, info] of this.routes) {
      if (!routesByVersion[info.version]) {
        routesByVersion[info.version] = [];
      }
      routesByVersion[info.version].push({ path, info });
    }

    for (const [version, routes] of Object.entries(routesByVersion)) {
      console.log(`\n  🔖 Version: ${version}`);
      console.log('  ' + '-'.repeat(78));
      
      routes.forEach(({ path, info }) => {
        const deprecated = info.deprecated ? ' [DEPRECATED]' : '';
        const desc = info.description ? ` - ${info.description}` : '';
        console.log(`    ${path}${deprecated}${desc}`);
      });
    }

    console.log('\n' + '='.repeat(80));
    console.log(`  Total Routes: ${this.routeCount}`);
    console.log('='.repeat(80) + '\n');
  }

  /**
   * Create route group with shared middleware
   */
  group(prefix, middleware, callback) {
    const groupRouter = express.Router();
    
    // Apply group middleware
    if (Array.isArray(middleware)) {
      middleware.forEach(m => groupRouter.use(m));
    } else if (middleware) {
      groupRouter.use(middleware);
    }

    // Execute callback to add routes
    callback(groupRouter);

    return this.registerRoute(prefix, groupRouter);
  }

  /**
   * Mount all routes to Express app
   */
  mount(app) {
    logger.info('🔗 Mounting routes to Express app...');

    // Apply global middleware first
    this.middleware.forEach(middleware => {
      app.use(middleware);
      logger.debug(`  ✓ Global middleware applied: ${middleware.name || 'anonymous'}`);
    });

    // Mount all registered routes
    for (const [path, info] of this.routes) {
      app.use(path, info.router);
    }

    logger.info(`✅ ${this.routeCount} routes mounted successfully\n`);
    
    return app;
  }

  /**
   * Create API documentation endpoint
   */
  createDocsEndpoint() {
    const router = express.Router();

    router.get('/', (req, res) => {
      const routeMap = this.generateRouteMap();
      
      res.json({
        success: true,
        data: routeMap,
        timestamp: new Date().toISOString()
      });
    });

    return router;
  }

  /**
   * Health check for routes
   */
  healthCheck() {
    return {
      status: 'healthy',
      routeCount: this.routeCount,
      versions: Array.from(new Set(
        Array.from(this.routes.values()).map(r => r.version)
      ))
    };
  }

  /**
   * Clear all routes (useful for testing)
   */
  clear() {
    this.routes.clear();
    this.routeCount = 0;
    this.middleware = [];
    logger.debug('All routes cleared');
  }
}

/**
 * Route Builder Helper
 */
export class RouteBuilder {
  constructor(basePath = '') {
    this.router = express.Router();
    this.basePath = basePath;
    this.routes = [];
  }

  /**
   * Add GET route
   */
  get(path, ...handlers) {
    this.router.get(path, ...handlers);
    this.routes.push({ method: 'GET', path: `${this.basePath}${path}` });
    return this;
  }

  /**
   * Add POST route
   */
  post(path, ...handlers) {
    this.router.post(path, ...handlers);
    this.routes.push({ method: 'POST', path: `${this.basePath}${path}` });
    return this;
  }

  /**
   * Add PUT route
   */
  put(path, ...handlers) {
    this.router.put(path, ...handlers);
    this.routes.push({ method: 'PUT', path: `${this.basePath}${path}` });
    return this;
  }

  /**
   * Add PATCH route
   */
  patch(path, ...handlers) {
    this.router.patch(path, ...handlers);
    this.routes.push({ method: 'PATCH', path: `${this.basePath}${path}` });
    return this;
  }

  /**
   * Add DELETE route
   */
  delete(path, ...handlers) {
    this.router.delete(path, ...handlers);
    this.routes.push({ method: 'DELETE', path: `${this.basePath}${path}` });
    return this;
  }

  /**
   * Add middleware to all routes
   */
  use(...handlers) {
    this.router.use(...handlers);
    return this;
  }

  /**
   * Build and return router
   */
  build() {
    return this.router;
  }

  /**
   * Get route list
   */
  getRoutes() {
    return this.routes;
  }
}

export default Router;
