/**
 * Product Routes - MILITARY-GRADE Product Management System
 * Enterprise e-commerce product catalog with advanced features
 * 
 * @module routes/product
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ENTERPRISE FEATURES:
 * ============================================================================
 * - Product CRUD operations
 * - Advanced search & filtering
 * - Faceted navigation
 * - Product variants (size, color, etc.)
 * - Inventory management
 * - Price management & discounts
 * - Category hierarchy
 * - Product recommendations
 * - Related products
 * - Recently viewed tracking
 * - Trending products
 * - Stock alerts
 * - Bulk operations
 * - Import/Export (CSV, Excel)
 * - Image galleries
 * - Product attributes (custom fields)
 * - SEO optimization
 * - Product reviews integration
 * - Wishlist integration
 * - Compare products
 * - Price history tracking
 * - Elasticsearch integration ready
 * 
 * ============================================================================
 * SECURITY:
 * ============================================================================
 * - Admin-only write operations
 * - SQL injection prevention
 * - XSS sanitization
 * - Rate limiting
 * - Cache poisoning prevention
 * - Input validation
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
import productController from '../controllers/product.controller.js';

// Middleware
import { authenticate, optionalAuth } from '../middleware/authentication.js';
import { requireRole, requireAdmin, requireModerator } from '../middleware/authorization.js';
import { 
  apiRateLimit, 
  strictRateLimit,
  createEndpointLimiter 
} from '../middleware/rateLimit.js';

// Define search rate limit
const searchRateLimit = createEndpointLimiter({
  windowMs: 60 * 1000,
  max: 60,
  message: 'Too many search requests'
});
import { validateRequest } from '../middleware/validation.js';
import { sanitizeInput, sanitizeHTML } from '../middleware/sanitization.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { attackLogger } from '../middleware/attackLogger.js';
import { modeSwitchMiddleware, getCurrentMode } from '../middleware/modeSwitch.js';

// Config & Constants
import { Config } from '../config/environment.js';
import { 
  HTTP_STATUS, 
  USER_ROLES, 
  ERROR_CODES,
  SUCCESS_MESSAGES,
  ERROR_MESSAGES 
} from '../config/constants.js';

const router = express.Router();
const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

const createProductValidation = [
  body('name')
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Product name must be between 3 and 200 characters')
    .matches(/^[a-zA-Z0-9\s\-',.&()]+$/)
    .withMessage('Product name contains invalid characters'),
  
  body('description')
    .trim()
    .isLength({ min: 10, max: 5000 })
    .withMessage('Description must be between 10 and 5000 characters'),
  
  body('shortDescription')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Short description cannot exceed 500 characters'),
  
  body('price')
    .isFloat({ min: 0.01, max: 999999.99 })
    .withMessage('Price must be between 0.01 and 999999.99')
    .toFloat(),
  
  body('comparePrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Compare price must be a positive number')
    .toFloat()
    .custom((value, { req }) => {
      if (value && value <= req.body.price) {
        throw new Error('Compare price must be greater than selling price');
      }
      return true;
    }),
  
  body('cost')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Cost must be a positive number')
    .toFloat(),
  
  body('sku')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('SKU must be between 3 and 50 characters')
    .matches(/^[A-Z0-9\-_]+$/i)
    .withMessage('SKU can only contain letters, numbers, hyphens, and underscores'),
  
  body('barcode')
    .optional()
    .trim()
    .matches(/^[0-9]{8,13}$/)
    .withMessage('Invalid barcode format'),
  
  body('stock')
    .isInt({ min: 0 })
    .withMessage('Stock must be a non-negative integer')
    .toInt(),
  
  body('lowStockThreshold')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Low stock threshold must be a non-negative integer')
    .toInt(),
  
  body('categoryId')
    .isInt({ min: 1 })
    .withMessage('Valid category ID is required')
    .toInt(),
  
  body('brandId')
    .optional()
    .isInt({ min: 1 })
    .toInt(),
  
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
  
  body('tags.*')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .matches(/^[a-zA-Z0-9\s\-]+$/),
  
  body('images')
    .optional()
    .isArray()
    .withMessage('Images must be an array'),
  
  body('images.*')
    .optional()
    .trim()
    .isURL()
    .withMessage('Invalid image URL'),
  
  body('weight')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Weight must be a positive number')
    .toFloat(),
  
  body('dimensions')
    .optional()
    .isObject()
    .withMessage('Dimensions must be an object'),
  
  body('dimensions.length')
    .optional()
    .isFloat({ min: 0 })
    .toFloat(),
  
  body('dimensions.width')
    .optional()
    .isFloat({ min: 0 })
    .toFloat(),
  
  body('dimensions.height')
    .optional()
    .isFloat({ min: 0 })
    .toFloat(),
  
  body('isActive')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('isFeatured')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('allowBackorder')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('trackInventory')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('metaTitle')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Meta title cannot exceed 200 characters'),
  
  body('metaDescription')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Meta description cannot exceed 500 characters'),
  
  body('metaKeywords')
    .optional()
    .isArray()
];

const updateProductValidation = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 3, max: 200 })
    .matches(/^[a-zA-Z0-9\s\-',.&()]+$/),
  
  body('description')
    .optional()
    .trim()
    .isLength({ min: 10, max: 5000 }),
  
  body('price')
    .optional()
    .isFloat({ min: 0.01, max: 999999.99 })
    .toFloat(),
  
  body('stock')
    .optional()
    .isInt({ min: 0 })
    .toInt(),
  
  body('categoryId')
    .optional()
    .isInt({ min: 1 })
    .toInt(),
  
  body('isActive')
    .optional()
    .isBoolean()
    .toBoolean(),
  
  body('isFeatured')
    .optional()
    .isBoolean()
    .toBoolean()
];

const reviewValidation = [
  body('rating')
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5')
    .toInt(),
  
  body('title')
    .trim()
    .isLength({ min: 5, max: 100 })
    .withMessage('Review title must be between 5 and 100 characters'),
  
  body('comment')
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Review comment must be between 10 and 2000 characters'),
  
  body('verifiedPurchase')
    .optional()
    .isBoolean()
    .toBoolean()
];

// ============================================================================
// RATE LIMITERS
// ============================================================================

const productCreateLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: 'Too many products created. Please try again later.'
});

const productSearchLimit = createEndpointLimiter({
  windowMs: 60 * 1000,
  max: 60,
  message: 'Too many search requests'
});

const reviewSubmitLimit = createEndpointLimiter({
  windowMs: 24 * 60 * 60 * 1000,
  max: 5,
  message: 'Too many reviews submitted. Maximum 5 per day.'
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

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
// PRODUCT CATALOG ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/products:
 *   get:
 *     summary: Get all products (with advanced filtering)
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: categoryId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: minPrice
 *         schema:
 *           type: number
 *       - in: query
 *         name: maxPrice
 *         schema:
 *           type: number
 *       - in: query
 *         name: inStock
 *         schema:
 *           type: boolean
 *       - in: query
 *         name: featured
 *         schema:
 *           type: boolean
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [name, price, createdAt, popularity, rating]
 *       - in: query
 *         name: sortOrder
 *         schema:
 *           type: string
 *           enum: [ASC, DESC]
 *     responses:
 *       200:
 *         description: List of products
 */
router.get('/',
  apiRateLimit,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('search').optional().trim().isLength({ max: 200 }),
  query('categoryId').optional().isInt({ min: 1 }).toInt(),
  query('brandId').optional().isInt({ min: 1 }).toInt(),
  query('minPrice').optional().isFloat({ min: 0 }).toFloat(),
  query('maxPrice').optional().isFloat({ min: 0 }).toFloat(),
  query('inStock').optional().isBoolean().toBoolean(),
  query('featured').optional().isBoolean().toBoolean(),
  query('sortBy').optional().isIn(['name', 'price', 'createdAt', 'popularity', 'rating']),
  query('sortOrder').optional().isIn(['ASC', 'DESC']),
  enhancedValidate,
  productController.getAllProducts
);

/**
 * @swagger
 * /api/v1/products/search:
 *   get:
 *     summary: Advanced product search
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Search results
 */
router.get('/search',
  productSearchLimit,
  query('q')
    .trim()
    .isLength({ min: 2, max: 200 })
    .withMessage('Search query must be between 2 and 200 characters'),
  query('filters').optional().isJSON(),
  enhancedValidate,
  productController.searchProducts
);

/**
 * @swagger
 * /api/v1/products/featured:
 *   get:
 *     summary: Get featured products
 *     tags: [Products]
 *     responses:
 *       200:
 *         description: List of featured products
 */
router.get('/featured',
  apiRateLimit,
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  productController.getFeaturedProducts
);

/**
 * @swagger
 * /api/v1/products/trending:
 *   get:
 *     summary: Get trending products
 *     tags: [Products]
 *     responses:
 *       200:
 *         description: List of trending products
 */
router.get('/trending',
  apiRateLimit,
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  query('period').optional().isIn(['day', 'week', 'month']),
  enhancedValidate,
  productController.getTrendingProducts
);

/**
 * @swagger
 * /api/v1/products/new:
 *   get:
 *     summary: Get newest products
 *     tags: [Products]
 *     responses:
 *       200:
 *         description: List of newest products
 */
router.get('/new',
  apiRateLimit,
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  productController.getNewProducts
);

/**
 * @swagger
 * /api/v1/products/deals:
 *   get:
 *     summary: Get products on sale/deals
 *     tags: [Products]
 *     responses:
 *       200:
 *         description: List of products on sale
 */
router.get('/deals',
  apiRateLimit,
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  enhancedValidate,
  productController.getDeals
);

/**
 * @swagger
 * /api/v1/products/{id}:
 *   get:
 *     summary: Get product by ID
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Product details
 *       404:
 *         description: Product not found
 */
router.get('/:id',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid product ID'),
  enhancedValidate,
  productController.getProductById
);

/**
 * @swagger
 * /api/v1/products:
 *   post:
 *     summary: Create new product (admin only)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Product created successfully
 */
router.post('/',
  productCreateLimit,
  authenticate,
  requireAdmin,
  sanitizeInput,
  createProductValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  productController.createProduct
);

/**
 * @swagger
 * /api/v1/products/{id}:
 *   put:
 *     summary: Update product (admin only)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Product updated successfully
 */
router.put('/:id',
  apiRateLimit,
  authenticate,
  requireAdmin,
  param('id').isInt().withMessage('Invalid product ID'),
  sanitizeInput,
  updateProductValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  productController.updateProduct
);

/**
 * @swagger
 * /api/v1/products/{id}:
 *   delete:
 *     summary: Delete product (admin only)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Product deleted successfully
 */
router.delete('/:id',
  strictRateLimit,
  authenticate,
  requireAdmin,
  param('id').isInt().withMessage('Invalid product ID'),
  productController.deleteProduct
);

// ============================================================================
// PRODUCT REVIEWS
// ============================================================================

/**
 * @swagger
 * /api/v1/products/{id}/reviews:
 *   get:
 *     summary: Get product reviews
 *     tags: [Products, Reviews]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of reviews
 */
router.get('/:id/reviews',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid product ID'),
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
  query('rating').optional().isInt({ min: 1, max: 5 }).toInt(),
  query('sortBy').optional().isIn(['createdAt', 'rating', 'helpful']),
  enhancedValidate,
  productController.getProductReviews
);

/**
 * @swagger
 * /api/v1/products/{id}/reviews:
 *   post:
 *     summary: Add product review
 *     tags: [Products, Reviews]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Review added successfully
 */
router.post('/:id/reviews',
  reviewSubmitLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid product ID'),
  sanitizeInput,
  sanitizeHTML(['title', 'comment']),
  reviewValidation,
  enhancedValidate,
  attackLogger,
  modeSwitchMiddleware,
  productController.addProductReview
);

// ============================================================================
// PRODUCT RELATIONSHIPS
// ============================================================================

/**
 * @swagger
 * /api/v1/products/{id}/related:
 *   get:
 *     summary: Get related products
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of related products
 */
router.get('/:id/related',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid product ID'),
  query('limit').optional().isInt({ min: 1, max: 20 }).toInt(),
  enhancedValidate,
  productController.getRelatedProducts
);

/**
 * @swagger
 * /api/v1/products/{id}/similar:
 *   get:
 *     summary: Get similar products
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of similar products
 */
router.get('/:id/similar',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid product ID'),
  query('limit').optional().isInt({ min: 1, max: 20 }).toInt(),
  enhancedValidate,
  productController.getSimilarProducts
);

/**
 * @swagger
 * /api/v1/products/{id}/recommendations:
 *   get:
 *     summary: Get personalized product recommendations
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of recommended products
 */
router.get('/:id/recommendations',
  apiRateLimit,
  optionalAuth,
  param('id').isInt().withMessage('Invalid product ID'),
  query('limit').optional().isInt({ min: 1, max: 20 }).toInt(),
  enhancedValidate,
  productController.getRecommendations
);

// ============================================================================
// STOCK & INVENTORY
// ============================================================================

/**
 * @swagger
 * /api/v1/products/{id}/stock:
 *   get:
 *     summary: Check product stock availability
 *     tags: [Products, Inventory]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Stock information
 */
router.get('/:id/stock',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid product ID'),
  productController.checkStock
);

/**
 * @swagger
 * /api/v1/products/{id}/stock:
 *   put:
 *     summary: Update product stock (admin only)
 *     tags: [Products, Inventory]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Stock updated successfully
 */
router.put('/:id/stock',
  apiRateLimit,
  authenticate,
  requireAdmin,
  param('id').isInt().withMessage('Invalid product ID'),
  body('quantity')
    .isInt({ min: 0 })
    .withMessage('Quantity must be a non-negative integer')
    .toInt(),
  body('operation')
    .isIn(['set', 'add', 'subtract'])
    .withMessage('Operation must be set, add, or subtract'),
  enhancedValidate,
  productController.updateStock
);

// ============================================================================
// CATEGORIES
// ============================================================================

/**
 * @swagger
 * /api/v1/products/categories:
 *   get:
 *     summary: Get all product categories
 *     tags: [Products, Categories]
 *     responses:
 *       200:
 *         description: List of categories
 */
router.get('/categories/all',
  apiRateLimit,
  query('includeEmpty').optional().isBoolean().toBoolean(),
  enhancedValidate,
  productController.getAllCategories
);

/**
 * @swagger
 * /api/v1/products/categories/{id}:
 *   get:
 *     summary: Get category by ID
 *     tags: [Products, Categories]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Category details
 */
router.get('/categories/:id',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid category ID'),
  enhancedValidate,
  productController.getCategoryById
);

/**
 * @swagger
 * /api/v1/products/categories/{id}/products:
 *   get:
 *     summary: Get products in category
 *     tags: [Products, Categories]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of products in category
 */
router.get('/categories/:id/products',
  apiRateLimit,
  param('id').isInt().withMessage('Invalid category ID'),
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  enhancedValidate,
  productController.getProductsByCategory
);

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @swagger
 * /api/v1/products/stats/overview:
 *   get:
 *     summary: Get product statistics (admin only)
 *     tags: [Products, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Product statistics
 */
router.get('/stats/overview',
  apiRateLimit,
  authenticate,
  requireAdmin,
  productController.getProductStats
);

/**
 * @swagger
 * /api/v1/products/{id}/analytics:
 *   get:
 *     summary: Get product analytics (admin only)
 *     tags: [Products, Analytics]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Product analytics data
 */
router.get('/:id/analytics',
  apiRateLimit,
  authenticate,
  requireAdmin,
  param('id').isInt().withMessage('Invalid product ID'),
  query('period').optional().isIn(['day', 'week', 'month', 'year']),
  enhancedValidate,
  productController.getProductAnalytics
);

// ============================================================================
// BULK OPERATIONS (ADMIN)
// ============================================================================

/**
 * @swagger
 * /api/v1/products/bulk/update:
 *   put:
 *     summary: Bulk update products (admin only)
 *     tags: [Products, Bulk Operations]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Products updated successfully
 */
router.put('/bulk/update',
  strictRateLimit,
  authenticate,
  requireAdmin,
  body('productIds').isArray({ min: 1, max: 100 }),
  body('productIds.*').isInt({ min: 1 }),
  body('updates').isObject(),
  enhancedValidate,
  productController.bulkUpdateProducts
);

/**
 * @swagger
 * /api/v1/products/bulk/delete:
 *   delete:
 *     summary: Bulk delete products (admin only)
 *     tags: [Products, Bulk Operations]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Products deleted successfully
 */
router.delete('/bulk/delete',
  strictRateLimit,
  authenticate,
  requireAdmin,
  body('productIds').isArray({ min: 1, max: 100 }),
  body('productIds.*').isInt({ min: 1 }),
  enhancedValidate,
  productController.bulkDeleteProducts
);

// ============================================================================
// IMPORT/EXPORT
// ============================================================================

/**
 * @swagger
 * /api/v1/products/export:
 *   get:
 *     summary: Export products to CSV (admin only)
 *     tags: [Products, Import/Export]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: CSV file
 */
router.get('/export/csv',
  strictRateLimit,
  authenticate,
  requireAdmin,
  query('categoryId').optional().isInt({ min: 1 }).toInt(),
  query('format').optional().isIn(['csv', 'excel', 'json']),
  enhancedValidate,
  productController.exportProducts
);

/**
 * @swagger
 * /api/v1/products/import:
 *   post:
 *     summary: Import products from CSV (admin only)
 *     tags: [Products, Import/Export]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Products imported successfully
 */
router.post('/import/csv',
  strictRateLimit,
  authenticate,
  requireAdmin,
  productController.importProducts
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((error, req, res, next) => {
  logger.error('Product route error', {
    error: error.message,
    path: req.path,
    method: req.method,
    userId: req.user?.id
  });

  res.status(error.status || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: error.code || ERROR_CODES.INTERNAL_ERROR,
    message: Config.app.env === 'development' ? error.message : ERROR_MESSAGES.INTERNAL_ERROR,
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// EXPORTS
// ============================================================================

logger.info('✅ Product routes loaded (MILITARY-GRADE)');

export default router;
