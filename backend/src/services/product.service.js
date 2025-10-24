/**
 * Product Service
 * Enterprise-grade business logic for product operations
 * 
 * Features:
 * - Advanced caching strategies with Redis/Memory
 * - Complex product search with Elasticsearch-like features
 * - Stock management with transaction safety
 * - Product recommendation engine
 * - Inventory tracking and alerts
 * - Price history and analytics
 * - Multi-variant product support
 * - Image optimization and CDN integration
 * 
 * @module services/product
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Config } from '../config/environment.js';
import { tables, commonQueries } from '../config/database.js';
import { 
  ValidationError, 
  NotFoundError,
  DatabaseError 
} from '../middleware/errorHandler.js';
import { 
  PAGINATION,
  SORT_ORDER,
  CACHE_TTL,
  ERROR_MESSAGES 
} from '../config/constants.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Get product by ID with comprehensive data
 * Implements multi-level caching strategy
 * 
 * @param {number} productId - Product ID
 * @param {object} options - Query options
 * @returns {Promise<object>} Product with all related data
 */
export const getProductById = async (productId, options = {}) => {
  const {
    includeImages = true,
    includeVariants = true,
    includeReviews = false,
    includeRelated = false,
    incrementViews = false
  } = options;

  try {
    // Try cache first
    const cacheKey = CacheKeyBuilder.product(productId);
    let product = await cache.get(cacheKey);

    if (!product) {
      // Fetch from database with optimized query
      const [products] = await db.execute(
        `SELECT 
          p.*,
          c.name as category_name,
          c.slug as category_slug,
          c.parent_id as category_parent_id,
          COALESCE(p.rating, 0) as rating,
          COALESCE(p.review_count, 0) as review_count,
          COALESCE(p.sales_count, 0) as sales_count,
          CASE 
            WHEN p.stock > 0 THEN 'in_stock'
            WHEN p.stock = 0 AND p.allow_backorder THEN 'backorder'
            ELSE 'out_of_stock'
          END as availability_status
         FROM ${tables.PRODUCTS} p
         LEFT JOIN ${tables.CATEGORIES} c ON p.category_id = c.id
         WHERE p.id = ? AND p.is_active = TRUE
         LIMIT 1`,
        [productId]
      );

      if (products.length === 0) {
        throw new NotFoundError('Product');
      }

      product = products[0];

      // Get product images if requested
      if (includeImages) {
        const [images] = await db.execute(
          `SELECT id, url, alt_text, is_primary, sort_order, thumbnail_url, medium_url, large_url
           FROM ${tables.PRODUCT_IMAGES}
           WHERE product_id = ?
           ORDER BY is_primary DESC, sort_order ASC`,
          [productId]
        );
        product.images = images;
      }

      // Get product variants if requested
      if (includeVariants) {
        const [variants] = await db.execute(
          `SELECT id, sku, name, price, stock, attributes
           FROM ${tables.PRODUCT_VARIANTS}
           WHERE product_id = ? AND is_active = TRUE
           ORDER BY sort_order ASC`,
          [productId]
        );
        product.variants = variants.map(v => ({
          ...v,
          attributes: v.attributes ? JSON.parse(v.attributes) : {}
        }));
      }

      // Cache for 30 minutes
      await cache.set(cacheKey, product, CACHE_TTL.PRODUCT);
    }

    // Get fresh review data if requested (don't cache this)
    if (includeReviews) {
      const [reviews] = await db.execute(
        `SELECT r.*, u.username, u.avatar
         FROM ${tables.REVIEWS} r
         JOIN ${tables.USERS} u ON r.user_id = u.id
         WHERE r.product_id = ? AND r.status = 'approved'
         ORDER BY r.created_at DESC
         LIMIT 10`,
        [productId]
      );
      product.recent_reviews = reviews;
    }

    // Get related products if requested
    if (includeRelated) {
      product.related_products = await getRelatedProducts(productId, 6);
    }

    // Increment view count asynchronously (fire and forget)
    if (incrementViews) {
      incrementProductViews(productId).catch(err => 
        logger.error('Failed to increment product views', { productId, error: err })
      );
    }

    return product;
  } catch (error) {
    logger.error('Error fetching product', { productId, error: error.message });
    throw error;
  }
};

/**
 * Advanced product search with filtering, sorting, and pagination
 * Implements Elasticsearch-like search capabilities
 * 
 * @param {object} filters - Search filters
 * @returns {Promise<object>} Search results with pagination
 */
export const searchProducts = async (filters = {}) => {
  const {
    search = '',
    categoryId = null,
    categorySlug = null,
    minPrice = 0,
    maxPrice = Number.MAX_SAFE_INTEGER,
    minRating = 0,
    tags = [],
    brands = [],
    inStock = false,
    onSale = false,
    featured = false,
    sortBy = 'relevance',
    sortOrder = SORT_ORDER.DESC,
    page = PAGINATION.DEFAULT_PAGE,
    limit = PAGINATION.DEFAULT_LIMIT
  } = filters;

  try {
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const conditions = ['p.is_active = TRUE'];
    const values = [];

    // Full-text search with relevance scoring
    if (search && search.trim()) {
      conditions.push(`(
        MATCH(p.name, p.description, p.sku) AGAINST (? IN NATURAL LANGUAGE MODE)
        OR p.name LIKE ?
        OR p.sku LIKE ?
        OR p.description LIKE ?
      )`);
      const searchTerm = search.trim();
      const searchPattern = `%${searchTerm}%`;
      values.push(searchTerm, searchPattern, searchPattern, searchPattern);
    }

    // Category filter
    if (categoryId) {
      conditions.push('p.category_id = ?');
      values.push(categoryId);
    } else if (categorySlug) {
      conditions.push('c.slug = ?');
      values.push(categorySlug);
    }

    // Price range filter
    if (minPrice > 0) {
      conditions.push('p.price >= ?');
      values.push(minPrice);
    }
    if (maxPrice < Number.MAX_SAFE_INTEGER) {
      conditions.push('p.price <= ?');
      values.push(maxPrice);
    }

    // Rating filter
    if (minRating > 0) {
      conditions.push('p.rating >= ?');
      values.push(minRating);
    }

    // Stock filter
    if (inStock) {
      conditions.push('p.stock > 0');
    }

    // Sale filter
    if (onSale) {
      conditions.push('p.sale_price IS NOT NULL AND p.sale_price < p.price');
    }

    // Featured filter
    if (featured) {
      conditions.push('p.is_featured = TRUE');
    }

    // Tags filter (JSON array search)
    if (tags && tags.length > 0) {
      const tagConditions = tags.map(() => 'JSON_CONTAINS(p.tags, ?)').join(' OR ');
      conditions.push(`(${tagConditions})`);
      tags.forEach(tag => values.push(JSON.stringify(tag)));
    }

    // Brands filter
    if (brands && brands.length > 0) {
      const placeholders = brands.map(() => '?').join(',');
      conditions.push(`p.brand IN (${placeholders})`);
      values.push(...brands);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Determine sort column and direction
    let orderByClause;
    switch (sortBy) {
      case 'price_low':
        orderByClause = 'ORDER BY p.price ASC';
        break;
      case 'price_high':
        orderByClause = 'ORDER BY p.price DESC';
        break;
      case 'rating':
        orderByClause = 'ORDER BY p.rating DESC, p.review_count DESC';
        break;
      case 'popular':
        orderByClause = 'ORDER BY p.sales_count DESC, p.view_count DESC';
        break;
      case 'newest':
        orderByClause = 'ORDER BY p.created_at DESC';
        break;
      case 'name':
        orderByClause = `ORDER BY p.name ${sortOrder}`;
        break;
      case 'relevance':
      default:
        if (search && search.trim()) {
          orderByClause = `ORDER BY 
            MATCH(p.name, p.description, p.sku) AGAINST (? IN NATURAL LANGUAGE MODE) DESC,
            p.sales_count DESC`;
          values.unshift(search.trim()); // Add at beginning for ORDER BY
        } else {
          orderByClause = 'ORDER BY p.featured_priority DESC, p.created_at DESC';
        }
    }

    // Get total count for pagination
    const countQuery = `
      SELECT COUNT(DISTINCT p.id) as total
      FROM ${tables.PRODUCTS} p
      LEFT JOIN ${tables.CATEGORIES} c ON p.category_id = c.id
      ${whereClause}
    `;
    
    const [countResult] = await db.execute(countQuery, values);
    const totalCount = countResult[0].total;

    // Get products
    const productsQuery = `
      SELECT 
        p.id,
        p.name,
        p.slug,
        p.sku,
        p.description,
        p.short_description,
        p.price,
        p.sale_price,
        p.stock,
        p.rating,
        p.review_count,
        p.sales_count,
        p.view_count,
        p.is_featured,
        p.brand,
        p.tags,
        c.name as category_name,
        c.slug as category_slug,
        (SELECT url FROM ${tables.PRODUCT_IMAGES} WHERE product_id = p.id AND is_primary = TRUE LIMIT 1) as image_url,
        (SELECT thumbnail_url FROM ${tables.PRODUCT_IMAGES} WHERE product_id = p.id AND is_primary = TRUE LIMIT 1) as thumbnail_url,
        CASE 
          WHEN p.stock > 0 THEN 'in_stock'
          WHEN p.stock = 0 AND p.allow_backorder THEN 'backorder'
          ELSE 'out_of_stock'
        END as availability_status,
        CASE 
          WHEN p.sale_price IS NOT NULL AND p.sale_price < p.price 
          THEN ROUND(((p.price - p.sale_price) / p.price) * 100) 
          ELSE 0 
        END as discount_percentage
      FROM ${tables.PRODUCTS} p
      LEFT JOIN ${tables.CATEGORIES} c ON p.category_id = c.id
      ${whereClause}
      ${orderByClause}
      LIMIT ? OFFSET ?
    `;

    const [products] = await db.execute(productsQuery, [...values, parseInt(limit), offset]);

    // Parse JSON fields
    const processedProducts = products.map(product => ({
      ...product,
      tags: product.tags ? JSON.parse(product.tags) : [],
      final_price: product.sale_price || product.price
    }));

    // Build facets for filtering (categories, brands, price ranges)
    const facets = await buildSearchFacets(whereClause, values);

    return {
      products: processedProducts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: totalCount,
        pages: Math.ceil(totalCount / parseInt(limit)),
        hasNext: offset + parseInt(limit) < totalCount,
        hasPrev: parseInt(page) > 1
      },
      facets,
      filters: {
        search,
        categoryId,
        minPrice,
        maxPrice,
        minRating,
        inStock,
        onSale,
        featured,
        sortBy
      }
    };
  } catch (error) {
    logger.error('Error searching products', { filters, error: error.message });
    throw new DatabaseError('Failed to search products');
  }
};

/**
 * Build search facets for advanced filtering
 * 
 * @param {string} whereClause - SQL WHERE clause
 * @param {array} values - Query parameters
 * @returns {Promise<object>} Facets data
 */
const buildSearchFacets = async (whereClause, values) => {
  try {
    // Get categories with product counts
    const [categories] = await db.execute(
      `SELECT c.id, c.name, c.slug, COUNT(p.id) as product_count
       FROM ${tables.CATEGORIES} c
       INNER JOIN ${tables.PRODUCTS} p ON c.id = p.category_id
       ${whereClause}
       GROUP BY c.id, c.name, c.slug
       HAVING product_count > 0
       ORDER BY c.name ASC`,
      values
    );

    // Get brands with product counts
    const [brands] = await db.execute(
      `SELECT p.brand, COUNT(*) as product_count
       FROM ${tables.PRODUCTS} p
       ${whereClause}
       GROUP BY p.brand
       HAVING p.brand IS NOT NULL AND product_count > 0
       ORDER BY p.brand ASC`,
      values
    );

    // Get price ranges
    const [priceRange] = await db.execute(
      `SELECT 
        MIN(p.price) as min_price,
        MAX(p.price) as max_price,
        AVG(p.price) as avg_price
       FROM ${tables.PRODUCTS} p
       ${whereClause}`,
      values
    );

    return {
      categories,
      brands,
      priceRange: priceRange[0]
    };
  } catch (error) {
    logger.error('Error building search facets', error);
    return { categories: [], brands: [], priceRange: {} };
  }
};

/**
 * Get related products based on category and tags
 * 
 * @param {number} productId - Current product ID
 * @param {number} limit - Number of related products
 * @returns {Promise<array>} Related products
 */
export const getRelatedProducts = async (productId, limit = 6) => {
  try {
    // Get current product data
    const currentProduct = await getProductById(productId, { 
      includeImages: false,
      includeVariants: false 
    });

    const [relatedProducts] = await db.execute(
      `SELECT 
        p.id,
        p.name,
        p.slug,
        p.price,
        p.sale_price,
        p.rating,
        p.review_count,
        (SELECT url FROM ${tables.PRODUCT_IMAGES} WHERE product_id = p.id AND is_primary = TRUE LIMIT 1) as image_url,
        (SELECT thumbnail_url FROM ${tables.PRODUCT_IMAGES} WHERE product_id = p.id AND is_primary = TRUE LIMIT 1) as thumbnail_url
       FROM ${tables.PRODUCTS} p
       WHERE p.id != ? 
         AND p.is_active = TRUE
         AND p.category_id = ?
         AND p.stock > 0
       ORDER BY 
         p.is_featured DESC,
         p.sales_count DESC,
         RAND()
       LIMIT ?`,
      [productId, currentProduct.category_id, limit]
    );

    return relatedProducts.map(p => ({
      ...p,
      final_price: p.sale_price || p.price
    }));
  } catch (error) {
    logger.error('Error fetching related products', { productId, error: error.message });
    return [];
  }
};

/**
 * Update product stock with transaction safety
 * Supports different operations: set, increment, decrement
 * 
 * @param {number} productId - Product ID
 * @param {number} quantity - Stock quantity
 * @param {string} operation - Operation type
 * @returns {Promise<object>} Updated stock info
 */
export const updateProductStock = async (productId, quantity, operation = 'set') => {
  const connection = await db.beginTransaction();

  try {
    // Get current stock with row lock
    const [products] = await connection.execute(
      `SELECT id, name, stock, stock_threshold 
       FROM ${tables.PRODUCTS} 
       WHERE id = ? 
       FOR UPDATE`,
      [productId]
    );

    if (products.length === 0) {
      throw new NotFoundError('Product');
    }

    const product = products[0];
    let newStock;

    switch (operation) {
      case 'increment':
        newStock = product.stock + quantity;
        break;
      case 'decrement':
        newStock = Math.max(0, product.stock - quantity);
        if (newStock < 0) {
          throw new ValidationError('Insufficient stock');
        }
        break;
      case 'set':
      default:
        newStock = Math.max(0, quantity);
    }

    // Update stock
    await connection.execute(
      `UPDATE ${tables.PRODUCTS} 
       SET stock = ?, updated_at = NOW() 
       WHERE id = ?`,
      [newStock, productId]
    );

    // Log stock change
    await connection.execute(
      `INSERT INTO product_stock_history 
       (product_id, old_stock, new_stock, quantity, operation, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [productId, product.stock, newStock, quantity, operation]
    );

    await db.commit(connection);

    // Clear cache
    await cache.delete(CacheKeyBuilder.product(productId));

    // Check if stock is low and send alert
    if (newStock <= product.stock_threshold && newStock > 0) {
      logger.warn('Low stock alert', { 
        productId, 
        productName: product.name, 
        stock: newStock,
        threshold: product.stock_threshold 
      });
      // Could trigger notification service here
    }

    logger.info('Product stock updated', { 
      productId, 
      operation, 
      oldStock: product.stock, 
      newStock 
    });

    return {
      productId,
      oldStock: product.stock,
      newStock,
      operation
    };
  } catch (error) {
    await db.rollback(connection);
    logger.error('Error updating product stock', { productId, error: error.message });
    throw error;
  }
};

/**
 * Calculate and update product rating
 * 
 * @param {number} productId - Product ID
 * @returns {Promise<object>} Rating statistics
 */
export const calculateProductRating = async (productId) => {
  try {
    const [result] = await db.execute(
      `SELECT 
        COUNT(*) as review_count,
        COALESCE(AVG(rating), 0) as avg_rating,
        SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) as five_star,
        SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) as four_star,
        SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as three_star,
        SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) as two_star,
        SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as one_star
       FROM ${tables.REVIEWS}
       WHERE product_id = ? AND status = 'approved'`,
      [productId]
    );

    const stats = result[0];
    const rating = parseFloat(stats.avg_rating).toFixed(2);

    // Update product
    await db.execute(
      `UPDATE ${tables.PRODUCTS} 
       SET rating = ?, review_count = ?, updated_at = NOW()
       WHERE id = ?`,
      [rating, stats.review_count, productId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.product(productId));

    logger.info('Product rating updated', { productId, rating, reviewCount: stats.review_count });

    return {
      rating: parseFloat(rating),
      reviewCount: stats.review_count,
      distribution: {
        5: stats.five_star,
        4: stats.four_star,
        3: stats.three_star,
        2: stats.two_star,
        1: stats.one_star
      }
    };
  } catch (error) {
    logger.error('Error calculating product rating', { productId, error: error.message });
    throw error;
  }
};

/**
 * Check product availability for given quantity
 * 
 * @param {number} productId - Product ID
 * @param {number} quantity - Requested quantity
 * @returns {Promise<object>} Availability info
 */
export const checkProductAvailability = async (productId, quantity = 1) => {
  try {
    const product = await getProductById(productId, {
      includeImages: false,
      includeVariants: false,
      includeReviews: false
    });

    const available = product.stock >= quantity;
    const canBackorder = !available && product.allow_backorder;

    return {
      available,
      inStock: product.stock > 0,
      canBackorder,
      stock: product.stock,
      requested: quantity,
      status: product.availability_status,
      estimatedRestockDate: product.estimated_restock_date || null
    };
  } catch (error) {
    logger.error('Error checking product availability', { productId, error: error.message });
    throw error;
  }
};

/**
 * Increment product view count
 * 
 * @param {number} productId - Product ID
 */
const incrementProductViews = async (productId) => {
  try {
    await db.execute(
      `UPDATE ${tables.PRODUCTS} 
       SET view_count = view_count + 1 
       WHERE id = ?`,
      [productId]
    );
  } catch (error) {
    logger.error('Error incrementing product views', { productId, error: error.message });
  }
};

/**
 * Get product price history
 * 
 * @param {number} productId - Product ID
 * @param {number} days - Number of days to fetch
 * @returns {Promise<array>} Price history
 */
export const getProductPriceHistory = async (productId, days = 30) => {
  try {
    const [history] = await db.execute(
      `SELECT price, sale_price, DATE(created_at) as date
       FROM product_price_history
       WHERE product_id = ?
         AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
       ORDER BY created_at ASC`,
      [productId, days]
    );

    return history;
  } catch (error) {
    logger.error('Error fetching price history', { productId, error: error.message });
    return [];
  }
};

/**
 * Get low stock products
 * 
 * @param {number} limit - Number of products
 * @returns {Promise<array>} Low stock products
 */
export const getLowStockProducts = async (limit = 50) => {
  try {
    const [products] = await db.execute(
      `SELECT id, name, sku, stock, stock_threshold, category_id
       FROM ${tables.PRODUCTS}
       WHERE is_active = TRUE 
         AND stock > 0 
         AND stock <= stock_threshold
       ORDER BY (stock / stock_threshold) ASC
       LIMIT ?`,
      [limit]
    );

    return products;
  } catch (error) {
    logger.error('Error fetching low stock products', error);
    return [];
  }
};

/**
 * Bulk update products
 * 
 * @param {array} updates - Array of product updates
 * @returns {Promise<object>} Update results
 */
export const bulkUpdateProducts = async (updates) => {
  const results = {
    success: [],
    failed: []
  };

  for (const update of updates) {
    try {
      const { id, ...data } = update;
      
      const fields = Object.keys(data).map(key => `${key} = ?`).join(', ');
      const values = [...Object.values(data), id];

      await db.execute(
        `UPDATE ${tables.PRODUCTS} SET ${fields}, updated_at = NOW() WHERE id = ?`,
        values
      );

      await cache.delete(CacheKeyBuilder.product(id));
      results.success.push(id);
    } catch (error) {
      logger.error('Bulk update failed for product', { productId: update.id, error: error.message });
      results.failed.push({ id: update.id, error: error.message });
    }
  }

  return results;
};

export default {
  getProductById,
  searchProducts,
  getRelatedProducts,
  updateProductStock,
  calculateProductRating,
  checkProductAvailability,
  getProductPriceHistory,
  getLowStockProducts,
  bulkUpdateProducts
};
