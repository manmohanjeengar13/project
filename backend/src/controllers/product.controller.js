/**
 * Product Controller
 * Handles product catalog management
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { 
  HTTP_STATUS, 
  PAGINATION,
  SORT_ORDER 
} from '../config/constants.js';
import { NotFoundError, ValidationError } from '../middleware/errorHandler.js';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

/**
 * Get all products with filtering and pagination
 */
export const getAllProducts = async (req, res, next) => {
  try {
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      search = '',
      category = '',
      minPrice = 0,
      maxPrice = 999999,
      inStock = '',
      sortBy = 'created_at',
      sortOrder = SORT_ORDER.DESC
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = ['is_active = TRUE'];
    const values = [];

    if (search) {
      conditions.push('(name LIKE ? OR description LIKE ? OR sku LIKE ?)');
      const searchPattern = `%${search}%`;
      values.push(searchPattern, searchPattern, searchPattern);
    }

    if (category) {
      conditions.push('category_id = ?');
      values.push(category);
    }

    if (minPrice) {
      conditions.push('price >= ?');
      values.push(parseFloat(minPrice));
    }

    if (maxPrice) {
      conditions.push('price <= ?');
      values.push(parseFloat(maxPrice));
    }

    if (inStock !== '') {
      if (inStock === 'true') {
        conditions.push('stock > 0');
      } else {
        conditions.push('stock = 0');
      }
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM products ${whereClause}`,
      values
    );
    const total = countResult[0].total;

    // Validate sortBy to prevent SQL injection
    const validSortFields = ['name', 'price', 'stock', 'created_at', 'updated_at'];
    const safeSortBy = validSortFields.includes(sortBy) ? sortBy : 'created_at';
    const safeSortOrder = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    // Get products
    const [products] = await db.execute(
      `SELECT p.*, c.name as category_name,
              (SELECT AVG(rating) FROM reviews WHERE product_id = p.id) as avg_rating,
              (SELECT COUNT(*) FROM reviews WHERE product_id = p.id) as review_count
       FROM products p
       LEFT JOIN categories c ON p.category_id = c.id
       ${whereClause}
       ORDER BY p.${safeSortBy} ${safeSortOrder}
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: products,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get product by ID
 */
export const getProductById = async (req, res, next) => {
  try {
    const productId = req.params.id;

    // Try cache first
    const cacheKey = CacheKeyBuilder.product(productId);
    let product = await cache.get(cacheKey);

    if (!product) {
      const [products] = await db.execute(
        `SELECT p.*, c.name as category_name,
                (SELECT AVG(rating) FROM reviews WHERE product_id = p.id) as avg_rating,
                (SELECT COUNT(*) FROM reviews WHERE product_id = p.id) as review_count
         FROM products p
         LEFT JOIN categories c ON p.category_id = c.id
         WHERE p.id = ? AND p.is_active = TRUE
         LIMIT 1`,
        [productId]
      );

      if (products.length === 0) {
        throw new NotFoundError('Product');
      }

      product = products[0];

      // Get product images
      const [images] = await db.execute(
        'SELECT id, image_url, is_primary FROM product_images WHERE product_id = ? ORDER BY is_primary DESC, id ASC',
        [productId]
      );
      product.images = images;

      // Get product variants if any
      const [variants] = await db.execute(
        'SELECT * FROM product_variants WHERE product_id = ?',
        [productId]
      );
      product.variants = variants;

      // Cache for 1 hour
      await cache.set(cacheKey, product, 3600);
    }

    // Increment view count (async, don't wait)
    db.execute(
      'UPDATE products SET views = views + 1 WHERE id = ?',
      [productId]
    ).catch(err => logger.error('Failed to increment view count:', err));

    res.json({
      success: true,
      data: product
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Create new product (Admin only)
 */
export const createProduct = async (req, res, next) => {
  try {
    const {
      name,
      description,
      price,
      stock,
      categoryId,
      sku,
      images = []
    } = req.body;

    // Check if SKU already exists
    if (sku) {
      const [existing] = await db.execute(
        'SELECT id FROM products WHERE sku = ? LIMIT 1',
        [sku]
      );

      if (existing.length > 0) {
        throw new ValidationError('SKU already exists');
      }
    }

    // Generate slug
    const slug = name.toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');

    // Insert product
    const [result] = await db.execute(
      `INSERT INTO products (
        name, slug, description, price, stock, category_id, sku, is_active, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, NOW())`,
      [name, slug, description, price, stock, categoryId, sku]
    );

    const productId = result.insertId;

    // Insert images if provided
    if (images.length > 0) {
      const imageValues = images.map((img, index) => 
        [productId, img, index === 0 ? 1 : 0]
      );
      
      await db.execute(
        `INSERT INTO product_images (product_id, image_url, is_primary) VALUES ?`,
        [imageValues]
      );
    }

    logger.info('Product created', { productId, name, adminId: req.user.id });

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Product created successfully',
      data: {
        id: productId,
        name,
        slug,
        price,
        stock
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update product (Admin only)
 */
export const updateProduct = async (req, res, next) => {
  try {
    const productId = req.params.id;
    const {
      name,
      description,
      price,
      stock,
      categoryId,
      sku,
      isActive
    } = req.body;

    // Check if product exists
    const [existing] = await db.execute(
      'SELECT id FROM products WHERE id = ? LIMIT 1',
      [productId]
    );

    if (existing.length === 0) {
      throw new NotFoundError('Product');
    }

    // Check if SKU is being changed and already exists
    if (sku) {
      const [skuCheck] = await db.execute(
        'SELECT id FROM products WHERE sku = ? AND id != ? LIMIT 1',
        [sku, productId]
      );

      if (skuCheck.length > 0) {
        throw new ValidationError('SKU already exists');
      }
    }

    // Build update query
    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push('name = ?');
      values.push(name);
      
      // Update slug
      const slug = name.toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');
      updates.push('slug = ?');
      values.push(slug);
    }

    if (description !== undefined) {
      updates.push('description = ?');
      values.push(description);
    }

    if (price !== undefined) {
      updates.push('price = ?');
      values.push(price);
    }

    if (stock !== undefined) {
      updates.push('stock = ?');
      values.push(stock);
    }

    if (categoryId !== undefined) {
      updates.push('category_id = ?');
      values.push(categoryId);
    }

    if (sku !== undefined) {
      updates.push('sku = ?');
      values.push(sku);
    }

    if (isActive !== undefined) {
      updates.push('is_active = ?');
      values.push(isActive ? 1 : 0);
    }

    if (updates.length === 0) {
      throw new ValidationError('No fields to update');
    }

    updates.push('updated_at = NOW()');
    values.push(productId);

    await db.execute(
      `UPDATE products SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.product(productId));

    logger.info('Product updated', { productId, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Product updated successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete product (Admin only)
 */
export const deleteProduct = async (req, res, next) => {
  try {
    const productId = req.params.id;

    // Soft delete (set is_active to false)
    const [result] = await db.execute(
      'UPDATE products SET is_active = FALSE, updated_at = NOW() WHERE id = ?',
      [productId]
    );

    if (result.affectedRows === 0) {
      throw new NotFoundError('Product');
    }

    // Clear cache
    await cache.delete(CacheKeyBuilder.product(productId));

    logger.info('Product deleted', { productId, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Product deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get product reviews
 */
export const getProductReviews = async (req, res, next) => {
  try {
    const productId = req.params.id;
    const { page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Get reviews
    const [reviews] = await db.execute(
      `SELECT r.*, u.username, u.first_name, u.last_name
       FROM reviews r
       JOIN users u ON r.user_id = u.id
       WHERE r.product_id = ?
       ORDER BY r.created_at DESC
       LIMIT ? OFFSET ?`,
      [productId, parseInt(limit), offset]
    );

    // Get total count
    const [countResult] = await db.execute(
      'SELECT COUNT(*) as total FROM reviews WHERE product_id = ?',
      [productId]
    );

    res.json({
      success: true,
      data: reviews,
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
 * Get related products
 */
export const getRelatedProducts = async (req, res, next) => {
  try {
    const productId = req.params.id;
    const { limit = 4 } = req.query;

    // Get product category
    const [products] = await db.execute(
      'SELECT category_id FROM products WHERE id = ? LIMIT 1',
      [productId]
    );

    if (products.length === 0) {
      throw new NotFoundError('Product');
    }

    const categoryId = products[0].category_id;

    // Get related products from same category
    const [related] = await db.execute(
      `SELECT p.*, 
              (SELECT AVG(rating) FROM reviews WHERE product_id = p.id) as avg_rating
       FROM products p
       WHERE p.category_id = ? AND p.id != ? AND p.is_active = TRUE
       ORDER BY RAND()
       LIMIT ?`,
      [categoryId, productId, parseInt(limit)]
    );

    res.json({
      success: true,
      data: related
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Search products
 */
export const searchProducts = async (req, res, next) => {
  try {
    const { q, limit = 10 } = req.query;

    if (!q || q.length < 2) {
      return res.json({
        success: true,
        data: []
      });
    }

    const searchPattern = `%${q}%`;

    const [products] = await db.execute(
      `SELECT id, name, slug, price, stock, 
              (SELECT image_url FROM product_images WHERE product_id = products.id AND is_primary = 1 LIMIT 1) as image
       FROM products
       WHERE (name LIKE ? OR description LIKE ? OR sku LIKE ?)
       AND is_active = TRUE
       LIMIT ?`,
      [searchPattern, searchPattern, searchPattern, parseInt(limit)]
    );

    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update product stock
 */
export const updateStock = async (req, res, next) => {
  try {
    const productId = req.params.id;
    const { stock } = req.body;

    if (typeof stock !== 'number' || stock < 0) {
      throw new ValidationError('Invalid stock value');
    }

    await db.execute(
      'UPDATE products SET stock = ?, updated_at = NOW() WHERE id = ?',
      [stock, productId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.product(productId));

    logger.info('Product stock updated', { productId, stock, adminId: req.user.id });

    res.json({
      success: true,
      message: 'Stock updated successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Bulk update products
 */
export const bulkUpdateProducts = async (req, res, next) => {
  try {
    const { productIds, action, value } = req.body;

    if (!Array.isArray(productIds) || productIds.length === 0) {
      throw new ValidationError('Product IDs must be a non-empty array');
    }

    let query;
    let params;

    switch (action) {
      case 'activate':
        query = 'UPDATE products SET is_active = TRUE, updated_at = NOW() WHERE id IN (?)';
        params = [productIds];
        break;

      case 'deactivate':
        query = 'UPDATE products SET is_active = FALSE, updated_at = NOW() WHERE id IN (?)';
        params = [productIds];
        break;

      case 'update_category':
        if (!value) throw new ValidationError('Category ID is required');
        query = 'UPDATE products SET category_id = ?, updated_at = NOW() WHERE id IN (?)';
        params = [value, productIds];
        break;

      case 'update_price':
        if (!value || value <= 0) throw new ValidationError('Invalid price');
        query = 'UPDATE products SET price = ?, updated_at = NOW() WHERE id IN (?)';
        params = [value, productIds];
        break;

      default:
        throw new ValidationError('Invalid action');
    }

    const [result] = await db.execute(query, params);

    // Clear cache for all affected products
    for (const productId of productIds) {
      await cache.delete(CacheKeyBuilder.product(productId));
    }

    logger.info('Bulk product update', { action, count: result.affectedRows, adminId: req.user.id });

    res.json({
      success: true,
      message: `${result.affectedRows} products updated successfully`
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get product statistics
 */
export const getProductStatistics = async (req, res, next) => {
  try {
    const productId = req.params.id;

    // Get product details
    const [products] = await db.execute(
      'SELECT * FROM products WHERE id = ? LIMIT 1',
      [productId]
    );

    if (products.length === 0) {
      throw new NotFoundError('Product');
    }

    // Get order statistics
    const [orderStats] = await db.execute(
      `SELECT 
        COUNT(DISTINCT o.id) as total_orders,
        COALESCE(SUM(oi.quantity), 0) as total_sold,
        COALESCE(SUM(oi.quantity * oi.price), 0) as total_revenue
       FROM order_items oi
       JOIN orders o ON oi.order_id = o.id
       WHERE oi.product_id = ? AND o.status != 'cancelled'`,
      [productId]
    );

    // Get review statistics
    const [reviewStats] = await db.execute(
      `SELECT 
        COUNT(*) as total_reviews,
        COALESCE(AVG(rating), 0) as avg_rating,
        COUNT(CASE WHEN rating = 5 THEN 1 END) as five_star,
        COUNT(CASE WHEN rating = 4 THEN 1 END) as four_star,
        COUNT(CASE WHEN rating = 3 THEN 1 END) as three_star,
        COUNT(CASE WHEN rating = 2 THEN 1 END) as two_star,
        COUNT(CASE WHEN rating = 1 THEN 1 END) as one_star
       FROM reviews WHERE product_id = ?`,
      [productId]
    );

    // Get wishlist count
    const [wishlistCount] = await db.execute(
      'SELECT COUNT(*) as count FROM wishlists WHERE product_id = ?',
      [productId]
    );

    res.json({
      success: true,
      data: {
        product: products[0],
        orders: orderStats[0],
        reviews: reviewStats[0],
        wishlist: wishlistCount[0].count
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get featured products
 */
export const getFeaturedProducts = async (req, res, next) => {
  try {
    const { limit = 8 } = req.query;

    const [products] = await db.execute(
      `SELECT p.*, 
              (SELECT AVG(rating) FROM reviews WHERE product_id = p.id) as avg_rating,
              (SELECT COUNT(*) FROM reviews WHERE product_id = p.id) as review_count
       FROM products p
       WHERE p.is_active = TRUE AND p.is_featured = TRUE
       ORDER BY p.created_at DESC
       LIMIT ?`,
      [parseInt(limit)]
    );

    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get best selling products
 */
export const getBestSellingProducts = async (req, res, next) => {
  try {
    const { limit = 10 } = req.query;

    const [products] = await db.execute(
      `SELECT p.*, 
              COALESCE(SUM(oi.quantity), 0) as total_sold,
              (SELECT AVG(rating) FROM reviews WHERE product_id = p.id) as avg_rating
       FROM products p
       LEFT JOIN order_items oi ON p.id = oi.product_id
       LEFT JOIN orders o ON oi.order_id = o.id AND o.status != 'cancelled'
       WHERE p.is_active = TRUE
       GROUP BY p.id
       ORDER BY total_sold DESC
       LIMIT ?`,
      [parseInt(limit)]
    );

    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get new arrivals
 */
export const getNewArrivals = async (req, res, next) => {
  try {
    const { limit = 8 } = req.query;

    const [products] = await db.execute(
      `SELECT p.*, 
              (SELECT AVG(rating) FROM reviews WHERE product_id = p.id) as avg_rating,
              (SELECT COUNT(*) FROM reviews WHERE product_id = p.id) as review_count
       FROM products p
       WHERE p.is_active = TRUE
       ORDER BY p.created_at DESC
       LIMIT ?`,
      [parseInt(limit)]
    );

    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get products on sale
 */
export const getProductsOnSale = async (req, res, next) => {
  try {
    const { limit = 10 } = req.query;

    const [products] = await db.execute(
      `SELECT p.*, 
              (SELECT AVG(rating) FROM reviews WHERE product_id = p.id) as avg_rating
       FROM products p
       WHERE p.is_active = TRUE AND p.sale_price IS NOT NULL AND p.sale_price < p.price
       ORDER BY ((p.price - p.sale_price) / p.price) DESC
       LIMIT ?`,
      [parseInt(limit)]
    );

    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Add product image
 */
export const addProductImage = async (req, res, next) => {
  try {
    const productId = req.params.id;
    const { imageUrl, isPrimary = false } = req.body;

    // If setting as primary, unset other primary images
    if (isPrimary) {
      await db.execute(
        'UPDATE product_images SET is_primary = 0 WHERE product_id = ?',
        [productId]
      );
    }

    const [result] = await db.execute(
      'INSERT INTO product_images (product_id, image_url, is_primary) VALUES (?, ?, ?)',
      [productId, imageUrl, isPrimary ? 1 : 0]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.product(productId));

    logger.info('Product image added', { productId, imageId: result.insertId });

    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'Image added successfully',
      data: {
        id: result.insertId,
        imageUrl,
        isPrimary
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete product image
 */
export const deleteProductImage = async (req, res, next) => {
  try {
    const { id: productId, imageId } = req.params;

    await db.execute(
      'DELETE FROM product_images WHERE id = ? AND product_id = ?',
      [imageId, productId]
    );

    // Clear cache
    await cache.delete(CacheKeyBuilder.product(productId));

    logger.info('Product image deleted', { productId, imageId });

    res.json({
      success: true,
      message: 'Image deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get low stock products (Admin only)
 */
export const getLowStockProducts = async (req, res, next) => {
  try {
    const { threshold = 10, limit = 20 } = req.query;

    const [products] = await db.execute(
      `SELECT id, name, sku, stock, price
       FROM products
       WHERE stock <= ? AND stock > 0 AND is_active = TRUE
       ORDER BY stock ASC
       LIMIT ?`,
      [parseInt(threshold), parseInt(limit)]
    );

    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get out of stock products (Admin only)
 */
export const getOutOfStockProducts = async (req, res, next) => {
  try {
    const { limit = 20 } = req.query;

    const [products] = await db.execute(
      `SELECT id, name, sku, price, updated_at
       FROM products
       WHERE stock = 0 AND is_active = TRUE
       ORDER BY updated_at DESC
       LIMIT ?`,
      [parseInt(limit)]
    );

    res.json({
      success: true,
      data: products
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Export products (Admin only)
 */
export const exportProducts = async (req, res, next) => {
  try {
    const { format = 'json' } = req.query;

    const [products] = await db.execute(
      `SELECT p.*, c.name as category_name
       FROM products p
       LEFT JOIN categories c ON p.category_id = c.id
       ORDER BY p.created_at DESC`
    );

    if (format === 'csv') {
      const csv = [
        ['ID', 'Name', 'SKU', 'Price', 'Stock', 'Category', 'Active', 'Created At'].join(','),
        ...products.map(p => [
          p.id,
          p.name,
          p.sku || '',
          p.price,
          p.stock,
          p.category_name || '',
          p.is_active,
          p.created_at
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=products.csv');
      return res.send(csv);
    }

    res.json({
      success: true,
      data: products,
      count: products.length
    });
  } catch (error) {
    next(error);
  }
};

export default {
  getAllProducts,
  getProductById,
  createProduct,
  updateProduct,
  deleteProduct,
  getProductReviews,
  getRelatedProducts,
  searchProducts,
  updateStock,
  bulkUpdateProducts,
  getProductStatistics,
  getFeaturedProducts,
  getBestSellingProducts,
  getNewArrivals,
  getProductsOnSale,
  addProductImage,
  deleteProductImage,
  getLowStockProducts,
  getOutOfStockProducts,
  exportProducts
};
