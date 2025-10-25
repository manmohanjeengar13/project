
/**
 * Product Model
 * Enterprise-grade product data model with inventory management
 * 
 * @module models/Product
 * @version 2.0.0
 * @license MIT
 * 
 * Features:
 * - Advanced inventory tracking
 * - Price history and analytics
 * - Multi-variant support
 * - Image management
 * - SEO optimization
 * - Review aggregation
 * - Stock alerts
 * - Bulk operations
 * - Category relationships
 * - Tag management
 * - Sales analytics
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { tables } from '../config/database.js';
import { ValidationError, NotFoundError } from '../middleware/errorHandler.js';
import { EventEmitter } from 'events';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

export class Product extends EventEmitter {
  constructor(data = {}) {
    super();
    
    // Core attributes
    this.id = data.id || null;
    this.name = data.name || null;
    this.slug = data.slug || null;
    this.sku = data.sku || null;
    this.description = data.description || null;
    this.shortDescription = data.short_description || data.shortDescription || null;
    
    // Category & Classification
    this.categoryId = data.category_id || data.categoryId || null;
    this.brand = data.brand || null;
    this.tags = data.tags ? (typeof data.tags === 'string' ? JSON.parse(data.tags) : data.tags) : [];
    
    // Pricing
    this.price = parseFloat(data.price) || 0;
    this.salePrice = data.sale_price ? parseFloat(data.sale_price) : null;
    this.costPrice = data.cost_price ? parseFloat(data.cost_price) : null;
    this.currency = data.currency || 'USD';
    this.taxRate = parseFloat(data.tax_rate) || 0;
    
    // Inventory
    this.stock = parseInt(data.stock) || 0;
    this.stockThreshold = parseInt(data.stock_threshold) || 10;
    this.allowBackorder = data.allow_backorder !== undefined ? data.allow_backorder : false;
    this.maxQuantityPerOrder = data.max_quantity_per_order || null;
    this.trackInventory = data.track_inventory !== undefined ? data.track_inventory : true;
    
    // Physical attributes
    this.weight = data.weight ? parseFloat(data.weight) : null;
    this.weightUnit = data.weight_unit || 'kg';
    this.dimensions = data.dimensions ? 
      (typeof data.dimensions === 'string' ? JSON.parse(data.dimensions) : data.dimensions) : 
      null;
    
    // Status & Features
    this.isActive = data.is_active !== undefined ? data.is_active : true;
    this.isFeatured = data.is_featured || false;
    this.isNew = data.is_new || false;
    this.featuredPriority = parseInt(data.featured_priority) || 0;
    
    // SEO
    this.metaTitle = data.meta_title || null;
    this.metaDescription = data.meta_description || null;
    this.metaKeywords = data.meta_keywords || null;
    
    // Analytics & Ratings
    this.rating = parseFloat(data.rating) || 0;
    this.reviewCount = parseInt(data.review_count) || 0;
    this.viewCount = parseInt(data.view_count) || 0;
    this.salesCount = parseInt(data.sales_count) || 0;
    this.wishlistCount = parseInt(data.wishlist_count) || 0;
    
    // Pricing strategies
    this.memberDiscountPercentage = data.member_discount_percentage ? parseFloat(data.member_discount_percentage) : null;
    this.bulkPricing = data.bulk_pricing ? 
      (typeof data.bulk_pricing === 'string' ? JSON.parse(data.bulk_pricing) : data.bulk_pricing) : 
      null;
    
    // Timestamps
    this.estimatedRestockDate = data.estimated_restock_date || null;
    this.availableFrom = data.available_from || null;
    this.availableUntil = data.available_until || null;
    this.createdAt = data.created_at || null;
    this.updatedAt = data.updated_at || null;
    this.deletedAt = data.deleted_at || null;
    
    // Internal flags
    this._isNew = !this.id;
    this._isDirty = false;
    this._dirtyAttributes = new Set();
    this._originalData = { ...data };
    
    // Relationships (lazy loaded)
    this._category = null;
    this._images = null;
    this._variants = null;
    this._reviews = null;
  }

  // ==========================================================================
  // VIRTUAL ATTRIBUTES
  // ==========================================================================

  get finalPrice() {
    return this.salePrice || this.price;
  }

  get discountPercentage() {
    if (!this.salePrice || this.salePrice >= this.price) return 0;
    return Math.round(((this.price - this.salePrice) / this.price) * 100);
  }

  get profit() {
    if (!this.costPrice) return null;
    return this.finalPrice - this.costPrice;
  }

  get profitMargin() {
    if (!this.costPrice || this.costPrice === 0) return null;
    return ((this.profit / this.costPrice) * 100).toFixed(2);
  }

  get isInStock() {
    return this.stock > 0;
  }

  get isLowStock() {
    return this.stock > 0 && this.stock <= this.stockThreshold;
  }

  get isOutOfStock() {
    return this.stock <= 0;
  }

  get availabilityStatus() {
    if (this.stock > 0) return 'in_stock';
    if (this.stock === 0 && this.allowBackorder) return 'backorder';
    return 'out_of_stock';
  }

  get isPremiumProduct() {
    return this.price > 100;
  }

  get isOnSale() {
    return this.salePrice && this.salePrice < this.price;
  }

  get averageRating() {
    return this.rating;
  }

  get popularity() {
    // Simple popularity score based on sales, views, and wishlists
    return (this.salesCount * 5) + (this.viewCount * 0.1) + (this.wishlistCount * 2);
  }

  get isDeleted() {
    return this.deletedAt !== null;
  }

  // ==========================================================================
  // VALIDATION
  // ==========================================================================

  validate() {
    const errors = [];

    // Name validation
    if (!this.name || this.name.length < 3) {
      errors.push('Product name must be at least 3 characters');
    }

    // SKU validation
    if (!this.sku) {
      errors.push('SKU is required');
    }
    if (this.sku && !/^[A-Z0-9-]+$/.test(this.sku)) {
      errors.push('SKU can only contain uppercase letters, numbers, and hyphens');
    }

    // Price validation
    if (this.price < 0) {
      errors.push('Price cannot be negative');
    }
    if (this.salePrice && this.salePrice < 0) {
      errors.push('Sale price cannot be negative');
    }
    if (this.salePrice && this.salePrice > this.price) {
      errors.push('Sale price cannot be higher than regular price');
    }

    // Stock validation
    if (this.trackInventory && this.stock < 0) {
      errors.push('Stock cannot be negative');
    }

    // Weight validation
    if (this.weight && this.weight < 0) {
      errors.push('Weight cannot be negative');
    }

    if (errors.length > 0) {
      throw new ValidationError('Product validation failed', { errors });
    }

    return true;
  }

  // ==========================================================================
  // HOOKS
  // ==========================================================================

  async beforeSave() {
    this.emit('beforeSave', this);

    // Generate slug from name if not provided
    if (!this.slug && this.name) {
      this.slug = this.generateSlug(this.name);
    }

    // Uppercase SKU
    if (this.sku) {
      this.sku = this.sku.toUpperCase().trim();
    }

    // Set timestamps
    if (this._isNew) {
      this.createdAt = new Date();
    }
    this.updatedAt = new Date();

    // Mark as new if recently added (within 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    this.isNew = this.createdAt > thirtyDaysAgo;
  }

  async afterSave() {
    this.emit('afterSave', this);

    // Clear cache
    if (this.id) {
      await cache.delete(CacheKeyBuilder.product(this.id));
      await cache.delete(`product:slug:${this.slug}`);
      await cache.delete(`product:sku:${this.sku}`);
    }

    // Check for low stock alert
    if (this.isLowStock) {
      this.emit('lowStock', this);
      logger.warn('Low stock alert', { 
        productId: this.id, 
        name: this.name, 
        stock: this.stock,
        threshold: this.stockThreshold
      });
    }

    logger.info('Product saved', { 
      productId: this.id, 
      name: this.name,
      sku: this.sku,
      isNew: this._isNew 
    });

    this._isNew = false;
    this._isDirty = false;
    this._dirtyAttributes.clear();
  }

  async beforeDelete() {
    this.emit('beforeDelete', this);
  }

  async afterDelete() {
    this.emit('afterDelete', this);

    // Clear cache
    if (this.id) {
      await cache.delete(CacheKeyBuilder.product(this.id));
    }

    logger.info('Product deleted', { productId: this.id, name: this.name });
  }

  // ==========================================================================
  // CRUD OPERATIONS
  // ==========================================================================

  async save() {
    try {
      this.validate();
      await this.beforeSave();

      if (this._isNew) {
        // INSERT
        const [result] = await db.execute(
          `INSERT INTO ${tables.PRODUCTS} (
            name, slug, sku, description, short_description,
            category_id, brand, tags,
            price, sale_price, cost_price, currency, tax_rate,
            stock, stock_threshold, allow_backorder, max_quantity_per_order, track_inventory,
            weight, weight_unit, dimensions,
            is_active, is_featured, is_new, featured_priority,
            meta_title, meta_description, meta_keywords,
            member_discount_percentage, bulk_pricing,
            available_from, available_until,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
          [
            this.name, this.slug, this.sku, this.description, this.shortDescription,
            this.categoryId, this.brand, JSON.stringify(this.tags),
            this.price, this.salePrice, this.costPrice, this.currency, this.taxRate,
            this.stock, this.stockThreshold, this.allowBackorder, this.maxQuantityPerOrder, this.trackInventory,
            this.weight, this.weightUnit, JSON.stringify(this.dimensions),
            this.isActive, this.isFeatured, this.isNew, this.featuredPriority,
            this.metaTitle, this.metaDescription, this.metaKeywords,
            this.memberDiscountPercentage, JSON.stringify(this.bulkPricing),
            this.availableFrom, this.availableUntil
          ]
        );

        this.id = result.insertId;
      } else {
        // UPDATE - Dynamic query based on dirty attributes
        const fields = [];
        const values = [];

        const attributeMap = {
          name: 'name',
          slug: 'slug',
          sku: 'sku',
          description: 'description',
          shortDescription: 'short_description',
          categoryId: 'category_id',
          brand: 'brand',
          tags: 'tags',
          price: 'price',
          salePrice: 'sale_price',
          stock: 'stock',
          isActive: 'is_active',
          isFeatured: 'is_featured'
        };

        for (const [jsName, dbName] of Object.entries(attributeMap)) {
          if (this._dirtyAttributes.has(jsName)) {
            fields.push(`${dbName} = ?`);
            let value = this[jsName];
            if (jsName === 'tags' || jsName === 'dimensions' || jsName === 'bulkPricing') {
              value = JSON.stringify(value);
            }
            values.push(value);
          }
        }

        fields.push('updated_at = NOW()');
        values.push(this.id);

        if (fields.length > 1) {
          await db.execute(
            `UPDATE ${tables.PRODUCTS} SET ${fields.join(', ')} WHERE id = ?`,
            values
          );
        }
      }

      await this.afterSave();
      return this;
    } catch (error) {
      logger.error('Product save failed', { error: error.message });
      throw error;
    }
  }

  async delete(soft = true) {
    try {
      if (!this.id) {
        throw new Error('Cannot delete unsaved product');
      }

      await this.beforeDelete();

      if (soft) {
        this.deletedAt = new Date();
        await db.execute(
          `UPDATE ${tables.PRODUCTS} SET deleted_at = NOW() WHERE id = ?`,
          [this.id]
        );
      } else {
        await db.execute(
          `DELETE FROM ${tables.PRODUCTS} WHERE id = ?`,
          [this.id]
        );
      }

      await this.afterDelete();
      return true;
    } catch (error) {
      logger.error('Product delete failed', { productId: this.id, error: error.message });
      throw error;
    }
  }

  async restore() {
    try {
      if (!this.id || !this.deletedAt) {
        throw new Error('Cannot restore non-deleted product');
      }

      await db.execute(
        `UPDATE ${tables.PRODUCTS} SET deleted_at = NULL WHERE id = ?`,
        [this.id]
      );

      this.deletedAt = null;
      await cache.delete(CacheKeyBuilder.product(this.id));

      logger.info('Product restored', { productId: this.id });
      return true;
    } catch (error) {
      logger.error('Product restore failed', { productId: this.id, error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // INVENTORY MANAGEMENT
  // ==========================================================================

  async updateStock(quantity, operation = 'set') {
    const connection = await db.beginTransaction();

    try {
      let newStock;

      switch (operation) {
        case 'increment':
          newStock = this.stock + quantity;
          break;
        case 'decrement':
          newStock = Math.max(0, this.stock - quantity);
          if (this.trackInventory && newStock < 0) {
            throw new ValidationError('Insufficient stock');
          }
          break;
        case 'set':
        default:
          newStock = Math.max(0, quantity);
      }

      await connection.execute(
        `UPDATE ${tables.PRODUCTS} SET stock = ?, updated_at = NOW() WHERE id = ?`,
        [newStock, this.id]
      );

      // Log stock change
      await connection.execute(
        `INSERT INTO product_stock_history (product_id, old_stock, new_stock, quantity, operation, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())`,
        [this.id, this.stock, newStock, quantity, operation]
      );

      await db.commit(connection);

      this.stock = newStock;
      await cache.delete(CacheKeyBuilder.product(this.id));

      this.emit('stockUpdated', { oldStock: this._originalData.stock, newStock, operation });

      logger.info('Stock updated', { 
        productId: this.id, 
        oldStock: this._originalData.stock, 
        newStock, 
        operation 
      });

      return newStock;
    } catch (error) {
      await db.rollback(connection);
      logger.error('Stock update failed', { productId: this.id, error: error.message });
      throw error;
    }
  }

  async reserveStock(quantity) {
    if (!this.trackInventory) return true;

    if (this.stock < quantity) {
      if (!this.allowBackorder) {
        throw new ValidationError('Insufficient stock and backorder not allowed');
      }
    }

    return await this.updateStock(quantity, 'decrement');
  }

  async releaseStock(quantity) {
    return await this.updateStock(quantity, 'increment');
  }

  // ==========================================================================
  // PRICING METHODS
  // ==========================================================================

  getPriceForQuantity(quantity, userRole = null) {
    let price = this.finalPrice;

    // Apply member discount
    if (userRole === 'premium' && this.memberDiscountPercentage) {
      price = price * (1 - this.memberDiscountPercentage / 100);
    }

    // Apply bulk pricing
    if (this.bulkPricing && Array.isArray(this.bulkPricing)) {
      for (const tier of this.bulkPricing) {
        if (quantity >= tier.min_quantity) {
          if (tier.discount_type === 'percentage') {
            price = price * (1 - tier.discount_value / 100);
          } else if (tier.discount_type === 'fixed') {
            price = tier.discount_value;
          }
        }
      }
    }

    return parseFloat(price.toFixed(2));
  }

  async updatePrice(newPrice, createHistory = true) {
    const oldPrice = this.price;
    this.price = newPrice;

    if (createHistory) {
      await db.execute(
        `INSERT INTO product_price_history (product_id, old_price, new_price, created_at)
         VALUES (?, ?, ?, NOW())`,
        [this.id, oldPrice, newPrice]
      );
    }

    await this.save();
    this.emit('priceUpdated', { oldPrice, newPrice });
  }

  // ==========================================================================
  // RATINGS & REVIEWS
  // ==========================================================================

  async updateRating() {
    const [result] = await db.execute(
      `SELECT COUNT(*) as count, COALESCE(AVG(rating), 0) as avg_rating
       FROM ${tables.REVIEWS}
       WHERE product_id = ? AND status = 'approved'`,
      [this.id]
    );

    this.reviewCount = result[0].count;
    this.rating = parseFloat(result[0].avg_rating.toFixed(2));

    await db.execute(
      `UPDATE ${tables.PRODUCTS} 
       SET rating = ?, review_count = ?, updated_at = NOW()
       WHERE id = ?`,
      [this.rating, this.reviewCount, this.id]
    );

    await cache.delete(CacheKeyBuilder.product(this.id));

    return { rating: this.rating, count: this.reviewCount };
  }

  async incrementViewCount() {
    this.viewCount++;

    await db.execute(
      `UPDATE ${tables.PRODUCTS} SET view_count = view_count + 1 WHERE id = ?`,
      [this.id]
    );

    // Update cache asynchronously
    cache.delete(CacheKeyBuilder.product(this.id)).catch(() => {});
  }

  // ==========================================================================
  // RELATIONSHIP METHODS
  // ==========================================================================

  async category(options = {}) {
    if (this._category && !options.reload) {
      return this._category;
    }

    if (!this.categoryId) return null;

    const [categories] = await db.execute(
      `SELECT * FROM ${tables.CATEGORIES} WHERE id = ? LIMIT 1`,
      [this.categoryId]
    );

    this._category = categories[0] || null;
    return this._category;
  }

  async images(options = {}) {
    if (this._images && !options.reload) {
      return this._images;
    }

    const [images] = await db.execute(
      `SELECT * FROM ${tables.PRODUCT_IMAGES}
       WHERE product_id = ?
       ORDER BY is_primary DESC, sort_order ASC`,
      [this.id]
    );

    this._images = images;
    return images;
  }

  async primaryImage() {
    const images = await this.images();
    return images.find(img => img.is_primary) || images[0] || null;
  }

  async variants(options = {}) {
    if (this._variants && !options.reload) {
      return this._variants;
    }

    const [variants] = await db.execute(
      `SELECT * FROM ${tables.PRODUCT_VARIANTS}
       WHERE product_id = ? AND is_active = TRUE
       ORDER BY sort_order ASC`,
      [this.id]
    );

    this._variants = variants;
    return variants;
  }

  async reviews(options = {}) {
    if (this._reviews && !options.reload) {
      return this._reviews;
    }

    const { limit = 10, offset = 0, status = 'approved' } = options;

    const [reviews] = await db.execute(
      `SELECT r.*, u.username, u.avatar
       FROM ${tables.REVIEWS} r
       JOIN ${tables.USERS} u ON r.user_id = u.id
       WHERE r.product_id = ? AND r.status = ?
       ORDER BY r.created_at DESC
       LIMIT ? OFFSET ?`,
      [this.id, status, limit, offset]
    );

    this._reviews = reviews;
    return reviews;
  }

  // ==========================================================================
  // UTILITIES
  // ==========================================================================

  generateSlug(name) {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }

  set(attribute, value) {
    if (this[attribute] !== value) {
      this[attribute] = value;
      this._isDirty = true;
      this._dirtyAttributes.add(attribute);
    }
    return this;
  }

  get isDirty() {
    return this._isDirty;
  }

  // ==========================================================================
  // SERIALIZATION
  // ==========================================================================

  toJSON(options = {}) {
    const { includeRelations = false, includeAnalytics = false } = options;

    const json = {
      id: this.id,
      name: this.name,
      slug: this.slug,
      sku: this.sku,
      description: this.description,
      shortDescription: this.shortDescription,
      categoryId: this.categoryId,
      brand: this.brand,
      tags: this.tags,
      price: this.price,
      salePrice: this.salePrice,
      finalPrice: this.finalPrice,
      discountPercentage: this.discountPercentage,
      currency: this.currency,
      stock: this.stock,
      availabilityStatus: this.availabilityStatus,
      isInStock: this.isInStock,
      isLowStock: this.isLowStock,
      isOnSale: this.isOnSale,
      weight: this.weight,
      dimensions: this.dimensions,
      isActive: this.isActive,
      isFeatured: this.isFeatured,
      isNew: this.isNew,
      rating: this.rating,
      reviewCount: this.reviewCount,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };

    if (includeAnalytics) {
      json.viewCount = this.viewCount;
      json.salesCount = this.salesCount;
      json.wishlistCount = this.wishlistCount;
      json.popularity = this.popularity;
      json.profitMargin = this.profitMargin;
    }

    if (includeRelations && this._category) {
      json.category = this._category;
    }

    if (includeRelations && this._images) {
      json.images = this._images;
    }

    return json;
  }

  toPublic() {
    return {
      id: this.id,
      name: this.name,
      slug: this.slug,
      shortDescription: this.shortDescription,
      price: this.price,
      salePrice: this.salePrice,
      finalPrice: this.finalPrice,
      discountPercentage: this.discountPercentage,
      availabilityStatus: this.availabilityStatus,
      rating: this.rating,
      reviewCount: this.reviewCount,
      isNew: this.isNew,
      isFeatured: this.isFeatured
    };
  }

  // ==========================================================================
  // STATIC METHODS
  // ==========================================================================

  static async findById(id, options = {}) {
    const { includeDeleted = false } = options;

    const cacheKey = CacheKeyBuilder.product(id);
    let productData = await cache.get(cacheKey);

    if (!productData) {
      const whereClause = includeDeleted ? 'id = ?' : 'id = ? AND deleted_at IS NULL';

      const [products] = await db.execute(
        `SELECT * FROM ${tables.PRODUCTS} WHERE ${whereClause} LIMIT 1`,
        [id]
      );

      if (products.length === 0) {
        return null;
      }

      productData = products[0];
      await cache.set(cacheKey, productData, 1800); // Cache for 30 minutes
    }

    return new Product(productData);
  }

  static async findBySlug(slug, options = {}) {
    const { includeDeleted = false } = options;

    const cacheKey = `product:slug:${slug}`;
    let productData = await cache.get(cacheKey);

    if (!productData) {
      const whereClause = includeDeleted ? 'slug = ?' : 'slug = ? AND deleted_at IS NULL';

      const [products] = await db.execute(
        `SELECT * FROM ${tables.PRODUCTS} WHERE ${whereClause} LIMIT 1`,
        [slug]
      );

      if (products.length === 0) {
        return null;
      }

      productData = products[0];
      await cache.set(cacheKey, productData, 1800);
    }

    return new Product(productData);
  }

  static async findBySKU(sku, options = {}) {
    const [products] = await db.execute(
      `SELECT * FROM ${tables.PRODUCTS} WHERE sku = ? AND deleted_at IS NULL LIMIT 1`,
      [sku.toUpperCase()]
    );

    return products.length > 0 ? new Product(products[0]) : null;
  }

  static async findAll(options = {}) {
    const {
      where = {},
      limit = 50,
      offset = 0,
      orderBy = 'created_at',
      orderDirection = 'DESC',
      includeDeleted = false
    } = options;

    const conditions = [];
    const values = [];

    if (!includeDeleted) {
      conditions.push('deleted_at IS NULL');
    }

    Object.entries(where).forEach(([key, value]) => {
      conditions.push(`${key} = ?`);
      values.push(value);
    });

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [products] = await db.execute(
      `SELECT * FROM ${tables.PRODUCTS}
       ${whereClause}
       ORDER BY ${orderBy} ${orderDirection}
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return products.map(productData => new Product(productData));
  }

  static async count(options = {}) {
    const { where = {}, includeDeleted = false } = options;

    const conditions = [];
    const values = [];

    if (!includeDeleted) {
      conditions.push('deleted_at IS NULL');
    }

    Object.entries(where).forEach(([key, value]) => {
      conditions.push(`${key} = ?`);
      values.push(value);
    });

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [result] = await db.execute(
      `SELECT COUNT(*) as count FROM ${tables.PRODUCTS} ${whereClause}`,
      values
    );

    return result[0].count;
  }

  static async search(query, options = {}) {
    const { limit = 20, offset = 0 } = options;

    const [products] = await db.execute(
      `SELECT * FROM ${tables.PRODUCTS}
       WHERE (name LIKE ? OR description LIKE ? OR sku LIKE ? OR brand LIKE ?)
         AND deleted_at IS NULL AND is_active = TRUE
       ORDER BY featured_priority DESC, name ASC
       LIMIT ? OFFSET ?`,
      [`%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`, limit, offset]
    );

    return products.map(productData => new Product(productData));
  }

  static async getLowStock(threshold = null) {
    const condition = threshold 
      ? 'stock <= ?' 
      : 'stock <= stock_threshold';
    
    const params = threshold ? [threshold] : [];

    const [products] = await db.execute(
      `SELECT * FROM ${tables.PRODUCTS}
       WHERE ${condition} 
         AND stock > 0 
         AND deleted_at IS NULL 
         AND is_active = TRUE
       ORDER BY stock ASC
       LIMIT 100`,
      params
    );

    return products.map(productData => new Product(productData));
  }

  static async getOutOfStock() {
    const [products] = await db.execute(
      `SELECT * FROM ${tables.PRODUCTS}
       WHERE stock = 0 
         AND deleted_at IS NULL 
         AND is_active = TRUE
       ORDER BY sales_count DESC
       LIMIT 100`
    );

    return products.map(productData => new Product(productData));
  }

  static async getFeatured(limit = 10) {
    const [products] = await db.execute(
      `SELECT * FROM ${tables.PRODUCTS}
       WHERE is_featured = TRUE 
         AND deleted_at IS NULL 
         AND is_active = TRUE
       ORDER BY featured_priority DESC, created_at DESC
       LIMIT ?`,
      [limit]
    );

    return products.map(productData => new Product(productData));
  }

  static async getBestSelling(limit = 10) {
    const [products] = await db.execute(
      `SELECT * FROM ${tables.PRODUCTS}
       WHERE deleted_at IS NULL 
         AND is_active = TRUE
       ORDER BY sales_count DESC
       LIMIT ?`,
      [limit]
    );

    return products.map(productData => new Product(productData));
  }
}

export default Product;
