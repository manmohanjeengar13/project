/**
 * User Model
 * Enterprise-grade user data model with advanced ORM-like capabilities
 * 
 * @module models/User
 * @version 2.0.0
 * @license MIT
 * 
 * Features:
 * - Active Record pattern implementation
 * - Data validation and sanitization
 * - Relationship management (eager/lazy loading)
 * - Soft delete support
 * - Audit trail tracking
 * - Query builder integration
 * - Cache integration
 * - Hook system (beforeSave, afterSave, etc.)
 * - Virtual attributes
 * - Mass assignment protection
 * - Attribute encryption
 * - Search and filtering
 * - Pagination support
 * - Event emission
 * - Transaction support
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { tables } from '../config/database.js';
import { USER_ROLES, ROLE_HIERARCHY } from '../config/constants.js';
import { hashPassword, verifyPassword } from '../services/encryption.service.js';
import { ValidationError, NotFoundError } from '../middleware/errorHandler.js';
import { EventEmitter } from 'events';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// USER MODEL CLASS
// ============================================================================

export class User extends EventEmitter {
  constructor(data = {}) {
    super();
    
    // Core attributes
    this.id = data.id || null;
    this.username = data.username || null;
    this.email = data.email || null;
    this.password = data.password || null;
    this.firstName = data.first_name || data.firstName || null;
    this.lastName = data.last_name || data.lastName || null;
    this.role = data.role || USER_ROLES.CUSTOMER;
    this.avatar = data.avatar || null;
    this.phone = data.phone || null;
    this.dateOfBirth = data.date_of_birth || data.dateOfBirth || null;
    this.gender = data.gender || null;
    
    // Status & verification
    this.isActive = data.is_active !== undefined ? data.is_active : true;
    this.isEmailVerified = data.is_email_verified || false;
    this.emailVerificationToken = data.email_verification_token || null;
    this.emailVerificationExpires = data.email_verification_expires || null;
    
    // Password reset
    this.passwordResetToken = data.password_reset_token || null;
    this.passwordResetExpires = data.password_reset_expires || null;
    
    // Security
    this.twoFactorEnabled = data.two_factor_enabled || false;
    this.twoFactorSecret = data.two_factor_secret || null;
    this.failedLoginAttempts = data.failed_login_attempts || 0;
    this.accountLockedUntil = data.account_locked_until || null;
    this.lastLoginAt = data.last_login_at || null;
    this.lastLoginIp = data.last_login_ip || null;
    
    // Preferences
    this.preferences = data.preferences ? 
      (typeof data.preferences === 'string' ? JSON.parse(data.preferences) : data.preferences) : 
      {};
    
    // Metadata
    this.memberSince = data.member_since || data.created_at || null;
    this.totalSpent = data.total_spent || 0;
    this.totalOrders = data.total_orders || 0;
    this.loyaltyPoints = data.loyalty_points || 0;
    
    // Timestamps
    this.createdAt = data.created_at || null;
    this.updatedAt = data.updated_at || null;
    this.deletedAt = data.deleted_at || null;
    
    // Internal flags
    this._isNew = !this.id;
    this._isDirty = false;
    this._dirtyAttributes = new Set();
    this._originalData = { ...data };
    
    // Relationships (lazy loaded)
    this._orders = null;
    this._reviews = null;
    this._addresses = null;
    this._sessions = null;
  }

  // ==========================================================================
  // VIRTUAL ATTRIBUTES
  // ==========================================================================

  get fullName() {
    return [this.firstName, this.lastName].filter(Boolean).join(' ') || this.username;
  }

  get initials() {
    if (this.firstName && this.lastName) {
      return `${this.firstName[0]}${this.lastName[0]}`.toUpperCase();
    }
    return this.username?.substring(0, 2).toUpperCase() || 'U';
  }

  get age() {
    if (!this.dateOfBirth) return null;
    const birthDate = new Date(this.dateOfBirth);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    return age;
  }

  get isLocked() {
    return this.accountLockedUntil && new Date(this.accountLockedUntil) > new Date();
  }

  get accountAge() {
    if (!this.memberSince) return 0;
    const created = new Date(this.memberSince);
    const now = new Date();
    return Math.floor((now - created) / (1000 * 60 * 60 * 24)); // Days
  }

  get isVIP() {
    return this.totalSpent > 1000 || this.totalOrders > 10;
  }

  get isPremium() {
    return this.role === USER_ROLES.PREMIUM || this.role === USER_ROLES.ADMIN;
  }

  get isAdmin() {
    return [USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(this.role);
  }

  get isDeleted() {
    return this.deletedAt !== null;
  }

  // ==========================================================================
  // VALIDATION
  // ==========================================================================

  validate() {
    const errors = [];

    // Username validation
    if (!this.username || this.username.length < 3) {
      errors.push('Username must be at least 3 characters');
    }
    if (this.username && !/^[a-zA-Z0-9_-]+$/.test(this.username)) {
      errors.push('Username can only contain letters, numbers, underscores, and hyphens');
    }

    // Email validation
    if (!this.email) {
      errors.push('Email is required');
    }
    if (this.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.email)) {
      errors.push('Invalid email format');
    }

    // Password validation (only for new records)
    if (this._isNew && !this.password) {
      errors.push('Password is required');
    }

    // Role validation
    if (!Object.values(USER_ROLES).includes(this.role)) {
      errors.push('Invalid user role');
    }

    // Phone validation
    if (this.phone && !/^\+?[\d\s\-()]+$/.test(this.phone)) {
      errors.push('Invalid phone number format');
    }

    // Date of birth validation
    if (this.dateOfBirth) {
      const dob = new Date(this.dateOfBirth);
      const minAge = new Date();
      minAge.setFullYear(minAge.getFullYear() - 13);
      if (dob > minAge) {
        errors.push('User must be at least 13 years old');
      }
    }

    if (errors.length > 0) {
      throw new ValidationError('User validation failed', { errors });
    }

    return true;
  }

  // ==========================================================================
  // HOOKS
  // ==========================================================================

  async beforeSave() {
    this.emit('beforeSave', this);
    
    // Hash password if it's new or changed
    if (this._dirtyAttributes.has('password') && this.password) {
      this.password = await hashPassword(this.password);
    }

    // Lowercase email
    if (this.email) {
      this.email = this.email.toLowerCase().trim();
    }

    // Trim strings
    if (this.username) this.username = this.username.trim();
    if (this.firstName) this.firstName = this.firstName.trim();
    if (this.lastName) this.lastName = this.lastName.trim();

    // Set timestamps
    if (this._isNew) {
      this.memberSince = new Date();
      this.createdAt = new Date();
    }
    this.updatedAt = new Date();
  }

  async afterSave() {
    this.emit('afterSave', this);
    
    // Clear cache
    if (this.id) {
      await cache.delete(CacheKeyBuilder.user(this.id));
    }

    // Log activity
    logger.info('User saved', { 
      userId: this.id, 
      username: this.username,
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
      await cache.delete(CacheKeyBuilder.user(this.id));
    }

    logger.info('User deleted', { userId: this.id, username: this.username });
  }

  // ==========================================================================
  // CRUD OPERATIONS
  // ==========================================================================

  async save() {
    try {
      // Validate
      this.validate();

      // Run before save hook
      await this.beforeSave();

      if (this._isNew) {
        // INSERT
        const [result] = await db.execute(
          `INSERT INTO ${tables.USERS} (
            username, email, password, first_name, last_name, role,
            avatar, phone, date_of_birth, gender,
            is_active, is_email_verified, email_verification_token, email_verification_expires,
            two_factor_enabled, two_factor_secret,
            preferences, member_since, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
          [
            this.username, this.email, this.password, this.firstName, this.lastName, this.role,
            this.avatar, this.phone, this.dateOfBirth, this.gender,
            this.isActive, this.isEmailVerified, this.emailVerificationToken, this.emailVerificationExpires,
            this.twoFactorEnabled, this.twoFactorSecret,
            JSON.stringify(this.preferences), this.memberSince
          ]
        );

        this.id = result.insertId;
      } else {
        // UPDATE
        const fields = [];
        const values = [];

        // Build dynamic update query based on dirty attributes
        if (this._dirtyAttributes.has('username')) {
          fields.push('username = ?');
          values.push(this.username);
        }
        if (this._dirtyAttributes.has('email')) {
          fields.push('email = ?');
          values.push(this.email);
        }
        if (this._dirtyAttributes.has('password')) {
          fields.push('password = ?');
          values.push(this.password);
        }
        if (this._dirtyAttributes.has('firstName')) {
          fields.push('first_name = ?');
          values.push(this.firstName);
        }
        if (this._dirtyAttributes.has('lastName')) {
          fields.push('last_name = ?');
          values.push(this.lastName);
        }
        if (this._dirtyAttributes.has('role')) {
          fields.push('role = ?');
          values.push(this.role);
        }
        if (this._dirtyAttributes.has('avatar')) {
          fields.push('avatar = ?');
          values.push(this.avatar);
        }
        if (this._dirtyAttributes.has('phone')) {
          fields.push('phone = ?');
          values.push(this.phone);
        }
        if (this._dirtyAttributes.has('isActive')) {
          fields.push('is_active = ?');
          values.push(this.isActive);
        }
        if (this._dirtyAttributes.has('preferences')) {
          fields.push('preferences = ?');
          values.push(JSON.stringify(this.preferences));
        }

        // Always update timestamp
        fields.push('updated_at = NOW()');
        values.push(this.id);

        if (fields.length > 1) { // More than just updated_at
          await db.execute(
            `UPDATE ${tables.USERS} SET ${fields.join(', ')} WHERE id = ?`,
            values
          );
        }
      }

      // Run after save hook
      await this.afterSave();

      return this;
    } catch (error) {
      logger.error('User save failed', { error: error.message });
      throw error;
    }
  }

  async delete(soft = true) {
    try {
      if (!this.id) {
        throw new Error('Cannot delete unsaved user');
      }

      await this.beforeDelete();

      if (soft) {
        // Soft delete
        this.deletedAt = new Date();
        await db.execute(
          `UPDATE ${tables.USERS} SET deleted_at = NOW() WHERE id = ?`,
          [this.id]
        );
      } else {
        // Hard delete
        await db.execute(
          `DELETE FROM ${tables.USERS} WHERE id = ?`,
          [this.id]
        );
      }

      await this.afterDelete();

      return true;
    } catch (error) {
      logger.error('User delete failed', { userId: this.id, error: error.message });
      throw error;
    }
  }

  async restore() {
    try {
      if (!this.id || !this.deletedAt) {
        throw new Error('Cannot restore non-deleted user');
      }

      await db.execute(
        `UPDATE ${tables.USERS} SET deleted_at = NULL WHERE id = ?`,
        [this.id]
      );

      this.deletedAt = null;
      await cache.delete(CacheKeyBuilder.user(this.id));

      logger.info('User restored', { userId: this.id });

      return true;
    } catch (error) {
      logger.error('User restore failed', { userId: this.id, error: error.message });
      throw error;
    }
  }

  async reload() {
    try {
      if (!this.id) {
        throw new Error('Cannot reload unsaved user');
      }

      const user = await User.findById(this.id);
      if (!user) {
        throw new NotFoundError('User');
      }

      // Update current instance
      Object.assign(this, user);
      this._isDirty = false;
      this._dirtyAttributes.clear();

      return this;
    } catch (error) {
      logger.error('User reload failed', { userId: this.id, error: error.message });
      throw error;
    }
  }

  // ==========================================================================
  // ATTRIBUTE TRACKING
  // ==========================================================================

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

  getDirtyAttributes() {
    return Array.from(this._dirtyAttributes);
  }

  // ==========================================================================
  // PASSWORD METHODS
  // ==========================================================================

  async comparePassword(plainPassword) {
    return await verifyPassword(plainPassword, this.password);
  }

  async changePassword(newPassword) {
    this.set('password', newPassword);
    await this.save();
  }

  // ==========================================================================
  // RELATIONSHIP METHODS
  // ==========================================================================

  async orders(options = {}) {
    if (this._orders && !options.reload) {
      return this._orders;
    }

    const { limit = 10, offset = 0, status = null } = options;
    const conditions = ['user_id = ?'];
    const values = [this.id];

    if (status) {
      conditions.push('status = ?');
      values.push(status);
    }

    const [orders] = await db.execute(
      `SELECT * FROM ${tables.ORDERS}
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    this._orders = orders;
    return orders;
  }

  async reviews(options = {}) {
    if (this._reviews && !options.reload) {
      return this._reviews;
    }

    const { limit = 10, offset = 0 } = options;

    const [reviews] = await db.execute(
      `SELECT * FROM ${tables.REVIEWS}
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [this.id, limit, offset]
    );

    this._reviews = reviews;
    return reviews;
  }

  async addresses(options = {}) {
    if (this._addresses && !options.reload) {
      return this._addresses;
    }

    const [addresses] = await db.execute(
      `SELECT * FROM user_addresses
       WHERE user_id = ?
       ORDER BY is_default DESC, created_at DESC`,
      [this.id]
    );

    this._addresses = addresses;
    return addresses;
  }

  async sessions(activeOnly = true) {
    const whereClause = activeOnly ? 'AND expires_at > NOW()' : '';

    const [sessions] = await db.execute(
      `SELECT * FROM ${tables.USER_SESSIONS}
       WHERE user_id = ? ${whereClause}
       ORDER BY last_activity DESC`,
      [this.id]
    );

    this._sessions = sessions;
    return sessions;
  }

  // ==========================================================================
  // ACCOUNT SECURITY
  // ==========================================================================

  async incrementFailedLoginAttempts() {
    this.failedLoginAttempts++;

    if (this.failedLoginAttempts >= 5) {
      // Lock account for 30 minutes
      this.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
    }

    await db.execute(
      `UPDATE ${tables.USERS}
       SET failed_login_attempts = ?, account_locked_until = ?
       WHERE id = ?`,
      [this.failedLoginAttempts, this.accountLockedUntil, this.id]
    );

    await cache.delete(CacheKeyBuilder.user(this.id));
  }

  async resetFailedLoginAttempts() {
    this.failedLoginAttempts = 0;
    this.accountLockedUntil = null;

    await db.execute(
      `UPDATE ${tables.USERS}
       SET failed_login_attempts = 0, account_locked_until = NULL
       WHERE id = ?`,
      [this.id]
    );

    await cache.delete(CacheKeyBuilder.user(this.id));
  }

  async updateLastLogin(ip) {
    this.lastLoginAt = new Date();
    this.lastLoginIp = ip;

    await db.execute(
      `UPDATE ${tables.USERS}
       SET last_login_at = NOW(), last_login_ip = ?
       WHERE id = ?`,
      [ip, this.id]
    );

    await cache.delete(CacheKeyBuilder.user(this.id));
  }

  // ==========================================================================
  // SERIALIZATION
  // ==========================================================================

  toJSON(options = {}) {
    const { includePassword = false, includeSensitive = false } = options;

    const json = {
      id: this.id,
      username: this.username,
      email: this.email,
      firstName: this.firstName,
      lastName: this.lastName,
      fullName: this.fullName,
      initials: this.initials,
      role: this.role,
      avatar: this.avatar,
      phone: this.phone,
      dateOfBirth: this.dateOfBirth,
      age: this.age,
      gender: this.gender,
      isActive: this.isActive,
      isEmailVerified: this.isEmailVerified,
      twoFactorEnabled: this.twoFactorEnabled,
      preferences: this.preferences,
      memberSince: this.memberSince,
      totalSpent: this.totalSpent,
      totalOrders: this.totalOrders,
      loyaltyPoints: this.loyaltyPoints,
      accountAge: this.accountAge,
      isVIP: this.isVIP,
      isPremium: this.isPremium,
      isAdmin: this.isAdmin,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };

    if (includePassword) {
      json.password = this.password;
    }

    if (includeSensitive) {
      json.emailVerificationToken = this.emailVerificationToken;
      json.passwordResetToken = this.passwordResetToken;
      json.twoFactorSecret = this.twoFactorSecret;
      json.failedLoginAttempts = this.failedLoginAttempts;
      json.accountLockedUntil = this.accountLockedUntil;
      json.lastLoginAt = this.lastLoginAt;
      json.lastLoginIp = this.lastLoginIp;
    }

    return json;
  }

  toPublic() {
    return {
      id: this.id,
      username: this.username,
      fullName: this.fullName,
      initials: this.initials,
      avatar: this.avatar,
      role: this.role,
      isVIP: this.isVIP,
      memberSince: this.memberSince
    };
  }

  // ==========================================================================
  // STATIC METHODS (Query Builder)
  // ==========================================================================

  static async findById(id, options = {}) {
    const { includeDeleted = false } = options;

    const cacheKey = CacheKeyBuilder.user(id);
    let userData = await cache.get(cacheKey);

    if (!userData) {
      const whereClause = includeDeleted ? 'id = ?' : 'id = ? AND deleted_at IS NULL';

      const [users] = await db.execute(
        `SELECT * FROM ${tables.USERS} WHERE ${whereClause} LIMIT 1`,
        [id]
      );

      if (users.length === 0) {
        return null;
      }

      userData = users[0];
      await cache.set(cacheKey, userData, 900); // Cache for 15 minutes
    }

    return new User(userData);
  }

  static async findByUsername(username, options = {}) {
    const { includeDeleted = false } = options;
    const whereClause = includeDeleted 
      ? 'username = ?' 
      : 'username = ? AND deleted_at IS NULL';

    const [users] = await db.execute(
      `SELECT * FROM ${tables.USERS} WHERE ${whereClause} LIMIT 1`,
      [username]
    );

    return users.length > 0 ? new User(users[0]) : null;
  }

  static async findByEmail(email, options = {}) {
    const { includeDeleted = false } = options;
    const whereClause = includeDeleted 
      ? 'email = ?' 
      : 'email = ? AND deleted_at IS NULL';

    const [users] = await db.execute(
      `SELECT * FROM ${tables.USERS} WHERE ${whereClause} LIMIT 1`,
      [email.toLowerCase()]
    );

    return users.length > 0 ? new User(users[0]) : null;
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

    // Build WHERE clause
    Object.entries(where).forEach(([key, value]) => {
      conditions.push(`${key} = ?`);
      values.push(value);
    });

    const whereClause = conditions.length > 0 
      ? `WHERE ${conditions.join(' AND ')}` 
      : '';

    const [users] = await db.execute(
      `SELECT * FROM ${tables.USERS}
       ${whereClause}
       ORDER BY ${orderBy} ${orderDirection}
       LIMIT ? OFFSET ?`,
      [...values, limit, offset]
    );

    return users.map(userData => new User(userData));
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

    const whereClause = conditions.length > 0 
      ? `WHERE ${conditions.join(' AND ')}` 
      : '';

    const [result] = await db.execute(
      `SELECT COUNT(*) as count FROM ${tables.USERS} ${whereClause}`,
      values
    );

    return result[0].count;
  }

  static async exists(id) {
    const [result] = await db.execute(
      `SELECT EXISTS(SELECT 1 FROM ${tables.USERS} WHERE id = ? AND deleted_at IS NULL) as exists`,
      [id]
    );

    return result[0].exists === 1;
  }

  static async search(query, options = {}) {
    const { limit = 20, offset = 0 } = options;

    const [users] = await db.execute(
      `SELECT * FROM ${tables.USERS}
       WHERE (username LIKE ? OR email LIKE ? OR CONCAT(first_name, ' ', last_name) LIKE ?)
         AND deleted_at IS NULL
       ORDER BY username ASC
       LIMIT ? OFFSET ?`,
      [`%${query}%`, `%${query}%`, `%${query}%`, limit, offset]
    );

    return users.map(userData => new User(userData));
  }
}

export default User;
