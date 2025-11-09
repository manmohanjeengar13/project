-- ============================================================================
-- SQLi Demo Platform - Military-Grade Database Schema
-- ============================================================================
-- Version: 3.0.0
-- Database: MySQL 8.0+ / MariaDB 10.5+
-- Encoding: UTF8MB4
-- Collation: utf8mb4_unicode_ci
-- 
-- ENTERPRISE FEATURES:
-- - Full ACID compliance
-- - Optimized indexes for performance
-- - Foreign key constraints with cascading
-- - Triggers for audit trails
-- - Stored procedures for complex operations
-- - Views for common queries
-- - Partitioning support for large tables
-- - Full-text search indexes
-- - JSON column support
-- - Spatial data support
-- - Row-level security ready
-- 
-- SECURITY FEATURES:
-- - Encrypted sensitive fields
-- - Audit logging on all tables
-- - Soft delete support
-- - IP tracking and geolocation
-- - Failed login attempt tracking
-- - Session management
-- - API key management
-- - Role-based access control
-- 
-- @author Security Engineering Team
-- @license MIT
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';
SET time_zone = '+00:00';

-- ============================================================================
-- DATABASE SETUP
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `sqli_demo_platform` 
DEFAULT CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE `sqli_demo_platform`;

-- ============================================================================
-- TABLE: users
-- Core user accounts with authentication and profile data
-- ============================================================================

DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Authentication Credentials
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL COMMENT 'Bcrypt hashed password',
  
  -- Personal Information
  `first_name` VARCHAR(100) DEFAULT NULL,
  `last_name` VARCHAR(100) DEFAULT NULL,
  `full_name` VARCHAR(200) GENERATED ALWAYS AS (CONCAT(IFNULL(first_name, ''), ' ', IFNULL(last_name, ''))) STORED,
  `date_of_birth` DATE DEFAULT NULL,
  `gender` ENUM('male', 'female', 'other', 'prefer_not_to_say') DEFAULT NULL,
  `phone` VARCHAR(20) DEFAULT NULL,
  `avatar` VARCHAR(500) DEFAULT NULL,
  
  -- Address Information
  `address_line1` VARCHAR(255) DEFAULT NULL,
  `address_line2` VARCHAR(255) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `state` VARCHAR(100) DEFAULT NULL,
  `postal_code` VARCHAR(20) DEFAULT NULL,
  `country` VARCHAR(2) DEFAULT 'US' COMMENT 'ISO 3166-1 alpha-2',
  
  -- Account Status & Role
  `role` ENUM('customer', 'moderator', 'admin', 'super_admin') NOT NULL DEFAULT 'customer',
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_email_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_phone_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Email Verification
  `email_verification_token` VARCHAR(64) DEFAULT NULL,
  `email_verification_expires` DATETIME DEFAULT NULL,
  `email_verified_at` DATETIME DEFAULT NULL,
  
  -- Password Reset
  `password_reset_token` VARCHAR(64) DEFAULT NULL,
  `password_reset_expires` DATETIME DEFAULT NULL,
  `password_changed_at` DATETIME DEFAULT NULL,
  
  -- Two-Factor Authentication
  `two_factor_enabled` BOOLEAN NOT NULL DEFAULT FALSE,
  `two_factor_secret` VARCHAR(32) DEFAULT NULL,
  `two_factor_recovery_codes` JSON DEFAULT NULL COMMENT 'Encrypted backup codes',
  
  -- Security & Login Tracking
  `failed_login_attempts` INT UNSIGNED NOT NULL DEFAULT 0,
  `account_locked_until` DATETIME DEFAULT NULL,
  `last_login_at` DATETIME DEFAULT NULL,
  `last_login_ip` VARCHAR(45) DEFAULT NULL COMMENT 'IPv6 compatible',
  `last_login_user_agent` VARCHAR(500) DEFAULT NULL,
  `login_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  
  -- User Preferences & Settings
  `preferences` JSON DEFAULT NULL COMMENT 'User settings and preferences',
  `timezone` VARCHAR(50) DEFAULT 'UTC',
  `locale` VARCHAR(10) DEFAULT 'en_US',
  `currency` VARCHAR(3) DEFAULT 'USD',
  `notification_preferences` JSON DEFAULT NULL,
  
  -- E-commerce Metrics
  `member_since` DATETIME DEFAULT NULL,
  `total_spent` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `total_orders` INT UNSIGNED NOT NULL DEFAULT 0,
  `loyalty_points` INT UNSIGNED NOT NULL DEFAULT 0,
  `customer_tier` ENUM('bronze', 'silver', 'gold', 'platinum', 'diamond') DEFAULT 'bronze',
  
  -- API Access
  `api_access_enabled` BOOLEAN NOT NULL DEFAULT FALSE,
  `api_rate_limit` INT UNSIGNED DEFAULT 60 COMMENT 'Requests per minute',
  
  -- Referral System
  `referral_code` VARCHAR(20) UNIQUE DEFAULT NULL,
  `referred_by` BIGINT UNSIGNED DEFAULT NULL,
  `referral_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `referral_earnings` DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
  
  -- Metadata & Audit
  `metadata` JSON DEFAULT NULL COMMENT 'Additional flexible data',
  `notes` TEXT DEFAULT NULL COMMENT 'Admin notes about user',
  `tags` JSON DEFAULT NULL COMMENT 'User classification tags',
  
  -- Soft Delete Support
  `deleted_at` DATETIME DEFAULT NULL,
  `deleted_by` BIGINT UNSIGNED DEFAULT NULL,
  `deletion_reason` VARCHAR(255) DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_username` (`username`),
  UNIQUE KEY `idx_email` (`email`),
  UNIQUE KEY `idx_referral_code` (`referral_code`),
  KEY `idx_role` (`role`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_email_verified` (`is_email_verified`),
  KEY `idx_deleted_at` (`deleted_at`),
  KEY `idx_last_login` (`last_login_at`),
  KEY `idx_customer_tier` (`customer_tier`),
  KEY `idx_referred_by` (`referred_by`),
  KEY `idx_full_name` (`full_name`),
  FULLTEXT KEY `idx_search` (`username`, `email`, `first_name`, `last_name`),
  
  CONSTRAINT `fk_users_referred_by` FOREIGN KEY (`referred_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_users_deleted_by` FOREIGN KEY (`deleted_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    
  CONSTRAINT `chk_email_format` CHECK (`email` REGEXP '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$'),
  CONSTRAINT `chk_username_length` CHECK (CHAR_LENGTH(`username`) >= 3),
  CONSTRAINT `chk_failed_attempts` CHECK (`failed_login_attempts` >= 0),
  CONSTRAINT `chk_loyalty_points` CHECK (`loyalty_points` >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User accounts with full authentication';

-- ============================================================================
-- TABLE: user_sessions
-- Active user sessions for JWT refresh tokens and session management
-- ============================================================================

DROP TABLE IF EXISTS `user_sessions`;

CREATE TABLE `user_sessions` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Session Data
  `session_token` VARCHAR(255) NOT NULL UNIQUE COMMENT 'Hashed session identifier',
  `refresh_token` VARCHAR(500) NOT NULL UNIQUE COMMENT 'JWT refresh token',
  `access_token_hash` VARCHAR(64) DEFAULT NULL COMMENT 'Hash of current access token',
  
  -- Client Information
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) NOT NULL,
  `device_type` ENUM('desktop', 'mobile', 'tablet', 'other') DEFAULT 'other',
  `browser` VARCHAR(50) DEFAULT NULL,
  `operating_system` VARCHAR(50) DEFAULT NULL,
  `device_fingerprint` VARCHAR(64) DEFAULT NULL COMMENT 'Unique device identifier',
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `latitude` DECIMAL(10, 8) DEFAULT NULL,
  `longitude` DECIMAL(11, 8) DEFAULT NULL,
  
  -- Session Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `last_activity` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` DATETIME NOT NULL,
  `revoked_at` DATETIME DEFAULT NULL,
  `revoked_reason` VARCHAR(255) DEFAULT NULL,
  
  -- Security Flags
  `is_suspicious` BOOLEAN NOT NULL DEFAULT FALSE,
  `risk_score` TINYINT UNSIGNED DEFAULT 0 COMMENT '0-100 risk score',
  `mfa_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_session_token` (`session_token`),
  UNIQUE KEY `idx_refresh_token` (`refresh_token`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_expires_at` (`expires_at`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_last_activity` (`last_activity`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_device_fingerprint` (`device_fingerprint`),
  
  CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    
  CONSTRAINT `chk_risk_score` CHECK (`risk_score` BETWEEN 0 AND 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User session management';

-- ============================================================================
-- TABLE: categories
-- Product categories with hierarchical support
-- ============================================================================

DROP TABLE IF EXISTS `categories`;

CREATE TABLE `categories` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `parent_id` INT UNSIGNED DEFAULT NULL COMMENT 'Hierarchical category support',
  
  -- Category Information
  `name` VARCHAR(100) NOT NULL,
  `slug` VARCHAR(120) NOT NULL UNIQUE,
  `description` TEXT DEFAULT NULL,
  `icon` VARCHAR(100) DEFAULT NULL,
  `image` VARCHAR(500) DEFAULT NULL,
  `banner` VARCHAR(500) DEFAULT NULL,
  
  -- SEO
  `meta_title` VARCHAR(200) DEFAULT NULL,
  `meta_description` VARCHAR(500) DEFAULT NULL,
  `meta_keywords` VARCHAR(500) DEFAULT NULL,
  
  -- Display & Organization
  `sort_order` INT NOT NULL DEFAULT 0,
  `level` TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Tree depth level',
  `path` VARCHAR(500) DEFAULT NULL COMMENT 'Full path from root',
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Statistics
  `product_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `view_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_slug` (`slug`),
  KEY `idx_parent_id` (`parent_id`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_sort_order` (`sort_order`),
  KEY `idx_level` (`level`),
  KEY `idx_featured` (`is_featured`),
  FULLTEXT KEY `idx_search` (`name`, `description`),
  
  CONSTRAINT `fk_categories_parent` FOREIGN KEY (`parent_id`) 
    REFERENCES `categories` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    
  CONSTRAINT `chk_level` CHECK (`level` <= 10)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Product categories';

-- ============================================================================
-- TABLE: products
-- Product catalog with variants and inventory management
-- ============================================================================

DROP TABLE IF EXISTS `products`;

CREATE TABLE `products` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `category_id` INT UNSIGNED NOT NULL,
  
  -- Basic Information
  `sku` VARCHAR(50) NOT NULL UNIQUE COMMENT 'Stock Keeping Unit',
  `name` VARCHAR(255) NOT NULL,
  `slug` VARCHAR(300) NOT NULL UNIQUE,
  `description` TEXT DEFAULT NULL,
  `short_description` VARCHAR(500) DEFAULT NULL,
  
  -- Pricing
  `base_price` DECIMAL(15, 2) NOT NULL,
  `sale_price` DECIMAL(15, 2) DEFAULT NULL,
  `cost_price` DECIMAL(15, 2) DEFAULT NULL COMMENT 'Internal cost',
  `currency` VARCHAR(3) NOT NULL DEFAULT 'USD',
  `tax_rate` DECIMAL(5, 2) NOT NULL DEFAULT 0.00 COMMENT 'Tax percentage',
  
  -- Inventory
  `stock_quantity` INT NOT NULL DEFAULT 0,
  `low_stock_threshold` INT NOT NULL DEFAULT 10,
  `track_inventory` BOOLEAN NOT NULL DEFAULT TRUE,
  `allow_backorder` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_in_stock` BOOLEAN GENERATED ALWAYS AS (`stock_quantity` > 0 OR `allow_backorder` = TRUE) STORED,
  
  -- Physical Attributes
  `weight` DECIMAL(10, 2) DEFAULT NULL COMMENT 'Weight in kg',
  `length` DECIMAL(10, 2) DEFAULT NULL COMMENT 'Length in cm',
  `width` DECIMAL(10, 2) DEFAULT NULL COMMENT 'Width in cm',
  `height` DECIMAL(10, 2) DEFAULT NULL COMMENT 'Height in cm',
  
  -- Product Status
  `status` ENUM('draft', 'pending', 'active', 'inactive', 'out_of_stock', 'discontinued') NOT NULL DEFAULT 'draft',
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_bestseller` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_new_arrival` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_digital` BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Digital/downloadable product',
  
  -- Media
  `main_image` VARCHAR(500) DEFAULT NULL,
  `images` JSON DEFAULT NULL COMMENT 'Array of image URLs',
  `video_url` VARCHAR(500) DEFAULT NULL,
  `files` JSON DEFAULT NULL COMMENT 'Downloadable files for digital products',
  
  -- SEO
  `meta_title` VARCHAR(200) DEFAULT NULL,
  `meta_description` VARCHAR(500) DEFAULT NULL,
  `meta_keywords` VARCHAR(500) DEFAULT NULL,
  `canonical_url` VARCHAR(500) DEFAULT NULL,
  
  -- Rating & Reviews
  `rating_average` DECIMAL(3, 2) NOT NULL DEFAULT 0.00,
  `rating_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `review_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Sales & Views
  `view_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `sale_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `wishlist_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `cart_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Attributes & Specifications
  `attributes` JSON DEFAULT NULL COMMENT 'Product attributes (color, size, etc)',
  `specifications` JSON DEFAULT NULL COMMENT 'Technical specifications',
  `tags` JSON DEFAULT NULL COMMENT 'Product tags',
  
  -- Dates
  `available_from` DATETIME DEFAULT NULL,
  `available_until` DATETIME DEFAULT NULL,
  `featured_until` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` DATETIME DEFAULT NULL,
  `created_by` BIGINT UNSIGNED DEFAULT NULL,
  `updated_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_sku` (`sku`),
  UNIQUE KEY `idx_slug` (`slug`),
  KEY `idx_category` (`category_id`),
  KEY `idx_status` (`status`),
  KEY `idx_featured` (`is_featured`),
  KEY `idx_price` (`base_price`),
  KEY `idx_stock` (`stock_quantity`),
  KEY `idx_rating` (`rating_average`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_is_in_stock` (`is_in_stock`),
  KEY `idx_bestseller` (`is_bestseller`),
  FULLTEXT KEY `idx_search` (`name`, `description`, `short_description`, `sku`),
  
  CONSTRAINT `fk_products_category` FOREIGN KEY (`category_id`) 
    REFERENCES `categories` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `fk_products_created_by` FOREIGN KEY (`created_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_products_updated_by` FOREIGN KEY (`updated_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    
  CONSTRAINT `chk_price_positive` CHECK (`base_price` >= 0),
  CONSTRAINT `chk_sale_price` CHECK (`sale_price` IS NULL OR `sale_price` < `base_price`),
  CONSTRAINT `chk_rating_range` CHECK (`rating_average` BETWEEN 0 AND 5),
  CONSTRAINT `chk_tax_rate` CHECK (`tax_rate` >= 0 AND `tax_rate` <= 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Product catalog';

-- Partitioning for large product tables (optional, commented out)
-- PARTITION BY RANGE (YEAR(created_at)) (
--   PARTITION p2023 VALUES LESS THAN (2024),
--   PARTITION p2024 VALUES LESS THAN (2025),
--   PARTITION p2025 VALUES LESS THAN (2026),
--   PARTITION pfuture VALUES LESS THAN MAXVALUE
-- );

-- ============================================================================
-- TABLE: reviews
-- Product reviews and ratings with moderation support
-- ============================================================================

DROP TABLE IF EXISTS `reviews`;

CREATE TABLE `reviews` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `product_id` BIGINT UNSIGNED NOT NULL,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `order_id` BIGINT UNSIGNED DEFAULT NULL COMMENT 'Verified purchase',
  
  -- Review Content
  `title` VARCHAR(200) NOT NULL,
  `comment` TEXT NOT NULL,
  `rating` TINYINT UNSIGNED NOT NULL COMMENT '1-5 stars',
  
  -- Helpful Votes
  `helpful_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `not_helpful_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `report_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Media Attachments
  `images` JSON DEFAULT NULL COMMENT 'Review images',
  `videos` JSON DEFAULT NULL COMMENT 'Review videos',
  
  -- Review Status
  `status` ENUM('pending', 'approved', 'rejected', 'spam', 'flagged') NOT NULL DEFAULT 'pending',
  `is_verified_purchase` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Moderation
  `moderated_by` BIGINT UNSIGNED DEFAULT NULL,
  `moderated_at` DATETIME DEFAULT NULL,
  `moderation_reason` VARCHAR(500) DEFAULT NULL,
  
  -- Response from seller/admin
  `has_response` BOOLEAN NOT NULL DEFAULT FALSE,
  `response_text` TEXT DEFAULT NULL,
  `response_by` BIGINT UNSIGNED DEFAULT NULL,
  `response_at` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_product` (`product_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_order` (`order_id`),
  KEY `idx_rating` (`rating`),
  KEY `idx_status` (`status`),
  KEY `idx_verified_purchase` (`is_verified_purchase`),
  KEY `idx_created_at` (`created_at`),
  FULLTEXT KEY `idx_search` (`title`, `comment`),
  
  CONSTRAINT `fk_reviews_product` FOREIGN KEY (`product_id`) 
    REFERENCES `products` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_reviews_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_reviews_moderated_by` FOREIGN KEY (`moderated_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_reviews_response_by` FOREIGN KEY (`response_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    
  CONSTRAINT `chk_rating_value` CHECK (`rating` BETWEEN 1 AND 5),
  CONSTRAINT `chk_comment_length` CHECK (CHAR_LENGTH(`comment`) >= 10),
  
  -- Prevent duplicate reviews
  UNIQUE KEY `idx_unique_review` (`product_id`, `user_id`, `deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Product reviews';

-- ============================================================================
-- TABLE: orders
-- Order management with comprehensive tracking
-- ============================================================================

DROP TABLE IF EXISTS `orders`;

CREATE TABLE `orders` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Order Identification
  `order_number` VARCHAR(50) NOT NULL UNIQUE COMMENT 'Human-readable order ID',
  `invoice_number` VARCHAR(50) DEFAULT NULL UNIQUE,
  
  -- Order Status
  `status` ENUM('pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded', 'failed') NOT NULL DEFAULT 'pending',
  `payment_status` ENUM('pending', 'paid', 'failed', 'refunded', 'partially_refunded') NOT NULL DEFAULT 'pending',
  `fulfillment_status` ENUM('unfulfilled', 'partial', 'fulfilled') NOT NULL DEFAULT 'unfulfilled',
  
  -- Financial Details
  `subtotal` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `tax_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `shipping_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `discount_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `total_amount` DECIMAL(15, 2) NOT NULL,
  `currency` VARCHAR(3) NOT NULL DEFAULT 'USD',
  
  -- Coupon & Discounts
  `coupon_code` VARCHAR(50) DEFAULT NULL,
  `coupon_discount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `loyalty_points_used` INT UNSIGNED NOT NULL DEFAULT 0,
  `loyalty_points_earned` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Payment Information
  `payment_method` VARCHAR(50) NOT NULL,
  `payment_gateway` VARCHAR(50) DEFAULT NULL,
  `transaction_id` VARCHAR(100) DEFAULT NULL,
  `payment_details` JSON DEFAULT NULL COMMENT 'Encrypted payment info',
  `paid_at` DATETIME DEFAULT NULL,
  
  -- Shipping Information
  `shipping_method` VARCHAR(50) DEFAULT NULL,
  `shipping_provider` VARCHAR(50) DEFAULT NULL,
  `tracking_number` VARCHAR(100) DEFAULT NULL,
  `tracking_url` VARCHAR(500) DEFAULT NULL,
  `estimated_delivery` DATE DEFAULT NULL,
  `shipped_at` DATETIME DEFAULT NULL,
  `delivered_at` DATETIME DEFAULT NULL,
  
  -- Shipping Address
  `shipping_first_name` VARCHAR(100) NOT NULL,
  `shipping_last_name` VARCHAR(100) NOT NULL,
  `shipping_email` VARCHAR(255) NOT NULL,
  `shipping_phone` VARCHAR(20) NOT NULL,
  `shipping_address_line1` VARCHAR(255) NOT NULL,
  `shipping_address_line2` VARCHAR(255) DEFAULT NULL,
  `shipping_city` VARCHAR(100) NOT NULL,
  `shipping_state` VARCHAR(100) NOT NULL,
  `shipping_postal_code` VARCHAR(20) NOT NULL,
  `shipping_country` VARCHAR(2) NOT NULL,
  
  -- Billing Address
  `billing_first_name` VARCHAR(100) NOT NULL,
  `billing_last_name` VARCHAR(100) NOT NULL,
  `billing_email` VARCHAR(255) NOT NULL,
  `billing_phone` VARCHAR(20) NOT NULL,
  `billing_address_line1` VARCHAR(255) NOT NULL,
  `billing_address_line2` VARCHAR(255) DEFAULT NULL,
  `billing_city` VARCHAR(100) NOT NULL,
  `billing_state` VARCHAR(100) NOT NULL,
  `billing_postal_code` VARCHAR(20) NOT NULL,
  `billing_country` VARCHAR(2) NOT NULL,
  
  -- Additional Information
  `customer_notes` TEXT DEFAULT NULL,
  `admin_notes` TEXT DEFAULT NULL,
  `internal_notes` TEXT DEFAULT NULL,
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  
  -- Refund Information
  `refund_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `refund_reason` VARCHAR(500) DEFAULT NULL,
  `refunded_at` DATETIME DEFAULT NULL,
  `refunded_by` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Cancellation Information
  `cancelled_at` DATETIME DEFAULT NULL,
  `cancelled_by` BIGINT UNSIGNED DEFAULT NULL,
  `cancellation_reason` VARCHAR(500) DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `completed_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_order_number` (`order_number`),
  UNIQUE KEY `idx_invoice_number` (`invoice_number`),
  KEY `idx_user` (`user_id`),
  KEY `idx_status` (`status`),
  KEY `idx_payment_status` (`payment_status`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_transaction_id` (`transaction_id`),
  KEY `idx_tracking_number` (`tracking_number`),
  KEY `idx_total_amount` (`total_amount`),
  
  CONSTRAINT `fk_orders_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `fk_orders_refunded_by` FOREIGN KEY (`refunded_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_orders_cancelled_by` FOREIGN KEY (`cancelled_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    
  CONSTRAINT `chk_amounts_positive` CHECK (
    `subtotal` >= 0 AND 
    `tax_amount` >= 0 AND 
    `shipping_amount` >= 0 AND 
    `discount_amount` >= 0 AND 
    `total_amount` >= 0
  ),
  CONSTRAINT `chk_refund_amount` CHECK (`refund_amount` <= `total_amount`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Customer orders';

-- ============================================================================
-- TABLE: order_items
-- Individual items within orders
-- ============================================================================

DROP TABLE IF EXISTS `order_items`;

CREATE TABLE `order_items` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `order_id` BIGINT UNSIGNED NOT NULL,
  `product_id` BIGINT UNSIGNED NOT NULL,
  
  -- Product Details (snapshot at time of order)
  `product_name` VARCHAR(255) NOT NULL,
  `product_sku` VARCHAR(50) NOT NULL,
  `product_image` VARCHAR(500) DEFAULT NULL,
  
  -- Pricing
  `unit_price` DECIMAL(15, 2) NOT NULL,
  `quantity` INT UNSIGNED NOT NULL DEFAULT 1,
  `subtotal` DECIMAL(15, 2) NOT NULL,
  `tax_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `discount_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `total_amount` DECIMAL(15, 2) NOT NULL,
  
  -- Product Attributes
  `attributes` JSON DEFAULT NULL COMMENT 'Selected variant (color, size, etc)',
  `customization` JSON DEFAULT NULL COMMENT 'Custom options',
  
  -- Fulfillment
  `fulfillment_status` ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') NOT NULL DEFAULT 'pending',
  `shipped_quantity` INT UNSIGNED NOT NULL DEFAULT 0,
  `refunded_quantity` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_order` (`order_id`),
  KEY `idx_product` (`product_id`),
  KEY `idx_fulfillment` (`fulfillment_status`),
  
  CONSTRAINT `fk_order_items_order` FOREIGN KEY (`order_id`) 
    REFERENCES `orders` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_order_items_product` FOREIGN KEY (`product_id`) 
    REFERENCES `products` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
    
  CONSTRAINT `chk_quantity_positive` CHECK (`quantity` > 0),
  CONSTRAINT `chk_amounts_positive` CHECK (
    `unit_price` >= 0 AND 
    `subtotal` >= 0 AND 
    `total_amount` >= 0
  ),
  CONSTRAINT `chk_shipped_quantity` CHECK (`shipped_quantity` <= `quantity`),
  CONSTRAINT `chk_refunded_quantity` CHECK (`refunded_quantity` <= `quantity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Order line items';

-- ============================================================================
-- TABLE: coupons
-- Discount coupons and promotional codes
-- ============================================================================

DROP TABLE IF EXISTS `coupons`;

CREATE TABLE `coupons` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Coupon Identification
  `code` VARCHAR(50) NOT NULL UNIQUE,
  `name` VARCHAR(200) NOT NULL,
  `description` TEXT DEFAULT NULL,
  
  -- Discount Configuration
  `discount_type` ENUM('percentage', 'fixed_amount', 'free_shipping', 'buy_x_get_y') NOT NULL,
  `discount_value` DECIMAL(10, 2) NOT NULL,
  `max_discount_amount` DECIMAL(10, 2) DEFAULT NULL COMMENT 'Cap for percentage discounts',
  
  -- Usage Restrictions
  `min_purchase_amount` DECIMAL(10, 2) DEFAULT NULL,
  `max_purchase_amount` DECIMAL(10, 2) DEFAULT NULL,
  `usage_limit` INT UNSIGNED DEFAULT NULL COMMENT 'Total usage limit',
  `usage_limit_per_user` INT UNSIGNED DEFAULT 1,
  `usage_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Applicable Products/Categories
  `applies_to` ENUM('all', 'specific_products', 'specific_categories') NOT NULL DEFAULT 'all',
  `product_ids` JSON DEFAULT NULL COMMENT 'Array of product IDs',
  `category_ids` JSON DEFAULT NULL COMMENT 'Array of category IDs',
  `excluded_product_ids` JSON DEFAULT NULL,
  `excluded_category_ids` JSON DEFAULT NULL,
  
  -- Customer Restrictions
  `customer_eligibility` ENUM('all', 'new_customers', 'existing_customers', 'specific_users') NOT NULL DEFAULT 'all',
  `eligible_user_ids` JSON DEFAULT NULL,
  `min_loyalty_points` INT UNSIGNED DEFAULT NULL,
  `required_customer_tier` ENUM('bronze', 'silver', 'gold', 'platinum', 'diamond') DEFAULT NULL,
  
  -- Date Restrictions
  `valid_from` DATETIME DEFAULT NULL,
  `valid_until` DATETIME DEFAULT NULL,
  `active_days` JSON DEFAULT NULL COMMENT 'Array of day numbers (0-6)',
  `active_hours_start` TIME DEFAULT NULL,
  `active_hours_end` TIME DEFAULT NULL,
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_combinable` BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Can be used with other coupons',
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_code` (`code`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_valid_from` (`valid_from`),
  KEY `idx_valid_until` (`valid_until`),
  KEY `idx_discount_type` (`discount_type`),
  
  CONSTRAINT `fk_coupons_created_by` FOREIGN KEY (`created_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    
  CONSTRAINT `chk_discount_value` CHECK (`discount_value` > 0),
  CONSTRAINT `chk_date_range` CHECK (`valid_until` IS NULL OR `valid_until` >= `valid_from`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Promotional coupons';

-- ============================================================================
-- TABLE: coupon_usage
-- Track coupon usage by customers
-- ============================================================================

DROP TABLE IF EXISTS `coupon_usage`;

CREATE TABLE `coupon_usage` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `coupon_id` INT UNSIGNED NOT NULL,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `order_id` BIGINT UNSIGNED NOT NULL,
  
  -- Usage Details
  `discount_amount` DECIMAL(10, 2) NOT NULL,
  `order_amount` DECIMAL(10, 2) NOT NULL,
  
  -- Timestamps
  `used_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_coupon` (`coupon_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_order` (`order_id`),
  KEY `idx_used_at` (`used_at`),
  
  CONSTRAINT `fk_coupon_usage_coupon` FOREIGN KEY (`coupon_id`) 
    REFERENCES `coupons` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_coupon_usage_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_coupon_usage_order` FOREIGN KEY (`order_id`) 
    REFERENCES `orders` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Coupon usage tracking';

-- ============================================================================
-- TABLE: cart_items
-- Shopping cart items
-- ============================================================================

DROP TABLE IF EXISTS `cart_items`;

CREATE TABLE `cart_items` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL COMMENT 'NULL for guest carts',
  `session_id` VARCHAR(100) DEFAULT NULL COMMENT 'For guest users',
  `product_id` BIGINT UNSIGNED NOT NULL,
  
  -- Cart Details
  `quantity` INT UNSIGNED NOT NULL DEFAULT 1,
  `unit_price` DECIMAL(15, 2) NOT NULL,
  `attributes` JSON DEFAULT NULL COMMENT 'Selected variant',
  `customization` JSON DEFAULT NULL,
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `saved_for_later` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `expires_at` DATETIME DEFAULT NULL COMMENT 'Cart expiration',
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_session` (`session_id`),
  KEY `idx_product` (`product_id`),
  KEY `idx_expires_at` (`expires_at`),
  
  CONSTRAINT `fk_cart_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_cart_product` FOREIGN KEY (`product_id`) 
    REFERENCES `products` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    
  CONSTRAINT `chk_cart_quantity` CHECK (`quantity` > 0),
  CONSTRAINT `chk_cart_identifier` CHECK (`user_id` IS NOT NULL OR `session_id` IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Shopping cart';

-- ============================================================================
-- TABLE: wishlists
-- User wish lists
-- ============================================================================

DROP TABLE IF EXISTS `wishlists`;

CREATE TABLE `wishlists` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `product_id` BIGINT UNSIGNED NOT NULL,
  
  -- Wishlist Details
  `priority` TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '1-5 priority',
  `notes` TEXT DEFAULT NULL,
  `notify_on_sale` BOOLEAN NOT NULL DEFAULT FALSE,
  `notify_on_restock` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_user_product` (`user_id`, `product_id`),
  KEY `idx_product` (`product_id`),
  KEY `idx_priority` (`priority`),
  
  CONSTRAINT `fk_wishlist_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_wishlist_product` FOREIGN KEY (`product_id`) 
    REFERENCES `products` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    
  CONSTRAINT `chk_priority_range` CHECK (`priority` BETWEEN 1 AND 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User wishlists';

-- ============================================================================
-- TABLE: files
-- File uploads and document management
-- ============================================================================

DROP TABLE IF EXISTS `files`;

CREATE TABLE `files` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- File Information
  `filename` VARCHAR(255) NOT NULL,
  `original_filename` VARCHAR(255) NOT NULL,
  `file_path` VARCHAR(500) NOT NULL,
  `file_url` VARCHAR(500) NOT NULL,
  `mime_type` VARCHAR(100) NOT NULL,
  `file_size` BIGINT UNSIGNED NOT NULL COMMENT 'Size in bytes',
  `file_extension` VARCHAR(10) NOT NULL,
  
  -- File Type Classification
  `file_type` ENUM('image', 'video', 'audio', 'document', 'archive', 'other') NOT NULL,
  `is_public` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_temporary` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Image-specific
  `width` INT UNSIGNED DEFAULT NULL,
  `height` INT UNSIGNED DEFAULT NULL,
  `thumbnail_path` VARCHAR(500) DEFAULT NULL,
  
  -- Security
  `hash` VARCHAR(64) NOT NULL COMMENT 'File hash for integrity',
  `virus_scan_status` ENUM('pending', 'clean', 'infected', 'error') DEFAULT 'pending',
  `virus_scan_at` DATETIME DEFAULT NULL,
  
  -- Usage Tracking
  `download_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `view_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Metadata
  `metadata` JSON DEFAULT NULL,
  `alt_text` VARCHAR(255) DEFAULT NULL,
  `description` TEXT DEFAULT NULL,
  
  -- Expiration
  `expires_at` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_filename` (`filename`),
  KEY `idx_file_type` (`file_type`),
  KEY `idx_hash` (`hash`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_expires_at` (`expires_at`),
  
  CONSTRAINT `fk_files_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    
  CONSTRAINT `chk_file_size` CHECK (`file_size` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='File uploads';

-- ============================================================================
-- TABLE: notifications
-- User notifications system
-- ============================================================================

DROP TABLE IF EXISTS `notifications`;

CREATE TABLE `notifications` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Notification Content
  `type` VARCHAR(50) NOT NULL COMMENT 'order_update, security_alert, etc',
  `title` VARCHAR(200) NOT NULL,
  `message` TEXT NOT NULL,
  `data` JSON DEFAULT NULL COMMENT 'Additional notification data',
  
  -- Notification Channels
  `channel` ENUM('in_app', 'email', 'sms', 'push', 'webhook') NOT NULL DEFAULT 'in_app',
  
  -- Priority & Category
  `priority` ENUM('low', 'medium', 'high', 'urgent') NOT NULL DEFAULT 'medium',
  `category` VARCHAR(50) DEFAULT NULL COMMENT 'orders, security, marketing, etc',
  
  -- Action
  `action_url` VARCHAR(500) DEFAULT NULL,
  `action_text` VARCHAR(50) DEFAULT NULL,
  
  -- Status
  `is_read` BOOLEAN NOT NULL DEFAULT FALSE,
  `read_at` DATETIME DEFAULT NULL,
  `is_archived` BOOLEAN NOT NULL DEFAULT FALSE,
  `archived_at` DATETIME DEFAULT NULL,
  
  -- Delivery Status (for external channels)
  `delivery_status` ENUM('pending', 'sent', 'delivered', 'failed', 'bounced') DEFAULT 'pending',
  `delivered_at` DATETIME DEFAULT NULL,
  `failure_reason` VARCHAR(500) DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_type` (`type`),
  KEY `idx_is_read` (`is_read`),
  KEY `idx_priority` (`priority`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_channel` (`channel`),
  
  CONSTRAINT `fk_notifications_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User notifications';

-- ============================================================================
-- TABLE: webhooks
-- Webhook endpoints for integrations
-- ============================================================================

DROP TABLE IF EXISTS `webhooks`;

CREATE TABLE `webhooks` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Webhook Configuration
  `name` VARCHAR(100) NOT NULL,
  `url` VARCHAR(500) NOT NULL,
  `secret` VARCHAR(64) NOT NULL COMMENT 'HMAC signature secret',
  
  -- Events
  `events` JSON NOT NULL COMMENT 'Array of subscribed events',
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Retry Configuration
  `max_retries` TINYINT UNSIGNED NOT NULL DEFAULT 3,
  `retry_delay` INT UNSIGNED NOT NULL DEFAULT 300 COMMENT 'Seconds',
  
  -- Headers
  `custom_headers` JSON DEFAULT NULL,
  
  -- Statistics
  `total_deliveries` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `successful_deliveries` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `failed_deliveries` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `last_delivery_at` DATETIME DEFAULT NULL,
  `last_success_at` DATETIME DEFAULT NULL,
  `last_failure_at` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_is_active` (`is_active`),
  
  CONSTRAINT `fk_webhooks_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Webhook endpoints';

-- ============================================================================
-- TABLE: webhook_logs
-- Webhook delivery logs
-- ============================================================================

DROP TABLE IF EXISTS `webhook_logs`;

CREATE TABLE `webhook_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `webhook_id` INT UNSIGNED NOT NULL,
  
  -- Event Details
  `event_type` VARCHAR(50) NOT NULL,
  `payload` JSON NOT NULL,
  
  -- Delivery Details
  `url` VARCHAR(500) NOT NULL,
  `http_method` VARCHAR(10) NOT NULL DEFAULT 'POST',
  `request_headers` JSON DEFAULT NULL,
  `request_body` MEDIUMTEXT DEFAULT NULL,
  
  -- Response Details
  `response_status` INT DEFAULT NULL,
  `response_headers` JSON DEFAULT NULL,
  `response_body` TEXT DEFAULT NULL,
  `response_time` INT UNSIGNED DEFAULT NULL COMMENT 'Milliseconds',
  
  -- Status
  `status` ENUM('pending', 'success', 'failed', 'retrying') NOT NULL DEFAULT 'pending',
  `retry_count` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `error_message` TEXT DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `delivered_at` DATETIME DEFAULT NULL,
  `next_retry_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_webhook` (`webhook_id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_status` (`status`),
  KEY `idx_created_at` (`created_at`),
  
  CONSTRAINT `fk_webhook_logs_webhook` FOREIGN KEY (`webhook_id`) 
    REFERENCES `webhooks` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Webhook delivery logs';

-- ============================================================================
-- TABLE: api_tokens
-- API access tokens for integrations
-- ============================================================================

DROP TABLE IF EXISTS `api_tokens`;

CREATE TABLE `api_tokens` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Token Information
  `name` VARCHAR(100) NOT NULL COMMENT 'Descriptive token name',
  `token_hash` VARCHAR(64) NOT NULL UNIQUE COMMENT 'SHA256 hash of token',
  `token_prefix` VARCHAR(10) NOT NULL COMMENT 'First 8 chars for identification',
  
  -- Permissions & Scopes
  `scopes` JSON NOT NULL COMMENT 'Array of permission scopes',
  `rate_limit` INT UNSIGNED DEFAULT 60 COMMENT 'Requests per minute',
  
  -- IP Restrictions
  `allowed_ips` JSON DEFAULT NULL COMMENT 'Whitelist of IPs',
  `blocked_ips` JSON DEFAULT NULL COMMENT 'Blacklist of IPs',
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `last_used_at` DATETIME DEFAULT NULL,
  `last_used_ip` VARCHAR(45) DEFAULT NULL,
  
  -- Usage Statistics
  `usage_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `last_hour_requests` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Expiration
  `expires_at` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `revoked_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_token_hash` (`token_hash`),
  KEY `idx_user` (`user_id`),
  KEY `idx_token_prefix` (`token_prefix`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_expires_at` (`expires_at`),
  
  CONSTRAINT `fk_api_tokens_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='API access tokens';

-- ============================================================================
-- SECURITY TABLES
-- ============================================================================

-- TABLE: attack_logs
DROP TABLE IF EXISTS `attack_logs`;

CREATE TABLE `attack_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Attack Information
  `attack_type` VARCHAR(50) NOT NULL,
  `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  `payload` JSON NOT NULL COMMENT 'Attack payload details',
  `patterns` JSON DEFAULT NULL COMMENT 'Detected patterns',
  
  -- Request Details
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `endpoint` VARCHAR(500) NOT NULL,
  `http_method` VARCHAR(10) NOT NULL,
  `request_headers` JSON DEFAULT NULL,
  `request_body` MEDIUMTEXT DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  
  -- Response
  `was_blocked` BOOLEAN NOT NULL DEFAULT FALSE,
  `block_reason` VARCHAR(255) DEFAULT NULL,
  `response_action` VARCHAR(50) DEFAULT NULL COMMENT 'logged, blocked, honeypot, etc',
  
  -- Timestamps
  `timestamp` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_attack_type` (`attack_type`),
  KEY `idx_severity` (`severity`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_timestamp` (`timestamp`),
  KEY `idx_endpoint` (`endpoint`(255)),
  
  CONSTRAINT `fk_attack_logs_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Security attack logs';

-- Partitioning by month for attack logs
ALTER TABLE `attack_logs` PARTITION BY RANGE (TO_DAYS(`timestamp`)) (
  PARTITION p_2024_01 VALUES LESS THAN (TO_DAYS('2024-02-01')),
  PARTITION p_2024_02 VALUES LESS THAN (TO_DAYS('2024-03-01')),
  PARTITION p_2024_03 VALUES LESS THAN (TO_DAYS('2024-04-01')),
  PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- TABLE: security_events
DROP TABLE IF EXISTS `security_events`;

CREATE TABLE `security_events` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Event Information
  `event_type` VARCHAR(50) NOT NULL COMMENT 'login, logout, password_change, etc',
  `event_category` ENUM('authentication', 'authorization', 'data_access', 'configuration', 'attack') NOT NULL,
  `severity` ENUM('info', 'warning', 'critical') NOT NULL DEFAULT 'info',
  
  -- Event Details
  `description` TEXT DEFAULT NULL,
  `details` JSON DEFAULT NULL,
  
  -- Request Context
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  
  -- Status
  `was_successful` BOOLEAN NOT NULL DEFAULT TRUE,
  `failure_reason` VARCHAR(255) DEFAULT NULL,
  
  -- Timestamps
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_event_category` (`event_category`),
  KEY `idx_severity` (`severity`),
  KEY `idx_timestamp` (`timestamp`),
  KEY `idx_ip_address` (`ip_address`),
  
  CONSTRAINT `fk_security_events_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Security event tracking';

-- TABLE: audit_logs
DROP TABLE IF EXISTS `audit_logs`;

CREATE TABLE `audit_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Audit Information
  `action` VARCHAR(50) NOT NULL COMMENT 'create, update, delete, view',
  `entity_type` VARCHAR(50) NOT NULL COMMENT 'user, product, order, etc',
  `entity_id` BIGINT UNSIGNED NOT NULL,
  
  -- Change Details
  `old_values` JSON DEFAULT NULL COMMENT 'Previous state',
  `new_values` JSON DEFAULT NULL COMMENT 'New state',
  `changed_fields` JSON DEFAULT NULL COMMENT 'List of changed fields',
  
  -- Request Context
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `request_id` VARCHAR(100) DEFAULT NULL,
  
  -- Additional Info
  `description` VARCHAR(500) DEFAULT NULL,
  `metadata` JSON DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_action` (`action`),
  KEY `idx_entity` (`entity_type`, `entity_id`),
  KEY `idx_created_at` (`created_at`),
  
  CONSTRAINT `fk_audit_logs_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Audit trail for all changes';

-- TABLE: login_history
DROP TABLE IF EXISTS `login_history`;

CREATE TABLE `login_history` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Login Details
  `username` VARCHAR(50) NOT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `device_type` VARCHAR(50) DEFAULT NULL,
  `browser` VARCHAR(50) DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  
  -- Status
  `success` BOOLEAN NOT NULL,
  `failure_reason` VARCHAR(255) DEFAULT NULL,
  `mfa_used` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Timestamps
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_username` (`username`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_success` (`success`),
  KEY `idx_timestamp` (`timestamp`),
  
  CONSTRAINT `fk_login_history_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Login attempt history';

-- TABLE: ip_blacklist
DROP TABLE IF EXISTS `ip_blacklist`;

CREATE TABLE `ip_blacklist` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- IP Information
  `ip_address` VARCHAR(45) NOT NULL UNIQUE,
  `ip_range` VARCHAR(100) DEFAULT NULL COMMENT 'CIDR notation',
  
  -- Blacklist Details
  `reason` VARCHAR(255) NOT NULL,
  `attack_type` VARCHAR(50) DEFAULT NULL,
  `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_permanent` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Statistics
  `total_attacks` INT UNSIGNED NOT NULL DEFAULT 0,
  `last_attack_at` DATETIME DEFAULT NULL,
  
  -- Expiration
  `blocked_until` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_ip_address` (`ip_address`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_blocked_until` (`blocked_until`),
  
  CONSTRAINT `fk_ip_blacklist_created_by` FOREIGN KEY (`created_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='IP address blacklist';

-- TABLE: rate_limits
DROP TABLE IF EXISTS `rate_limits`;

CREATE TABLE `rate_limits` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Identifier
  `identifier` VARCHAR(100) NOT NULL COMMENT 'IP or user ID',
  `identifier_type` ENUM('ip', 'user', 'api_token') NOT NULL,
  
  -- Endpoint/Resource
  `resource` VARCHAR(200) NOT NULL COMMENT 'Endpoint or resource path',
  
  -- Rate Limit Data
  `request_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `window_start` DATETIME NOT NULL,
  `window_end` DATETIME NOT NULL,
  
  -- Status
  `is_blocked` BOOLEAN NOT NULL DEFAULT FALSE,
  `blocked_until` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_rate_limit_unique` (`identifier`, `resource`, `window_start`),
  KEY `idx_identifier` (`identifier`),
  KEY `idx_resource` (`resource`),
  KEY `idx_window_end` (`window_end`),
  KEY `idx_is_blocked` (`is_blocked`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Rate limiting tracking';

-- ============================================================================
-- ANALYTICS & TRACKING TABLES
-- ============================================================================

-- TABLE: page_views
DROP TABLE IF EXISTS `page_views`;

CREATE TABLE `page_views` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  
  -- Page Information
  `url` VARCHAR(500) NOT NULL,
  `path` VARCHAR(500) NOT NULL,
  `page_title` VARCHAR(200) DEFAULT NULL,
  `referrer` VARCHAR(500) DEFAULT NULL,
  
  -- User Context
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `device_type` VARCHAR(50) DEFAULT NULL,
  `browser` VARCHAR(50) DEFAULT NULL,
  `operating_system` VARCHAR(50) DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  
  -- Performance
  `load_time` INT UNSIGNED DEFAULT NULL COMMENT 'Page load time in ms',
  
  -- Timestamps
  `viewed_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_session` (`session_id`),
  KEY `idx_path` (`path`(255)),
  KEY `idx_viewed_at` (`viewed_at`),
  KEY `idx_ip_address` (`ip_address`),
  
  CONSTRAINT `fk_page_views_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Page view tracking';

-- TABLE: search_queries
DROP TABLE IF EXISTS `search_queries`;

CREATE TABLE `search_queries` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  
  -- Search Information
  `query` VARCHAR(500) NOT NULL,
  `results_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `category` VARCHAR(50) DEFAULT NULL,
  `filters` JSON DEFAULT NULL,
  
  -- Context
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  
  -- Results Interaction
  `clicked_result_id` BIGINT UNSIGNED DEFAULT NULL,
  `clicked_result_position` INT UNSIGNED DEFAULT NULL,
  `time_to_click` INT UNSIGNED DEFAULT NULL COMMENT 'Milliseconds',
  
  -- Timestamps
  `searched_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_session` (`session_id`),
  KEY `idx_query` (`query`(255)),
  KEY `idx_searched_at` (`searched_at`),
  FULLTEXT KEY `idx_fulltext_query` (`query`),
  
  CONSTRAINT `fk_search_queries_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Search query tracking';

-- TABLE: settings
DROP TABLE IF EXISTS `settings`;

CREATE TABLE `settings` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Setting Information
  `key` VARCHAR(100) NOT NULL UNIQUE,
  `value` TEXT DEFAULT NULL,
  `value_type` ENUM('string', 'number', 'boolean', 'json', 'encrypted') NOT NULL DEFAULT 'string',
  
  -- Metadata
  `category` VARCHAR(50) NOT NULL DEFAULT 'general',
  `description` VARCHAR(500) DEFAULT NULL,
  `is_public` BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Can be accessed by frontend',
  `is_encrypted` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Validation
  `validation_rules` JSON DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updated_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_key` (`key`),
  KEY `idx_category` (`category`),
  KEY `idx_is_public` (`is_public`),
  
  CONSTRAINT `fk_settings_updated_by` FOREIGN KEY (`updated_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Application settings';

-- TABLE: admin_notes
DROP TABLE IF EXISTS `admin_notes`;

CREATE TABLE `admin_notes` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL COMMENT 'Subject user',
  `admin_id` BIGINT UNSIGNED NOT NULL COMMENT 'Admin who created note',
  
  -- Note Content
  `subject` VARCHAR(200) NOT NULL,
  `note` TEXT NOT NULL,
  `note_type` ENUM('general', 'warning', 'important', 'security') NOT NULL DEFAULT 'general',
  `priority` ENUM('low', 'medium', 'high', 'urgent') NOT NULL DEFAULT 'medium',
  
  -- Visibility
  `is_visible_to_moderators` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_flagged` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_admin` (`admin_id`),
  KEY `idx_note_type` (`note_type`),
  KEY `idx_priority` (`priority`),
  KEY `idx_created_at` (`created_at`),
  
  CONSTRAINT `fk_admin_notes_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_admin_notes_admin` FOREIGN KEY (`admin_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Admin notes about users';

-- ============================================================================
-- DATABASE VIEWS
-- ============================================================================

-- VIEW: admin_dashboard_view
DROP VIEW IF EXISTS `admin_dashboard_view`;

CREATE VIEW `admin_dashboard_view` AS
SELECT 
  DATE(o.created_at) AS date,
  COUNT(DISTINCT o.id) AS total_orders,
  COUNT(DISTINCT o.user_id) AS unique_customers,
  SUM(o.total_amount) AS revenue,
  AVG(o.total_amount) AS avg_order_value,
  COUNT(DISTINCT CASE WHEN o.status = 'completed' THEN o.id END) AS completed_orders,
  COUNT(DISTINCT CASE WHEN o.status = 'cancelled' THEN o.id END) AS cancelled_orders,
  COUNT(DISTINCT u.id) AS new_users
FROM orders o
LEFT JOIN users u ON DATE(u.created_at) = DATE(o.created_at)
WHERE o.created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY DATE(o.created_at)
ORDER BY date DESC;

-- VIEW: product_stats_view
DROP VIEW IF EXISTS `product_stats_view`;

CREATE VIEW `product_stats_view` AS
SELECT 
  p.id,
  p.name,
  p.sku,
  p.base_price,
  p.stock_quantity,
  p.rating_average,
  p.review_count,
  p.view_count,
  p.sale_count,
  COALESCE(SUM(oi.quantity), 0) AS total_sold,
  COALESCE(SUM(oi.total_amount), 0) AS total_revenue,
  COUNT(DISTINCT r.id) AS total_reviews,
  AVG(r.rating) AS calculated_rating
FROM products p
LEFT JOIN order_items oi ON p.id = oi.product_id
LEFT JOIN reviews r ON p.id = r.product_id AND r.status = 'approved'
WHERE p.deleted_at IS NULL
GROUP BY p.id;

-- VIEW: user_activity_view
DROP VIEW IF EXISTS `user_activity_view`;

CREATE VIEW `user_activity_view` AS
SELECT 
  u.id,
  u.username,
  u.email,
  u.role,
  u.total_orders,
  u.total_spent,
  u.loyalty_points,
  u.last_login_at,
  COUNT(DISTINCT o.id) AS order_count,
  COUNT(DISTINCT r.id) AS review_count,
  COUNT(DISTINCT w.id) AS wishlist_count,
  MAX(o.created_at) AS last_order_date,
  DATEDIFF(CURDATE(), u.created_at) AS account_age_days
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
LEFT JOIN reviews r ON u.id = r.user_id
LEFT JOIN wishlists w ON u.id = w.user_id
WHERE u.deleted_at IS NULL
GROUP BY u.id;

-- VIEW: attack_summary_view
DROP VIEW IF EXISTS `attack_summary_view`;

CREATE VIEW `attack_summary_view` AS
SELECT 
  DATE(timestamp) AS date,
  attack_type,
  severity,
  COUNT(*) AS attack_count,
  COUNT(DISTINCT ip_address) AS unique_ips,
  COUNT(DISTINCT user_id) AS affected_users,
  SUM(CASE WHEN was_blocked THEN 1 ELSE 0 END) AS blocked_count,
  ROUND(SUM(CASE WHEN was_blocked THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS block_rate
FROM attack_logs
WHERE timestamp >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
GROUP BY DATE(timestamp), attack_type, severity
ORDER BY date DESC, attack_count DESC;

-- ============================================================================
-- STORED PROCEDURES
-- ============================================================================

-- PROCEDURE: sp_create_order
DROP PROCEDURE IF EXISTS `sp_create_order`;

DELIMITER $

CREATE PROCEDURE `sp_create_order`(
  IN p_user_id BIGINT UNSIGNED,
  IN p_cart_items JSON,
  IN p_shipping_address JSON,
  IN p_billing_address JSON,
  IN p_payment_method VARCHAR(50),
  IN p_coupon_code VARCHAR(50),
  OUT p_order_id BIGINT UNSIGNED,
  OUT p_order_number VARCHAR(50),
  OUT p_total_amount DECIMAL(15, 2)
)
BEGIN
  DECLARE v_subtotal DECIMAL(15, 2) DEFAULT 0.00;
  DECLARE v_tax DECIMAL(15, 2) DEFAULT 0.00;
  DECLARE v_shipping DECIMAL(15, 2) DEFAULT 0.00;
  DECLARE v_discount DECIMAL(15, 2) DEFAULT 0.00;
  DECLARE v_total DECIMAL(15, 2) DEFAULT 0.00;
  DECLARE v_order_num VARCHAR(50);
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;

  -- Generate order number
  SET v_order_num = CONCAT('ORD-', DATE_FORMAT(NOW(), '%Y%m%d'), '-', LPAD(FLOOR(RAND() * 9999), 4, '0'));

  -- Calculate totals (simplified - would be more complex in production)
  SET v_subtotal = JSON_LENGTH(p_cart_items) * 50.00; -- Placeholder
  SET v_tax = v_subtotal * 0.10;
  SET v_shipping = 10.00;
  SET v_total = v_subtotal + v_tax + v_shipping - v_discount;

  -- Create order
  INSERT INTO orders (
    user_id, order_number, status, payment_status,
    subtotal, tax_amount, shipping_amount, discount_amount, total_amount,
    payment_method,
    shipping_first_name, shipping_last_name, shipping_email, shipping_phone,
    shipping_address_line1, shipping_city, shipping_state, shipping_postal_code, shipping_country,
    billing_first_name, billing_last_name, billing_email, billing_phone,
    billing_address_line1, billing_city, billing_state, billing_postal_code, billing_country
  ) VALUES (
    p_user_id, v_order_num, 'pending', 'pending',
    v_subtotal, v_tax, v_shipping, v_discount, v_total,
    p_payment_method,
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.firstName')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.lastName')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.email')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.phone')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.addressLine1')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.city')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.state')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.postalCode')),
    JSON_UNQUOTE(JSON_EXTRACT(p_shipping_address, '$.country')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.firstName')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.lastName')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.email')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.phone')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.addressLine1')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.city')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.state')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.postalCode')),
    JSON_UNQUOTE(JSON_EXTRACT(p_billing_address, '$.country'))
  );

  SET p_order_id = LAST_INSERT_ID();
  SET p_order_number = v_order_num;
  SET p_total_amount = v_total;

  COMMIT;
END$

DELIMITER ;

-- PROCEDURE: sp_apply_coupon
DROP PROCEDURE IF EXISTS `sp_apply_coupon`;

DELIMITER $

CREATE PROCEDURE `sp_apply_coupon`(
  IN p_coupon_code VARCHAR(50),
  IN p_user_id BIGINT UNSIGNED,
  IN p_subtotal DECIMAL(15, 2),
  OUT p_discount_amount DECIMAL(15, 2),
  OUT p_is_valid BOOLEAN,
  OUT p_error_message VARCHAR(255)
)
BEGIN
  DECLARE v_coupon_id INT UNSIGNED;
  DECLARE v_discount_type VARCHAR(20);
  DECLARE v_discount_value DECIMAL(10, 2);
  DECLARE v_max_discount DECIMAL(10, 2);
  DECLARE v_min_purchase DECIMAL(10, 2);
  DECLARE v_usage_count INT UNSIGNED;
  DECLARE v_usage_limit INT UNSIGNED;
  DECLARE v_user_usage_count INT UNSIGNED;
  DECLARE v_user_usage_limit INT UNSIGNED;

  SET p_is_valid = FALSE;
  SET p_discount_amount = 0.00;
  SET p_error_message = NULL;

  -- Get coupon details
  SELECT id, discount_type, discount_value, max_discount_amount, 
         min_purchase_amount, usage_count, usage_limit, usage_limit_per_user
  INTO v_coupon_id, v_discount_type, v_discount_value, v_max_discount,
       v_min_purchase, v_usage_count, v_usage_limit, v_user_usage_limit
  FROM coupons
  WHERE code = p_coupon_code
    AND is_active = TRUE
    AND (valid_from IS NULL OR valid_from <= NOW())
    AND (valid_until IS NULL OR valid_until >= NOW())
  LIMIT 1;

  IF v_coupon_id IS NULL THEN
    SET p_error_message = 'Invalid or expired coupon code';
    LEAVE sp_apply_coupon;
  END IF;

  -- Check minimum purchase
  IF v_min_purchase IS NOT NULL AND p_subtotal < v_min_purchase THEN
    SET p_error_message = CONCAT('Minimum purchase of , v_min_purchase, ' required');
    LEAVE sp_apply_coupon;
  END IF;

  -- Check total usage limit
  IF v_usage_limit IS NOT NULL AND v_usage_count >= v_usage_limit THEN
    SET p_error_message = 'Coupon usage limit reached';
    LEAVE sp_apply_coupon;
  END IF;

  -- Check user usage limit
  SELECT COUNT(*) INTO v_user_usage_count
  FROM coupon_usage
  WHERE coupon_id = v_coupon_id AND user_id = p_user_id;

  IF v_user_usage_limit IS NOT NULL AND v_user_usage_count >= v_user_usage_limit THEN
    SET p_error_message = 'You have already used this coupon';
    LEAVE sp_apply_coupon;
  END IF;

  -- Calculate discount
  IF v_discount_type = 'percentage' THEN
    SET p_discount_amount = (p_subtotal * v_discount_value) / 100;
    IF v_max_discount IS NOT NULL AND p_discount_amount > v_max_discount THEN
      SET p_discount_amount = v_max_discount;
    END IF;
  ELSEIF v_discount_type = 'fixed_amount' THEN
    SET p_discount_amount = v_discount_value;
    IF p_discount_amount > p_subtotal THEN
      SET p_discount_amount = p_subtotal;
    END IF;
  END IF;

  SET p_is_valid = TRUE;
END$

DELIMITER ;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Update product rating when review is created/updated
DROP TRIGGER IF EXISTS `trg_reviews_after_insert`;

DELIMITER $

CREATE TRIGGER `trg_reviews_after_insert`
AFTER INSERT ON `reviews`
FOR EACH ROW
BEGIN
  IF NEW.status = 'approved' THEN
    UPDATE products
    SET 
      rating_count = rating_count + 1,
      review_count = review_count + 1,
      rating_average = (
        SELECT AVG(rating)
        FROM reviews
        WHERE product_id = NEW.product_id
          AND status = 'approved'
          AND deleted_at IS NULL
      )
    WHERE id = NEW.product_id;
  END IF;
END$

DELIMITER ;

-- Update product rating when review is updated
DROP TRIGGER IF EXISTS `trg_reviews_after_update`;

DELIMITER $

CREATE TRIGGER `trg_reviews_after_update`
AFTER UPDATE ON `reviews`
FOR EACH ROW
BEGIN
  IF NEW.status != OLD.status OR NEW.rating != OLD.rating THEN
    UPDATE products
    SET 
      rating_average = (
        SELECT COALESCE(AVG(rating), 0)
        FROM reviews
        WHERE product_id = NEW.product_id
          AND status = 'approved'
          AND deleted_at IS NULL
      ),
      rating_count = (
        SELECT COUNT(*)
        FROM reviews
        WHERE product_id = NEW.product_id
          AND status = 'approved'
          AND deleted_at IS NULL
      )
    WHERE id = NEW.product_id;
  END IF;
END$

DELIMITER ;

-- Update order totals when order items change
DROP TRIGGER IF EXISTS `trg_order_items_after_insert`;

DELIMITER $

CREATE TRIGGER `trg_order_items_after_insert`
AFTER INSERT ON `order_items`
FOR EACH ROW
BEGIN
  UPDATE orders
  SET 
    subtotal = (
      SELECT COALESCE(SUM(subtotal), 0)
      FROM order_items
      WHERE order_id = NEW.order_id
    ),
    total_amount = subtotal + tax_amount + shipping_amount - discount_amount
  WHERE id = NEW.order_id;
END$

DELIMITER ;

-- Log user changes to audit log
DROP TRIGGER IF EXISTS `trg_users_after_update`;

DELIMITER $

CREATE TRIGGER `trg_users_after_update`
AFTER UPDATE ON `users`
FOR EACH ROW
BEGIN
  DECLARE v_changed_fields JSON;
  DECLARE v_old_values JSON;
  DECLARE v_new_values JSON;

  IF NEW.email != OLD.email OR NEW.role != OLD.role OR NEW.is_active != OLD.is_active THEN
    SET v_changed_fields = JSON_ARRAY();
    SET v_old_values = JSON_OBJECT();
    SET v_new_values = JSON_OBJECT();

    IF NEW.email != OLD.email THEN
      SET v_changed_fields = JSON_ARRAY_APPEND(v_changed_fields, ', 'email');
      SET v_old_values = JSON_SET(v_old_values, '$.email', OLD.email);
      SET v_new_values = JSON_SET(v_new_values, '$.email', NEW.email);
    END IF;

    IF NEW.role != OLD.role THEN
      SET v_changed_fields = JSON_ARRAY_APPEND(v_changed_fields, ', 'role');
      SET v_old_values = JSON_SET(v_old_values, '$.role', OLD.role);
      SET v_new_values = JSON_SET(v_new_values, '$.role', NEW.role);
    END IF;

    IF NEW.is_active != OLD.is_active THEN
      SET v_changed_fields = JSON_ARRAY_APPEND(v_changed_fields, ', 'is_active');
      SET v_old_values = JSON_SET(v_old_values, '$.is_active', OLD.is_active);
      SET v_new_values = JSON_SET(v_new_values, '$.is_active', NEW.is_active);
    END IF;

    INSERT INTO audit_logs (
      user_id, action, entity_type, entity_id,
      old_values, new_values, changed_fields
    ) VALUES (
      NEW.id, 'update', 'user', NEW.id,
      v_old_values, v_new_values, v_changed_fields
    );
  END IF;
END$

DELIMITER ;

-- Update product stock when order is placed
DROP TRIGGER IF EXISTS `trg_order_items_stock_update`;

DELIMITER $

CREATE TRIGGER `trg_order_items_stock_update`
AFTER INSERT ON `order_items`
FOR EACH ROW
BEGIN
  UPDATE products
  SET 
    stock_quantity = stock_quantity - NEW.quantity,
    sale_count = sale_count + NEW.quantity
  WHERE id = NEW.product_id
    AND track_inventory = TRUE;
END$

DELIMITER ;

-- ============================================================================
-- INDEXES & PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Composite indexes for common queries
CREATE INDEX idx_orders_user_status ON orders(user_id, status);
CREATE INDEX idx_orders_status_created ON orders(status, created_at);
CREATE INDEX idx_products_category_status ON products(category_id, status);
CREATE INDEX idx_reviews_product_status ON reviews(product_id, status);
CREATE INDEX idx_attack_logs_ip_timestamp ON attack_logs(ip_address, timestamp);

-- ============================================================================
-- INITIAL DATA SETUP
-- ============================================================================

-- Insert default settings
INSERT INTO `settings` (`key`, `value`, `value_type`, `category`, `description`, `is_public`) VALUES
('site_name', 'SQLi Demo Platform', 'string', 'general', 'Website name', TRUE),
('site_description', 'Enterprise-grade SQL Injection demonstration platform', 'string', 'general', 'Website description', TRUE),
('admin_email', 'admin@sqli-demo.local', 'string', 'general', 'Administrator email', FALSE),
('security_mode', 'vulnerable', 'string', 'security', 'Current security mode (vulnerable/secure)', TRUE),
('enable_registration', 'true', 'boolean', 'security', 'Allow new user registrations', TRUE),
('enable_2fa', 'false', 'boolean', 'security', 'Enable two-factor authentication', TRUE),
('max_login_attempts', '5', 'number', 'security', 'Maximum failed login attempts', FALSE),
('session_timeout', '3600', 'number', 'security', 'Session timeout in seconds', FALSE),
('enable_rate_limiting', 'true', 'boolean', 'security', 'Enable API rate limiting', TRUE),
('default_currency', 'USD', 'string', 'ecommerce', 'Default currency code', TRUE),
('tax_rate', '10.00', 'number', 'ecommerce', 'Default tax rate percentage', FALSE),
('shipping_cost', '10.00', 'number', 'ecommerce', 'Standard shipping cost', FALSE),
('free_shipping_threshold', '100.00', 'number', 'ecommerce', 'Free shipping minimum order', TRUE),
('enable_email_notifications', 'true', 'boolean', 'notifications', 'Enable email notifications', FALSE),
('enable_sms_notifications', 'false', 'boolean', 'notifications', 'Enable SMS notifications', FALSE);

-- ============================================================================
-- CLEANUP & MAINTENANCE FUNCTIONS
-- ============================================================================

-- PROCEDURE: sp_cleanup_expired_sessions
DROP PROCEDURE IF EXISTS `sp_cleanup_expired_sessions`;

DELIMITER $

CREATE PROCEDURE `sp_cleanup_expired_sessions`()
BEGIN
  DELETE FROM user_sessions
  WHERE expires_at < NOW()
    AND is_active = FALSE;

  SELECT ROW_COUNT() AS deleted_sessions;
END$

DELIMITER ;

-- PROCEDURE: sp_cleanup_old_logs
DROP PROCEDURE IF EXISTS `sp_cleanup_old_logs`;

DELIMITER $

CREATE PROCEDURE `sp_cleanup_old_logs`(IN p_days INT)
BEGIN
  DECLARE v_cutoff_date DATETIME;
  DECLARE v_deleted_attacks INT DEFAULT 0;
  DECLARE v_deleted_page_views INT DEFAULT 0;
  DECLARE v_deleted_searches INT DEFAULT 0;

  SET v_cutoff_date = DATE_SUB(NOW(), INTERVAL p_days DAY);

  DELETE FROM attack_logs WHERE created_at < v_cutoff_date;
  SET v_deleted_attacks = ROW_COUNT();

  DELETE FROM page_views WHERE viewed_at < v_cutoff_date;
  SET v_deleted_page_views = ROW_COUNT();

  DELETE FROM search_queries WHERE searched_at < v_cutoff_date;
  SET v_deleted_searches = ROW_COUNT();

  SELECT 
    v_deleted_attacks AS deleted_attack_logs,
    v_deleted_page_views AS deleted_page_views,
    v_deleted_searches AS deleted_search_queries;
END$

DELIMITER ;

-- ============================================================================
-- EVENTS (SCHEDULED TASKS)
-- ============================================================================

-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- Clean up expired sessions daily
DROP EVENT IF EXISTS `evt_cleanup_expired_sessions`;

CREATE EVENT `evt_cleanup_expired_sessions`
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO CALL sp_cleanup_expired_sessions();

-- Clean up old cart items weekly
DROP EVENT IF EXISTS `evt_cleanup_old_carts`;

CREATE EVENT `evt_cleanup_old_carts`
ON SCHEDULE EVERY 1 WEEK
STARTS CURRENT_TIMESTAMP
DO
  DELETE FROM cart_items
  WHERE expires_at < NOW()
    OR (expires_at IS NULL AND updated_at < DATE_SUB(NOW(), INTERVAL 30 DAY));

-- Clean up old logs monthly
DROP EVENT IF EXISTS `evt_cleanup_old_logs`;

CREATE EVENT `evt_cleanup_old_logs`
ON SCHEDULE EVERY 1 MONTH
STARTS CURRENT_TIMESTAMP
DO CALL sp_cleanup_old_logs(90);

-- ============================================================================
-- COMPLETION MESSAGE
-- ============================================================================

SELECT '
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ✅ DATABASE SCHEMA CREATED SUCCESSFULLY                            ║
║                                                                      ║
║   Database: sqli_demo_platform                                      ║
║   Tables: 30+ core tables                                           ║
║   Views: 4 analytical views                                         ║
║   Procedures: 4 stored procedures                                   ║
║   Triggers: 5 automated triggers                                    ║
║   Events: 3 scheduled maintenance tasks                             ║
║                                                                      ║
║   Enterprise Features: ✅                                             ║
║   Security Features: ✅                                               ║
║   Performance Optimization: ✅                                        ║
║   Audit Trails: ✅                                                    ║
║                                                                      ║
║   Next Steps:                                                        ║
║   1. Run migrations: node database/migrate.js                       ║
║   2. Seed data: node database/seed.js                               ║
║   3. Start application: npm start                                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
' AS 'Schema Status';

SET FOREIGN_KEY_CHECKS = 1;
