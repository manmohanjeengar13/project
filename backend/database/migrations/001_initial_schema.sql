-- ============================================================================
-- Migration 001: Initial Schema
-- ============================================================================
-- Creates the foundational database structure for SQLi Demo Platform
-- Version: 1.0.0
-- Date: 2024-01-01
-- ============================================================================

-- Enable strict mode
SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO';
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- CORE USER TABLES
-- ============================================================================

-- Users table with comprehensive authentication
CREATE TABLE IF NOT EXISTS `users` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  
  `first_name` VARCHAR(100) DEFAULT NULL,
  `last_name` VARCHAR(100) DEFAULT NULL,
  `full_name` VARCHAR(200) GENERATED ALWAYS AS (CONCAT(IFNULL(first_name, ''), ' ', IFNULL(last_name, ''))) STORED,
  `date_of_birth` DATE DEFAULT NULL,
  `gender` ENUM('male', 'female', 'other', 'prefer_not_to_say') DEFAULT NULL,
  `phone` VARCHAR(20) DEFAULT NULL,
  `avatar` VARCHAR(500) DEFAULT NULL,
  
  `address_line1` VARCHAR(255) DEFAULT NULL,
  `address_line2` VARCHAR(255) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `state` VARCHAR(100) DEFAULT NULL,
  `postal_code` VARCHAR(20) DEFAULT NULL,
  `country` VARCHAR(2) DEFAULT 'US',
  
  `role` ENUM('customer', 'moderator', 'admin', 'super_admin') NOT NULL DEFAULT 'customer',
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_email_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_phone_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  
  `email_verification_token` VARCHAR(64) DEFAULT NULL,
  `email_verification_expires` DATETIME DEFAULT NULL,
  `email_verified_at` DATETIME DEFAULT NULL,
  
  `password_reset_token` VARCHAR(64) DEFAULT NULL,
  `password_reset_expires` DATETIME DEFAULT NULL,
  `password_changed_at` DATETIME DEFAULT NULL,
  
  `two_factor_enabled` BOOLEAN NOT NULL DEFAULT FALSE,
  `two_factor_secret` VARCHAR(32) DEFAULT NULL,
  `two_factor_recovery_codes` JSON DEFAULT NULL,
  
  `failed_login_attempts` INT UNSIGNED NOT NULL DEFAULT 0,
  `account_locked_until` DATETIME DEFAULT NULL,
  `last_login_at` DATETIME DEFAULT NULL,
  `last_login_ip` VARCHAR(45) DEFAULT NULL,
  `last_login_user_agent` VARCHAR(500) DEFAULT NULL,
  `login_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  
  `preferences` JSON DEFAULT NULL,
  `timezone` VARCHAR(50) DEFAULT 'UTC',
  `locale` VARCHAR(10) DEFAULT 'en_US',
  `currency` VARCHAR(3) DEFAULT 'USD',
  `notification_preferences` JSON DEFAULT NULL,
  
  `member_since` DATETIME DEFAULT NULL,
  `total_spent` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `total_orders` INT UNSIGNED NOT NULL DEFAULT 0,
  `loyalty_points` INT UNSIGNED NOT NULL DEFAULT 0,
  `customer_tier` ENUM('bronze', 'silver', 'gold', 'platinum', 'diamond') DEFAULT 'bronze',
  
  `api_access_enabled` BOOLEAN NOT NULL DEFAULT FALSE,
  `api_rate_limit` INT UNSIGNED DEFAULT 60,
  
  `referral_code` VARCHAR(20) UNIQUE DEFAULT NULL,
  `referred_by` BIGINT UNSIGNED DEFAULT NULL,
  `referral_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `referral_earnings` DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
  
  `metadata` JSON DEFAULT NULL,
  `notes` TEXT DEFAULT NULL,
  `tags` JSON DEFAULT NULL,
  
  `deleted_at` DATETIME DEFAULT NULL,
  `deleted_by` BIGINT UNSIGNED DEFAULT NULL,
  `deletion_reason` VARCHAR(255) DEFAULT NULL,
  
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_username` (`username`),
  UNIQUE KEY `idx_email` (`email`),
  KEY `idx_role` (`role`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_deleted_at` (`deleted_at`),
  FULLTEXT KEY `idx_search` (`username`, `email`, `first_name`, `last_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User sessions
CREATE TABLE IF NOT EXISTS `user_sessions` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `session_token` VARCHAR(255) NOT NULL UNIQUE,
  `refresh_token` VARCHAR(500) NOT NULL UNIQUE,
  `access_token_hash` VARCHAR(64) DEFAULT NULL,
  
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) NOT NULL,
  `device_type` ENUM('desktop', 'mobile', 'tablet', 'other') DEFAULT 'other',
  `browser` VARCHAR(50) DEFAULT NULL,
  `operating_system` VARCHAR(50) DEFAULT NULL,
  `device_fingerprint` VARCHAR(64) DEFAULT NULL,
  
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `latitude` DECIMAL(10, 8) DEFAULT NULL,
  `longitude` DECIMAL(11, 8) DEFAULT NULL,
  
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `last_activity` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` DATETIME NOT NULL,
  `revoked_at` DATETIME DEFAULT NULL,
  `revoked_reason` VARCHAR(255) DEFAULT NULL,
  
  `is_suspicious` BOOLEAN NOT NULL DEFAULT FALSE,
  `risk_score` TINYINT UNSIGNED DEFAULT 0,
  `mfa_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_expires_at` (`expires_at`),
  KEY `idx_is_active` (`is_active`),
  
  CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- E-COMMERCE TABLES
-- ============================================================================

-- Categories
CREATE TABLE IF NOT EXISTS `categories` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `parent_id` INT UNSIGNED DEFAULT NULL,
  `name` VARCHAR(100) NOT NULL,
  `slug` VARCHAR(120) NOT NULL UNIQUE,
  `description` TEXT DEFAULT NULL,
  `icon` VARCHAR(100) DEFAULT NULL,
  `image` VARCHAR(500) DEFAULT NULL,
  `banner` VARCHAR(500) DEFAULT NULL,
  
  `meta_title` VARCHAR(200) DEFAULT NULL,
  `meta_description` VARCHAR(500) DEFAULT NULL,
  `meta_keywords` VARCHAR(500) DEFAULT NULL,
  
  `sort_order` INT NOT NULL DEFAULT 0,
  `level` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `path` VARCHAR(500) DEFAULT NULL,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  
  `product_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `view_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_parent_id` (`parent_id`),
  KEY `idx_is_active` (`is_active`),
  FULLTEXT KEY `idx_search` (`name`, `description`),
  
  CONSTRAINT `fk_categories_parent` FOREIGN KEY (`parent_id`) 
    REFERENCES `categories` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Products
CREATE TABLE IF NOT EXISTS `products` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `category_id` INT UNSIGNED NOT NULL,
  
  `sku` VARCHAR(50) NOT NULL UNIQUE,
  `name` VARCHAR(255) NOT NULL,
  `slug` VARCHAR(300) NOT NULL UNIQUE,
  `description` TEXT DEFAULT NULL,
  `short_description` VARCHAR(500) DEFAULT NULL,
  
  `base_price` DECIMAL(15, 2) NOT NULL,
  `sale_price` DECIMAL(15, 2) DEFAULT NULL,
  `cost_price` DECIMAL(15, 2) DEFAULT NULL,
  `currency` VARCHAR(3) NOT NULL DEFAULT 'USD',
  `tax_rate` DECIMAL(5, 2) NOT NULL DEFAULT 0.00,
  
  `stock_quantity` INT NOT NULL DEFAULT 0,
  `low_stock_threshold` INT NOT NULL DEFAULT 10,
  `track_inventory` BOOLEAN NOT NULL DEFAULT TRUE,
  `allow_backorder` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_in_stock` BOOLEAN GENERATED ALWAYS AS (`stock_quantity` > 0 OR `allow_backorder` = TRUE) STORED,
  
  `weight` DECIMAL(10, 2) DEFAULT NULL,
  `length` DECIMAL(10, 2) DEFAULT NULL,
  `width` DECIMAL(10, 2) DEFAULT NULL,
  `height` DECIMAL(10, 2) DEFAULT NULL,
  
  `status` ENUM('draft', 'pending', 'active', 'inactive', 'out_of_stock', 'discontinued') NOT NULL DEFAULT 'draft',
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_bestseller` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_new_arrival` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_digital` BOOLEAN NOT NULL DEFAULT FALSE,
  
  `main_image` VARCHAR(500) DEFAULT NULL,
  `images` JSON DEFAULT NULL,
  `video_url` VARCHAR(500) DEFAULT NULL,
  `files` JSON DEFAULT NULL,
  
  `meta_title` VARCHAR(200) DEFAULT NULL,
  `meta_description` VARCHAR(500) DEFAULT NULL,
  `meta_keywords` VARCHAR(500) DEFAULT NULL,
  
  `rating_average` DECIMAL(3, 2) NOT NULL DEFAULT 0.00,
  `rating_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `review_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  `view_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `sale_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `wishlist_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `cart_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  `attributes` JSON DEFAULT NULL,
  `specifications` JSON DEFAULT NULL,
  `tags` JSON DEFAULT NULL,
  
  `available_from` DATETIME DEFAULT NULL,
  `available_until` DATETIME DEFAULT NULL,
  
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` DATETIME DEFAULT NULL,
  `created_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_category` (`category_id`),
  KEY `idx_status` (`status`),
  KEY `idx_featured` (`is_featured`),
  FULLTEXT KEY `idx_search` (`name`, `description`, `sku`),
  
  CONSTRAINT `fk_products_category` FOREIGN KEY (`category_id`) 
    REFERENCES `categories` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_products_created_by` FOREIGN KEY (`created_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Reviews
CREATE TABLE IF NOT EXISTS `reviews` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `product_id` BIGINT UNSIGNED NOT NULL,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `order_id` BIGINT UNSIGNED DEFAULT NULL,
  
  `title` VARCHAR(200) NOT NULL,
  `comment` TEXT NOT NULL,
  `rating` TINYINT UNSIGNED NOT NULL,
  
  `helpful_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `not_helpful_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `report_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  `images` JSON DEFAULT NULL,
  `videos` JSON DEFAULT NULL,
  
  `status` ENUM('pending', 'approved', 'rejected', 'spam', 'flagged') NOT NULL DEFAULT 'pending',
  `is_verified_purchase` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  
  `moderated_by` BIGINT UNSIGNED DEFAULT NULL,
  `moderated_at` DATETIME DEFAULT NULL,
  `moderation_reason` VARCHAR(500) DEFAULT NULL,
  
  `has_response` BOOLEAN NOT NULL DEFAULT FALSE,
  `response_text` TEXT DEFAULT NULL,
  `response_by` BIGINT UNSIGNED DEFAULT NULL,
  `response_at` DATETIME DEFAULT NULL,
  
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_product` (`product_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_rating` (`rating`),
  KEY `idx_status` (`status`),
  FULLTEXT KEY `idx_search` (`title`, `comment`),
  
  CONSTRAINT `fk_reviews_product` FOREIGN KEY (`product_id`) 
    REFERENCES `products` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_reviews_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE,
  
  UNIQUE KEY `idx_unique_review` (`product_id`, `user_id`, `deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Orders
CREATE TABLE IF NOT EXISTS `orders` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `order_number` VARCHAR(50) NOT NULL UNIQUE,
  `invoice_number` VARCHAR(50) DEFAULT NULL UNIQUE,
  
  `status` ENUM('pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded', 'failed') NOT NULL DEFAULT 'pending',
  `payment_status` ENUM('pending', 'paid', 'failed', 'refunded', 'partially_refunded') NOT NULL DEFAULT 'pending',
  `fulfillment_status` ENUM('unfulfilled', 'partial', 'fulfilled') NOT NULL DEFAULT 'unfulfilled',
  
  `subtotal` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `tax_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `shipping_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `discount_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `total_amount` DECIMAL(15, 2) NOT NULL,
  `currency` VARCHAR(3) NOT NULL DEFAULT 'USD',
  
  `coupon_code` VARCHAR(50) DEFAULT NULL,
  `coupon_discount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `loyalty_points_used` INT UNSIGNED NOT NULL DEFAULT 0,
  `loyalty_points_earned` INT UNSIGNED NOT NULL DEFAULT 0,
  
  `payment_method` VARCHAR(50) NOT NULL,
  `payment_gateway` VARCHAR(50) DEFAULT NULL,
  `transaction_id` VARCHAR(100) DEFAULT NULL,
  `payment_details` JSON DEFAULT NULL,
  `paid_at` DATETIME DEFAULT NULL,
  
  `shipping_method` VARCHAR(50) DEFAULT NULL,
  `shipping_provider` VARCHAR(50) DEFAULT NULL,
  `tracking_number` VARCHAR(100) DEFAULT NULL,
  `tracking_url` VARCHAR(500) DEFAULT NULL,
  `estimated_delivery` DATE DEFAULT NULL,
  `shipped_at` DATETIME DEFAULT NULL,
  `delivered_at` DATETIME DEFAULT NULL,
  
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
  
  `customer_notes` TEXT DEFAULT NULL,
  `admin_notes` TEXT DEFAULT NULL,
  `internal_notes` TEXT DEFAULT NULL,
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  
  `refund_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `refund_reason` VARCHAR(500) DEFAULT NULL,
  `refunded_at` DATETIME DEFAULT NULL,
  `refunded_by` BIGINT UNSIGNED DEFAULT NULL,
  
  `cancelled_at` DATETIME DEFAULT NULL,
  `cancelled_by` BIGINT UNSIGNED DEFAULT NULL,
  `cancellation_reason` VARCHAR(500) DEFAULT NULL,
  
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `completed_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_status` (`status`),
  KEY `idx_payment_status` (`payment_status`),
  
  CONSTRAINT `fk_orders_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Order Items
CREATE TABLE IF NOT EXISTS `order_items` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `order_id` BIGINT UNSIGNED NOT NULL,
  `product_id` BIGINT UNSIGNED NOT NULL,
  
  `product_name` VARCHAR(255) NOT NULL,
  `product_sku` VARCHAR(50) NOT NULL,
  `product_image` VARCHAR(500) DEFAULT NULL,
  
  `unit_price` DECIMAL(15, 2) NOT NULL,
  `quantity` INT UNSIGNED NOT NULL DEFAULT 1,
  `subtotal` DECIMAL(15, 2) NOT NULL,
  `tax_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `discount_amount` DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
  `total_amount` DECIMAL(15, 2) NOT NULL,
  
  `attributes` JSON DEFAULT NULL,
  `customization` JSON DEFAULT NULL,
  
  `fulfillment_status` ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') NOT NULL DEFAULT 'pending',
  `shipped_quantity` INT UNSIGNED NOT NULL DEFAULT 0,
  `refunded_quantity` INT UNSIGNED NOT NULL DEFAULT 0,
  
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_order` (`order_id`),
  KEY `idx_product` (`product_id`),
  
  CONSTRAINT `fk_order_items_order` FOREIGN KEY (`order_id`) 
    REFERENCES `orders` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_order_items_product` FOREIGN KEY (`product_id`) 
    REFERENCES `products` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- COMPLETION
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 1;

SELECT 'Migration 001: Initial Schema - Completed Successfully' AS status;
