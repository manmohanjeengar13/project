-- ============================================================================
-- Migration 003: Analytics & Supporting Tables
-- ============================================================================
-- Creates analytics, webhooks, notifications, and utility tables
-- Version: 1.0.0
-- Date: 2024-01-01
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- ANALYTICS & TRACKING
-- ============================================================================

-- Page Views - Website analytics
CREATE TABLE IF NOT EXISTS `page_views` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  
  -- Page Information
  `url` VARCHAR(500) NOT NULL,
  `path` VARCHAR(500) NOT NULL,
  `page_title` VARCHAR(200) DEFAULT NULL,
  `referrer` VARCHAR(500) DEFAULT NULL,
  `referrer_domain` VARCHAR(255) DEFAULT NULL,
  
  -- Query Parameters
  `query_string` VARCHAR(500) DEFAULT NULL,
  `utm_source` VARCHAR(100) DEFAULT NULL,
  `utm_medium` VARCHAR(100) DEFAULT NULL,
  `utm_campaign` VARCHAR(100) DEFAULT NULL,
  `utm_term` VARCHAR(100) DEFAULT NULL,
  `utm_content` VARCHAR(100) DEFAULT NULL,
  
  -- User Context
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `device_type` VARCHAR(50) DEFAULT NULL,
  `browser` VARCHAR(50) DEFAULT NULL,
  `browser_version` VARCHAR(20) DEFAULT NULL,
  `operating_system` VARCHAR(50) DEFAULT NULL,
  `os_version` VARCHAR(20) DEFAULT NULL,
  `screen_resolution` VARCHAR(20) DEFAULT NULL,
  `viewport_size` VARCHAR(20) DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `region` VARCHAR(100) DEFAULT NULL,
  `latitude` DECIMAL(10, 8) DEFAULT NULL,
  `longitude` DECIMAL(11, 8) DEFAULT NULL,
  
  -- Performance Metrics
  `load_time` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  `dom_load_time` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  `first_paint` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  `first_contentful_paint` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  `time_to_interactive` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  
  -- Engagement Metrics
  `time_on_page` INT UNSIGNED DEFAULT NULL COMMENT 'seconds',
  `scroll_depth` TINYINT UNSIGNED DEFAULT NULL COMMENT '0-100%',
  `bounce` BOOLEAN DEFAULT FALSE,
  `exit_page` BOOLEAN DEFAULT FALSE,
  
  -- Timestamps
  `viewed_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `exit_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_session` (`session_id`),
  KEY `idx_path` (`path`(255)),
  KEY `idx_viewed_at` (`viewed_at`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_referrer_domain` (`referrer_domain`),
  KEY `idx_device_type` (`device_type`),
  KEY `idx_bounce` (`bounce`),
  
  CONSTRAINT `fk_page_views_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Search Queries - Search analytics
CREATE TABLE IF NOT EXISTS `search_queries` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  
  -- Search Information
  `query` VARCHAR(500) NOT NULL,
  `query_normalized` VARCHAR(500) DEFAULT NULL,
  `query_language` VARCHAR(10) DEFAULT NULL,
  `results_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `has_results` BOOLEAN GENERATED ALWAYS AS (`results_count` > 0) STORED,
  
  -- Search Context
  `search_type` ENUM('products', 'articles', 'users', 'global') DEFAULT 'products',
  `category` VARCHAR(50) DEFAULT NULL,
  `filters` JSON DEFAULT NULL,
  `sort_by` VARCHAR(50) DEFAULT NULL,
  `page` INT UNSIGNED DEFAULT 1,
  `per_page` INT UNSIGNED DEFAULT 20,
  
  -- Context
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `referrer` VARCHAR(500) DEFAULT NULL,
  
  -- Results Interaction
  `clicked_result_id` BIGINT UNSIGNED DEFAULT NULL,
  `clicked_result_position` INT UNSIGNED DEFAULT NULL,
  `clicked_result_rank` INT UNSIGNED DEFAULT NULL,
  `time_to_click` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  `results_viewed` INT UNSIGNED DEFAULT 0,
  
  -- Search Quality Metrics
  `search_duration` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  `refined_search` BOOLEAN DEFAULT FALSE COMMENT 'User modified search',
  `abandoned` BOOLEAN DEFAULT FALSE COMMENT 'No clicks',
  `conversion` BOOLEAN DEFAULT FALSE COMMENT 'Led to purchase/action',
  
  -- Suggestions & Autocomplete
  `suggestion_used` BOOLEAN DEFAULT FALSE,
  `suggestion_text` VARCHAR(255) DEFAULT NULL,
  `autocomplete_used` BOOLEAN DEFAULT FALSE,
  
  -- Timestamps
  `searched_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_session` (`session_id`),
  KEY `idx_query` (`query`(255)),
  KEY `idx_searched_at` (`searched_at`),
  KEY `idx_has_results` (`has_results`),
  KEY `idx_search_type` (`search_type`),
  FULLTEXT KEY `idx_fulltext_query` (`query`),
  FULLTEXT KEY `idx_fulltext_normalized` (`query_normalized`),
  
  CONSTRAINT `fk_search_queries_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Event Tracking - Custom event analytics
CREATE TABLE IF NOT EXISTS `event_tracking` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  
  -- Event Information
  `event_name` VARCHAR(100) NOT NULL,
  `event_category` VARCHAR(50) NOT NULL,
  `event_action` VARCHAR(100) DEFAULT NULL,
  `event_label` VARCHAR(255) DEFAULT NULL,
  `event_value` DECIMAL(15, 2) DEFAULT NULL,
  
  -- Event Properties
  `properties` JSON DEFAULT NULL,
  `metadata` JSON DEFAULT NULL,
  
  -- Context
  `page_url` VARCHAR(500) DEFAULT NULL,
  `page_path` VARCHAR(500) DEFAULT NULL,
  `referrer` VARCHAR(500) DEFAULT NULL,
  
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `device_type` VARCHAR(50) DEFAULT NULL,
  
  -- Timestamps
  `event_timestamp` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_session` (`session_id`),
  KEY `idx_event_name` (`event_name`),
  KEY `idx_event_category` (`event_category`),
  KEY `idx_event_timestamp` (`event_timestamp`),
  
  CONSTRAINT `fk_event_tracking_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- NOTIFICATIONS & COMMUNICATIONS
-- ============================================================================

-- Notifications
CREATE TABLE IF NOT EXISTS `notifications` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Notification Content
  `type` VARCHAR(50) NOT NULL,
  `title` VARCHAR(200) NOT NULL,
  `message` TEXT NOT NULL,
  `data` JSON DEFAULT NULL,
  `icon` VARCHAR(100) DEFAULT NULL,
  `image` VARCHAR(500) DEFAULT NULL,
  
  -- Notification Channels
  `channel` ENUM('in_app', 'email', 'sms', 'push', 'webhook') NOT NULL DEFAULT 'in_app',
  `channels_sent` JSON DEFAULT NULL COMMENT 'Track multi-channel',
  
  -- Priority & Category
  `priority` ENUM('low', 'medium', 'high', 'urgent') NOT NULL DEFAULT 'medium',
  `category` VARCHAR(50) DEFAULT NULL,
  
  -- Action
  `action_url` VARCHAR(500) DEFAULT NULL,
  `action_text` VARCHAR(50) DEFAULT NULL,
  `action_data` JSON DEFAULT NULL,
  
  -- Status
  `is_read` BOOLEAN NOT NULL DEFAULT FALSE,
  `read_at` DATETIME DEFAULT NULL,
  `is_archived` BOOLEAN NOT NULL DEFAULT FALSE,
  `archived_at` DATETIME DEFAULT NULL,
  `is_dismissed` BOOLEAN NOT NULL DEFAULT FALSE,
  `dismissed_at` DATETIME DEFAULT NULL,
  
  -- Delivery Status
  `delivery_status` ENUM('pending', 'sent', 'delivered', 'failed', 'bounced') DEFAULT 'pending',
  `delivered_at` DATETIME DEFAULT NULL,
  `failure_reason` VARCHAR(500) DEFAULT NULL,
  `retry_count` TINYINT UNSIGNED DEFAULT 0,
  
  -- Grouping
  `group_key` VARCHAR(100) DEFAULT NULL COMMENT 'Group related notifications',
  `parent_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `scheduled_at` DATETIME DEFAULT NULL COMMENT 'Scheduled delivery time',
  `expires_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_type` (`type`),
  KEY `idx_is_read` (`is_read`),
  KEY `idx_priority` (`priority`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_channel` (`channel`),
  KEY `idx_delivery_status` (`delivery_status`),
  KEY `idx_group_key` (`group_key`),
  KEY `idx_composite` (`user_id`, `is_read`, `created_at`),
  
  CONSTRAINT `fk_notifications_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_notifications_parent` FOREIGN KEY (`parent_id`) 
    REFERENCES `notifications` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- WEBHOOKS & INTEGRATIONS
-- ============================================================================

-- Webhooks
CREATE TABLE IF NOT EXISTS `webhooks` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Webhook Configuration
  `name` VARCHAR(100) NOT NULL,
  `description` TEXT DEFAULT NULL,
  `url` VARCHAR(500) NOT NULL,
  `secret` VARCHAR(64) NOT NULL COMMENT 'HMAC signature secret',
  `secret_algorithm` VARCHAR(20) DEFAULT 'sha256',
  
  -- Events
  `events` JSON NOT NULL COMMENT 'Subscribed events',
  `event_filters` JSON DEFAULT NULL COMMENT 'Filter conditions',
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_verified` BOOLEAN NOT NULL DEFAULT FALSE,
  `verification_token` VARCHAR(64) DEFAULT NULL,
  `verified_at` DATETIME DEFAULT NULL,
  
  -- HTTP Configuration
  `http_method` VARCHAR(10) DEFAULT 'POST',
  `content_type` VARCHAR(50) DEFAULT 'application/json',
  `custom_headers` JSON DEFAULT NULL,
  `timeout` INT UNSIGNED DEFAULT 30 COMMENT 'seconds',
  
  -- Retry Configuration
  `max_retries` TINYINT UNSIGNED NOT NULL DEFAULT 3,
  `retry_delay` INT UNSIGNED NOT NULL DEFAULT 300 COMMENT 'seconds',
  `retry_backoff` ENUM('linear', 'exponential') DEFAULT 'exponential',
  
  -- Rate Limiting
  `rate_limit` INT UNSIGNED DEFAULT NULL COMMENT 'max per hour',
  `rate_limit_period` INT UNSIGNED DEFAULT 3600 COMMENT 'seconds',
  
  -- Statistics
  `total_deliveries` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `successful_deliveries` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `failed_deliveries` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `total_retries` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `last_delivery_at` DATETIME DEFAULT NULL,
  `last_success_at` DATETIME DEFAULT NULL,
  `last_failure_at` DATETIME DEFAULT NULL,
  `consecutive_failures` INT UNSIGNED DEFAULT 0,
  
  -- Health Monitoring
  `health_status` ENUM('healthy', 'degraded', 'unhealthy', 'disabled') DEFAULT 'healthy',
  `last_health_check` DATETIME DEFAULT NULL,
  `auto_disable_on_failure` BOOLEAN DEFAULT TRUE,
  `failure_threshold` TINYINT UNSIGNED DEFAULT 10,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_triggered_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_health_status` (`health_status`),
  
  CONSTRAINT `fk_webhooks_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Webhook Logs
CREATE TABLE IF NOT EXISTS `webhook_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `webhook_id` INT UNSIGNED NOT NULL,
  
  -- Event Details
  `event_id` VARCHAR(100) NOT NULL UNIQUE,
  `event_type` VARCHAR(50) NOT NULL,
  `payload` JSON NOT NULL,
  
  -- Delivery Details
  `url` VARCHAR(500) NOT NULL,
  `http_method` VARCHAR(10) NOT NULL DEFAULT 'POST',
  `request_headers` JSON DEFAULT NULL,
  `request_body` MEDIUMTEXT DEFAULT NULL,
  `request_signature` VARCHAR(128) DEFAULT NULL,
  
  -- Response Details
  `response_status` INT DEFAULT NULL,
  `response_headers` JSON DEFAULT NULL,
  `response_body` TEXT DEFAULT NULL,
  `response_time` INT UNSIGNED DEFAULT NULL COMMENT 'ms',
  
  -- Status
  `status` ENUM('pending', 'success', 'failed', 'retrying', 'cancelled') NOT NULL DEFAULT 'pending',
  `retry_count` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `error_message` TEXT DEFAULT NULL,
  `error_code` VARCHAR(50) DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `delivered_at` DATETIME DEFAULT NULL,
  `next_retry_at` DATETIME DEFAULT NULL,
  `completed_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_event_id` (`event_id`),
  KEY `idx_webhook` (`webhook_id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_status` (`status`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_next_retry` (`next_retry_at`),
  
  CONSTRAINT `fk_webhook_logs_webhook` FOREIGN KEY (`webhook_id`) 
    REFERENCES `webhooks` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- CART & WISHLIST
-- ============================================================================

-- Cart Items
CREATE TABLE IF NOT EXISTS `cart_items` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  `product_id` BIGINT UNSIGNED NOT NULL,
  
  -- Cart Details
  `quantity` INT UNSIGNED NOT NULL DEFAULT 1,
  `unit_price` DECIMAL(15, 2) NOT NULL,
  `attributes` JSON DEFAULT NULL,
  `customization` JSON DEFAULT NULL,
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `saved_for_later` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `expires_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_session` (`session_id`),
  KEY `idx_product` (`product_id`),
  KEY `idx_expires_at` (`expires_at`),
  
  CONSTRAINT `fk_cart_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_cart_product` FOREIGN KEY (`product_id`) 
    REFERENCES `products` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    
  CONSTRAINT `chk_cart_identifier` CHECK (`user_id` IS NOT NULL OR `session_id` IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Wishlists
CREATE TABLE IF NOT EXISTS `wishlists` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `product_id` BIGINT UNSIGNED NOT NULL,
  
  -- Wishlist Details
  `priority` TINYINT UNSIGNED NOT NULL DEFAULT 1,
  `notes` TEXT DEFAULT NULL,
  `notify_on_sale` BOOLEAN NOT NULL DEFAULT FALSE,
  `notify_on_restock` BOOLEAN NOT NULL DEFAULT FALSE,
  `price_alert_threshold` DECIMAL(15, 2) DEFAULT NULL,
  
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
    REFERENCES `products` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- SETTINGS & CONFIGURATION
-- ============================================================================

-- Settings
CREATE TABLE IF NOT EXISTS `settings` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Setting Information
  `key` VARCHAR(100) NOT NULL UNIQUE,
  `value` TEXT DEFAULT NULL,
  `value_type` ENUM('string', 'number', 'boolean', 'json', 'encrypted') NOT NULL DEFAULT 'string',
  
  -- Metadata
  `category` VARCHAR(50) NOT NULL DEFAULT 'general',
  `group` VARCHAR(50) DEFAULT NULL,
  `description` VARCHAR(500) DEFAULT NULL,
  `is_public` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_encrypted` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_required` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Validation
  `validation_rules` JSON DEFAULT NULL,
  `default_value` TEXT DEFAULT NULL,
  `allowed_values` JSON DEFAULT NULL,
  
  -- Display
  `display_order` INT DEFAULT 0,
  `display_name` VARCHAR(100) DEFAULT NULL,
  `help_text` VARCHAR(500) DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updated_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_key` (`key`),
  KEY `idx_category` (`category`),
  KEY `idx_is_public` (`is_public`),
  KEY `idx_group` (`group`),
  
  CONSTRAINT `fk_settings_updated_by` FOREIGN KEY (`updated_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Coupons
CREATE TABLE IF NOT EXISTS `coupons` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Coupon Identification
  `code` VARCHAR(50) NOT NULL UNIQUE,
  `name` VARCHAR(200) NOT NULL,
  `description` TEXT DEFAULT NULL,
  
  -- Discount Configuration
  `discount_type` ENUM('percentage', 'fixed_amount', 'free_shipping', 'buy_x_get_y') NOT NULL,
  `discount_value` DECIMAL(10, 2) NOT NULL,
  `max_discount_amount` DECIMAL(10, 2) DEFAULT NULL,
  
  -- Usage Restrictions
  `min_purchase_amount` DECIMAL(10, 2) DEFAULT NULL,
  `max_purchase_amount` DECIMAL(10, 2) DEFAULT NULL,
  `usage_limit` INT UNSIGNED DEFAULT NULL,
  `usage_limit_per_user` INT UNSIGNED DEFAULT 1,
  `usage_count` INT UNSIGNED NOT NULL DEFAULT 0,
  
  -- Applicable Products/Categories
  `applies_to` ENUM('all', 'specific_products', 'specific_categories') NOT NULL DEFAULT 'all',
  `product_ids` JSON DEFAULT NULL,
  `category_ids` JSON DEFAULT NULL,
  `excluded_product_ids` JSON DEFAULT NULL,
  `excluded_category_ids` JSON DEFAULT NULL,
  
  -- Customer Restrictions
  `customer_eligibility` ENUM('all', 'new_customers', 'existing_customers', 'specific_users') NOT NULL DEFAULT 'all',
  `eligible_user_ids` JSON DEFAULT NULL,
  
  -- Date Restrictions
  `valid_from` DATETIME DEFAULT NULL,
  `valid_until` DATETIME DEFAULT NULL,
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_featured` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_combinable` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_code` (`code`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_valid_dates` (`valid_from`, `valid_until`),
  
  CONSTRAINT `fk_coupons_created_by` FOREIGN KEY (`created_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Coupon Usage
CREATE TABLE IF NOT EXISTS `coupon_usage` (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Files
CREATE TABLE IF NOT EXISTS `files` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- File Information
  `filename` VARCHAR(255) NOT NULL,
  `original_filename` VARCHAR(255) NOT NULL,
  `file_path` VARCHAR(500) NOT NULL,
  `file_url` VARCHAR(500) NOT NULL,
  `mime_type` VARCHAR(100) NOT NULL,
  `file_size` BIGINT UNSIGNED NOT NULL,
  `file_extension` VARCHAR(10) NOT NULL,
  
  -- File Type
  `file_type` ENUM('image', 'video', 'audio', 'document', 'archive', 'other') NOT NULL,
  `is_public` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_temporary` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Image-specific
  `width` INT UNSIGNED DEFAULT NULL,
  `height` INT UNSIGNED DEFAULT NULL,
  `thumbnail_path` VARCHAR(500) DEFAULT NULL,
  
  -- Security
  `hash` VARCHAR(64) NOT NULL,
  `virus_scan_status` ENUM('pending', 'clean', 'infected', 'error') DEFAULT 'pending',
  `virus_scan_at` DATETIME DEFAULT NULL,
  
  -- Usage
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
  KEY `idx_expires_at` (`expires_at`),
  
  CONSTRAINT `fk_files_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Admin Notes
CREATE TABLE IF NOT EXISTS `admin_notes` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  `admin_id` BIGINT UNSIGNED NOT NULL,
  
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
  
  CONSTRAINT `fk_admin_notes_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_admin_notes_admin` FOREIGN KEY (`admin_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- COMPLETION
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 1;

SELECT 'Migration 003: Analytics & Supporting Tables - Completed Successfully' AS status;
