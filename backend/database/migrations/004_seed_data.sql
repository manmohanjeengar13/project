-- ============================================================================
-- Migration 004: Seed Data
-- ============================================================================
-- Populates database with initial demo data for testing and demonstration
-- Version: 1.0.0
-- Date: 2024-01-01
-- 
-- WARNING: This seed data is for DEVELOPMENT AND DEMO purposes only!
-- DO NOT use in production environments
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- USERS - Demo accounts with various roles
-- ============================================================================

INSERT INTO `users` (
  `username`, `email`, `password`, `first_name`, `last_name`, 
  `role`, `is_active`, `is_email_verified`, `member_since`, `created_at`
) VALUES
-- Super Admin (password: Admin@123456)
('admin', 'admin@sqli-demo.local', '$2b$10$xQx5kWZE6n5Z/EqYQZ5YJ.5YW5YW5YW5YW5YW5YW5YW5YW5YW5YW5', 'System', 'Administrator', 'super_admin', TRUE, TRUE, NOW(), NOW()),

-- Moderator (password: Moderator@123)
('moderator', 'moderator@sqli-demo.local', '$2b$10$yRy6lXAF7o6A/FrARBZZK.6ZX6ZX6ZX6ZX6ZX6ZX6ZX6ZX6ZX6ZX6', 'John', 'Moderator', 'moderator', TRUE, TRUE, NOW(), NOW()),

-- Regular Users (password: User@123456)
('john_doe', 'john.doe@example.com', '$2b$10$zSz7mYBG8p7B/GsBRCAAL.7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7', 'John', 'Doe', 'customer', TRUE, TRUE, NOW(), NOW()),
('jane_smith', 'jane.smith@example.com', '$2b$10$aTa8nZCH9q8C/HtCSDBBM.8B8B8B8B8B8B8B8B8B8B8B8B8B8B8B8', 'Jane', 'Smith', 'customer', TRUE, TRUE, NOW(), NOW()),
('bob_johnson', 'bob.johnson@example.com', '$2b$10$bUb9oADI0r9D/IuDTECCN.9C9C9C9C9C9C9C9C9C9C9C9C9C9C9C9', 'Bob', 'Johnson', 'customer', TRUE, TRUE, NOW(), NOW()),
('alice_wilson', 'alice.wilson@example.com', '$2b$10$cVc0pBEJ1s0E/JvEUFDDO.0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0', 'Alice', 'Wilson', 'customer', TRUE, TRUE, NOW(), NOW()),
('charlie_brown', 'charlie.brown@example.com', '$2b$10$dWd1qCFK2t1F/KwFVGEEP.1E1E1E1E1E1E1E1E1E1E1E1E1E1E1E1', 'Charlie', 'Brown', 'customer', TRUE, FALSE, NOW(), NOW()),

-- Test Account for SQLi (password: test123)
('testuser', 'test@sqli-demo.local', '$2b$10$eXe2rDGL3u2G/LxGWHFFQ.2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2', 'Test', 'User', 'customer', TRUE, TRUE, NOW(), NOW()),

-- Inactive Account
('inactive_user', 'inactive@example.com', '$2b$10$fYf3sEHM4v3H/MyHXIGGR.3G3G3G3G3G3G3G3G3G3G3G3G3G3G3G3', 'Inactive', 'User', 'customer', FALSE, FALSE, NOW(), NOW());

-- Update user IDs for referential integrity
UPDATE `users` SET `referral_code` = CONCAT('REF', LPAD(id, 6, '0')) WHERE `referral_code` IS NULL;

-- ============================================================================
-- CATEGORIES - Product categorization
-- ============================================================================

INSERT INTO `categories` (`name`, `slug`, `description`, `sort_order`, `level`, `is_active`, `is_featured`) VALUES
-- Main Categories (Level 0)
('Electronics', 'electronics', 'Electronic devices and accessories', 1, 0, TRUE, TRUE),
('Clothing', 'clothing', 'Fashion and apparel', 2, 0, TRUE, TRUE),
('Home & Garden', 'home-garden', 'Home improvement and gardening supplies', 3, 0, TRUE, FALSE),
('Sports & Outdoors', 'sports-outdoors', 'Sports equipment and outdoor gear', 4, 0, TRUE, FALSE),
('Books', 'books', 'Books and educational materials', 5, 0, TRUE, FALSE),
('Toys & Games', 'toys-games', 'Toys, games, and hobbies', 6, 0, TRUE, FALSE);

-- Subcategories (Level 1)
INSERT INTO `categories` (`parent_id`, `name`, `slug`, `description`, `sort_order`, `level`, `is_active`) VALUES
(1, 'Computers', 'computers', 'Desktop and laptop computers', 1, 1, TRUE),
(1, 'Smartphones', 'smartphones', 'Mobile phones and accessories', 2, 1, TRUE),
(1, 'Audio', 'audio', 'Headphones, speakers, and audio equipment', 3, 1, TRUE),
(2, 'Men\'s Clothing', 'mens-clothing', 'Clothing for men', 1, 1, TRUE),
(2, 'Women\'s Clothing', 'womens-clothing', 'Clothing for women', 2, 1, TRUE),
(2, 'Accessories', 'accessories', 'Fashion accessories', 3, 1, TRUE);

-- ============================================================================
-- PRODUCTS - Demo product catalog
-- ============================================================================

INSERT INTO `products` (
  `category_id`, `sku`, `name`, `slug`, `description`, `short_description`,
  `base_price`, `sale_price`, `stock_quantity`, `status`, `is_featured`,
  `main_image`, `rating_average`, `view_count`, `created_by`
) VALUES
-- Electronics
(7, 'LAPTOP-001', 'Professional Laptop 15"', 'professional-laptop-15', 
 'High-performance laptop with 16GB RAM, 512GB SSD, and Intel i7 processor. Perfect for professional work and gaming.',
 'Powerful laptop for professionals',
 1299.99, 1199.99, 50, 'active', TRUE,
 '/images/products/laptop-001.jpg', 4.5, 1250, 1),

(8, 'PHONE-001', 'Smartphone Pro Max', 'smartphone-pro-max',
 'Latest flagship smartphone with 6.7" OLED display, 5G connectivity, and triple camera system.',
 'Premium smartphone experience',
 999.99, NULL, 100, 'active', TRUE,
 '/images/products/phone-001.jpg', 4.8, 3200, 1),

(9, 'HEADPHONE-001', 'Wireless Noise-Cancelling Headphones', 'wireless-nc-headphones',
 'Premium over-ear headphones with active noise cancellation, 30-hour battery life.',
 'Superior audio quality',
 349.99, 299.99, 75, 'active', TRUE,
 '/images/products/headphone-001.jpg', 4.7, 890, 1),

-- Clothing
(10, 'SHIRT-001', 'Classic Cotton T-Shirt', 'classic-cotton-tshirt',
 'Comfortable 100% cotton t-shirt available in multiple colors and sizes.',
 'Everyday comfort',
 19.99, NULL, 500, 'active', FALSE,
 '/images/products/shirt-001.jpg', 4.2, 450, 1),

(11, 'DRESS-001', 'Summer Floral Dress', 'summer-floral-dress',
 'Beautiful floral print dress perfect for summer occasions.',
 'Elegant summer wear',
 79.99, 59.99, 80, 'active', TRUE,
 '/images/products/dress-001.jpg', 4.6, 620, 1),

(12, 'WATCH-001', 'Luxury Analog Watch', 'luxury-analog-watch',
 'Elegant stainless steel watch with leather strap.',
 'Timeless elegance',
 249.99, NULL, 30, 'active', FALSE,
 '/images/products/watch-001.jpg', 4.4, 340, 1),

-- More Products
(7, 'TABLET-001', 'Tablet Pro 11"', 'tablet-pro-11',
 '11-inch tablet with M1 chip, 128GB storage, and Apple Pencil support.',
 'Powerful portable computing',
 799.99, 749.99, 60, 'active', TRUE,
 '/images/products/tablet-001.jpg', 4.6, 890, 1),

(8, 'PHONE-002', 'Budget Smartphone', 'budget-smartphone',
 'Affordable smartphone with essential features and long battery life.',
 'Great value smartphone',
 299.99, NULL, 200, 'active', FALSE,
 '/images/products/phone-002.jpg', 4.0, 1100, 1),

(9, 'SPEAKER-001', 'Portable Bluetooth Speaker', 'portable-bluetooth-speaker',
 'Waterproof wireless speaker with 12-hour battery life.',
 'Music on the go',
 79.99, 69.99, 150, 'active', FALSE,
 '/images/products/speaker-001.jpg', 4.3, 560, 1),

(10, 'JEANS-001', 'Classic Denim Jeans', 'classic-denim-jeans',
 'Comfortable slim-fit jeans made from premium denim.',
 'Timeless style',
 59.99, NULL, 250, 'active', FALSE,
 '/images/products/jeans-001.jpg', 4.5, 780, 1);

-- ============================================================================
-- REVIEWS - Product reviews
-- ============================================================================

INSERT INTO `reviews` (
  `product_id`, `user_id`, `title`, `comment`, `rating`, 
  `status`, `is_verified_purchase`
) VALUES
(1, 3, 'Excellent laptop!', 'This laptop exceeded my expectations. Fast, reliable, and great value for money.', 5, 'approved', TRUE),
(1, 4, 'Good performance', 'Great laptop for work and gaming. Battery life could be better.', 4, 'approved', TRUE),
(2, 3, 'Best phone I\'ve owned', 'The camera quality is amazing and the screen is beautiful.', 5, 'approved', TRUE),
(2, 5, 'Worth the price', 'Expensive but worth every penny. Face ID works flawlessly.', 5, 'approved', TRUE),
(3, 4, 'Great sound quality', 'Noise cancellation is impressive. Very comfortable for long use.', 5, 'approved', TRUE),
(3, 6, 'Good headphones', 'Sound quality is excellent, but they feel a bit heavy after long use.', 4, 'approved', TRUE),
(4, 3, 'Perfect basic tee', 'Soft, comfortable, and fits well. Great for everyday wear.', 4, 'approved', TRUE),
(5, 4, 'Beautiful dress', 'Love the print and the fit. Perfect for summer events.', 5, 'approved', TRUE),
(7, 5, 'Perfect for work', 'Use it for design work and it handles everything smoothly.', 5, 'approved', TRUE),
(8, 6, 'Great value', 'Does everything I need without breaking the bank.', 4, 'approved', TRUE);

-- ============================================================================
-- ORDERS - Sample orders
-- ============================================================================

INSERT INTO `orders` (
  `user_id`, `order_number`, `status`, `payment_status`,
  `subtotal`, `tax_amount`, `shipping_amount`, `total_amount`,
  `payment_method`,
  `shipping_first_name`, `shipping_last_name`, `shipping_email`, `shipping_phone`,
  `shipping_address_line1`, `shipping_city`, `shipping_state`, `shipping_postal_code`, `shipping_country`,
  `billing_first_name`, `billing_last_name`, `billing_email`, `billing_phone`,
  `billing_address_line1`, `billing_city`, `billing_state`, `billing_postal_code`, `billing_country`
) VALUES
(3, 'ORD-20240101-0001', 'delivered', 'paid',
 1199.99, 120.00, 10.00, 1329.99, 'credit_card',
 'John', 'Doe', 'john.doe@example.com', '+1234567890',
 '123 Main Street', 'New York', 'NY', '10001', 'US',
 'John', 'Doe', 'john.doe@example.com', '+1234567890',
 '123 Main Street', 'New York', 'NY', '10001', 'US'),

(4, 'ORD-20240102-0002', 'shipped', 'paid',
 999.99, 100.00, 10.00, 1109.99, 'paypal',
 'Jane', 'Smith', 'jane.smith@example.com', '+1234567891',
 '456 Oak Avenue', 'Los Angeles', 'CA', '90001', 'US',
 'Jane', 'Smith', 'jane.smith@example.com', '+1234567891',
 '456 Oak Avenue', 'Los Angeles', 'CA', '90001', 'US'),

(5, 'ORD-20240103-0003', 'processing', 'paid',
 299.99, 30.00, 10.00, 339.99, 'credit_card',
 'Bob', 'Johnson', 'bob.johnson@example.com', '+1234567892',
 '789 Pine Road', 'Chicago', 'IL', '60601', 'US',
 'Bob', 'Johnson', 'bob.johnson@example.com', '+1234567892',
 '789 Pine Road', 'Chicago', 'IL', '60601', 'US');

-- ============================================================================
-- ORDER ITEMS
-- ============================================================================

INSERT INTO `order_items` (
  `order_id`, `product_id`, `product_name`, `product_sku`,
  `unit_price`, `quantity`, `subtotal`, `tax_amount`, `total_amount`
) VALUES
(1, 1, 'Professional Laptop 15"', 'LAPTOP-001', 1199.99, 1, 1199.99, 120.00, 1319.99),
(2, 2, 'Smartphone Pro Max', 'PHONE-001', 999.99, 1, 999.99, 100.00, 1099.99),
(3, 3, 'Wireless Noise-Cancelling Headphones', 'HEADPHONE-001', 299.99, 1, 299.99, 30.00, 329.99);

-- ============================================================================
-- COUPONS - Promotional codes
-- ============================================================================

INSERT INTO `coupons` (
  `code`, `name`, `description`, `discount_type`, `discount_value`,
  `min_purchase_amount`, `usage_limit`, `valid_from`, `valid_until`,
  `is_active`, `is_featured`, `created_by`
) VALUES
('WELCOME10', 'Welcome Discount', 'Get 10% off your first order', 'percentage', 10.00, 50.00, NULL, NOW(), DATE_ADD(NOW(), INTERVAL 1 YEAR), TRUE, TRUE, 1),
('SAVE20', 'Save $20', 'Get $20 off orders over $100', 'fixed_amount', 20.00, 100.00, 1000, NOW(), DATE_ADD(NOW(), INTERVAL 6 MONTH), TRUE, TRUE, 1),
('FREESHIP', 'Free Shipping', 'Free shipping on all orders', 'free_shipping', 0.00, 25.00, NULL, NOW(), DATE_ADD(NOW(), INTERVAL 1 YEAR), TRUE, FALSE, 1),
('SUMMER25', 'Summer Sale', '25% off summer collection', 'percentage', 25.00, NULL, 500, NOW(), DATE_ADD(NOW(), INTERVAL 3 MONTH), TRUE, TRUE, 1),
('EXPIRED', 'Expired Coupon', 'This coupon has expired (for testing)', 'percentage', 50.00, NULL, 10, DATE_SUB(NOW(), INTERVAL 1 MONTH), DATE_SUB(NOW(), INTERVAL 1 DAY), FALSE, FALSE, 1);

-- ============================================================================
-- SETTINGS - Application configuration
-- ============================================================================

INSERT INTO `settings` (`key`, `value`, `value_type`, `category`, `description`, `is_public`) VALUES
-- General Settings
('site_name', 'SQLi Demo Platform', 'string', 'general', 'Website name', TRUE),
('site_tagline', 'Enterprise Security Training Platform', 'string', 'general', 'Website tagline', TRUE),
('site_description', 'Military-grade SQL Injection demonstration platform for security education', 'string', 'general', 'Website description', TRUE),
('admin_email', 'admin@sqli-demo.local', 'string', 'general', 'Administrator email', FALSE),
('support_email', 'support@sqli-demo.local', 'string', 'general', 'Support email', TRUE),
('contact_phone', '+1-800-SECURITY', 'string', 'general', 'Contact phone number', TRUE),

-- Security Settings
('security_mode', 'vulnerable', 'string', 'security', 'Current security mode (vulnerable/secure)', TRUE),
('enable_registration', 'true', 'boolean', 'security', 'Allow new user registrations', TRUE),
('enable_2fa', 'false', 'boolean', 'security', 'Enable two-factor authentication', TRUE),
('max_login_attempts', '5', 'number', 'security', 'Maximum failed login attempts', FALSE),
('lockout_duration', '30', 'number', 'security', 'Account lockout duration (minutes)', FALSE),
('session_timeout', '3600', 'number', 'security', 'Session timeout (seconds)', FALSE),
('password_min_length', '8', 'number', 'security', 'Minimum password length', FALSE),
('enable_rate_limiting', 'true', 'boolean', 'security', 'Enable API rate limiting', TRUE),
('enable_csrf_protection', 'false', 'boolean', 'security', 'Enable CSRF protection', FALSE),

-- E-commerce Settings
('default_currency', 'USD', 'string', 'ecommerce', 'Default currency code', TRUE),
('currency_symbol', '$', 'string', 'ecommerce', 'Currency symbol', TRUE),
('tax_rate', '10.00', 'number', 'ecommerce', 'Default tax rate (%)', FALSE),
('shipping_cost', '10.00', 'number', 'ecommerce', 'Standard shipping cost', TRUE),
('free_shipping_threshold', '100.00', 'number', 'ecommerce', 'Free shipping minimum', TRUE),
('enable_guest_checkout', 'true', 'boolean', 'ecommerce', 'Allow guest checkout', TRUE),

-- Notification Settings
('enable_email_notifications', 'true', 'boolean', 'notifications', 'Enable email notifications', FALSE),
('enable_sms_notifications', 'false', 'boolean', 'notifications', 'Enable SMS notifications', FALSE),
('enable_push_notifications', 'true', 'boolean', 'notifications', 'Enable push notifications', FALSE),
('notification_email_from', 'noreply@sqli-demo.local', 'string', 'notifications', 'From email address', FALSE),

-- Feature Flags
('enable_reviews', 'true', 'boolean', 'features', 'Enable product reviews', TRUE),
('enable_wishlists', 'true', 'boolean', 'features', 'Enable wishlists', TRUE),
('enable_coupons', 'true', 'boolean', 'features', 'Enable coupon codes', TRUE),
('enable_loyalty_points', 'true', 'boolean', 'features', 'Enable loyalty points', TRUE),
('enable_webhooks', 'true', 'boolean', 'features', 'Enable webhook integrations', FALSE),

-- Analytics Settings
('enable_analytics', 'true', 'boolean', 'analytics', 'Enable analytics tracking', TRUE),
('analytics_sample_rate', '1.0', 'number', 'analytics', 'Analytics sampling rate', FALSE),
('enable_page_tracking', 'true', 'boolean', 'analytics', 'Track page views', TRUE),
('enable_event_tracking', 'true', 'boolean', 'analytics', 'Track custom events', TRUE),

-- Maintenance Settings
('maintenance_mode', 'false', 'boolean', 'maintenance', 'Enable maintenance mode', TRUE),
('maintenance_message', 'System under maintenance', 'string', 'maintenance', 'Maintenance message', TRUE),
('allow_admin_access_during_maintenance', 'true', 'boolean', 'maintenance', 'Allow admin access', FALSE);

-- ============================================================================
-- ATTACK LOGS - Sample attack data for demonstration
-- ============================================================================

INSERT INTO `attack_logs` (
  `attack_type`, `severity`, `payload`, `patterns`,
  `endpoint`, `http_method`, `ip_address`, `user_agent`,
  `was_blocked`, `timestamp`
) VALUES
('AUTH_BYPASS_ATTEMPT', 'critical', 
 JSON_OBJECT('username', 'admin\'--', 'password', 'anything'),
 JSON_ARRAY(JSON_OBJECT('category', 'AUTH_BYPASS', 'pattern', 'admin\'--')),
 '/api/v1/auth/login', 'POST', '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
 FALSE, DATE_SUB(NOW(), INTERVAL 1 HOUR)),

('SQLI_UNION', 'high',
 JSON_OBJECT('search', '\' UNION SELECT NULL--'),
 JSON_ARRAY(JSON_OBJECT('category', 'UNION_BASED', 'pattern', 'UNION SELECT')),
 '/api/v1/users/search', 'GET', '192.168.1.101', 'curl/7.68.0',
 FALSE, DATE_SUB(NOW(), INTERVAL 2 HOUR)),

('XSS_REFLECTED', 'medium',
 JSON_OBJECT('comment', '<script>alert("XSS")</script>'),
 JSON_ARRAY(JSON_OBJECT('category', 'XSS', 'pattern', '<script>')),
 '/api/v1/reviews', 'POST', '192.168.1.102', 'Mozilla/5.0',
 TRUE, DATE_SUB(NOW(), INTERVAL 3 HOUR));

-- ============================================================================
-- SECURITY EVENTS - Sample security events
-- ============================================================================

INSERT INTO `security_events` (
  `user_id`, `event_type`, `event_category`, `severity`,
  `description`, `ip_address`, `was_successful`, `timestamp`
) VALUES
(1, 'login', 'authentication', 'info', 'Admin user logged in successfully', '127.0.0.1', TRUE, DATE_SUB(NOW(), INTERVAL 1 DAY)),
(3, 'password_change', 'authentication', 'warning', 'User changed password', '192.168.1.50', TRUE, DATE_SUB(NOW(), INTERVAL 2 DAY)),
(NULL, 'failed_login', 'authentication', 'warning', 'Failed login attempt for unknown user', '192.168.1.100', FALSE, DATE_SUB(NOW(), INTERVAL 3 HOUR)),
(4, 'data_export', 'data_access', 'info', 'User exported order history', '192.168.1.60', TRUE, DATE_SUB(NOW(), INTERVAL 5 HOUR));

-- ============================================================================
-- LOGIN HISTORY - Sample login attempts
-- ============================================================================

INSERT INTO `login_history` (
  `user_id`, `username`, `ip_address`, `user_agent`,
  `success`, `timestamp`
) VALUES
(1, 'admin', '127.0.0.1', 'Mozilla/5.0', TRUE, DATE_SUB(NOW(), INTERVAL 1 HOUR)),
(3, 'john_doe', '192.168.1.50', 'Mozilla/5.0', TRUE, DATE_SUB(NOW(), INTERVAL 2 HOUR)),
(4, 'jane_smith', '192.168.1.51', 'Mozilla/5.0', TRUE, DATE_SUB(NOW(), INTERVAL 3 HOUR)),
(NULL, 'attacker', '192.168.1.100', 'curl/7.68.0', FALSE, DATE_SUB(NOW(), INTERVAL 4 HOUR)),
(NULL, 'admin\'--', '192.168.1.100', 'curl/7.68.0', FALSE, DATE_SUB(NOW(), INTERVAL 4 HOUR));

-- ============================================================================
-- PAGE VIEWS - Sample analytics data
-- ============================================================================

INSERT INTO `page_views` (
  `user_id`, `url`, `path`, `page_title`, `ip_address`,
  `device_type`, `browser`, `viewed_at`
) VALUES
(3, 'http://localhost:4000/products', '/products', 'Products', '192.168.1.50', 'desktop', 'Chrome', DATE_SUB(NOW(), INTERVAL 1 HOUR)),
(3, 'http://localhost:4000/products/1', '/products/1', 'Professional Laptop', '192.168.1.50', 'desktop', 'Chrome', DATE_SUB(NOW(), INTERVAL 50 MINUTE)),
(4, 'http://localhost:4000/', '/', 'Home', '192.168.1.51', 'mobile', 'Safari', DATE_SUB(NOW(), INTERVAL 2 HOUR)),
(NULL, 'http://localhost:4000/products', '/products', 'Products', '192.168.1.80', 'desktop', 'Firefox', DATE_SUB(NOW(), INTERVAL 3 HOUR));

-- ============================================================================
-- SEARCH QUERIES - Sample search data
-- ============================================================================

INSERT INTO `search_queries` (
  `user_id`, `query`, `results_count`, `search_type`,
  `ip_address`, `searched_at`
) VALUES
(3, 'laptop', 5, 'products', '192.168.1.50', DATE_SUB(NOW(), INTERVAL 1 HOUR)),
(4, 'wireless headphones', 3, 'products', '192.168.1.51', DATE_SUB(NOW(), INTERVAL 2 HOUR)),
(NULL, 'smartphone', 8, 'products', '192.168.1.80', DATE_SUB(NOW(), INTERVAL 3 HOUR)),
(3, '\' OR 1=1--', 0, 'products', '192.168.1.50', DATE_SUB(NOW(), INTERVAL 30 MINUTE));

-- ============================================================================
-- NOTIFICATIONS - Sample user notifications
-- ============================================================================

INSERT INTO `notifications` (
  `user_id`, `type`, `title`, `message`, `priority`,
  `action_url`, `is_read`
) VALUES
(3, 'order_update', 'Order Shipped', 'Your order #ORD-20240101-0001 has been shipped!', 'high', '/orders/1', TRUE),
(3, 'promotion', 'Special Offer', 'Get 25% off on summer collection', 'medium', '/products?category=summer', FALSE),
(4, 'order_update', 'Order Confirmed', 'Your order #ORD-20240102-0002 has been confirmed', 'high', '/orders/2', TRUE),
(5, 'security_alert', 'New Login', 'New login from Chicago, IL', 'high', '/account/security', FALSE);

-- ============================================================================
-- CART ITEMS - Sample cart data
-- ============================================================================

INSERT INTO `cart_items` (
  `user_id`, `product_id`, `quantity`, `unit_price`
) VALUES
(6, 1, 1, 1199.99),
(6, 3, 1, 299.99),
(7, 2, 1, 999.99);

-- ============================================================================
-- WISHLISTS - Sample wishlist data
-- ============================================================================

INSERT INTO `wishlists` (
  `user_id`, `product_id`, `priority`, `notify_on_sale`
) VALUES
(3, 7, 5, TRUE),
(4, 2, 4, TRUE),
(5, 1, 3, FALSE),
(6, 3, 5, TRUE);

-- ============================================================================
-- UPDATE STATISTICS
-- ============================================================================

-- Update product statistics
UPDATE `products` SET 
  `rating_count` = (SELECT COUNT(*) FROM `reviews` WHERE `product_id` = `products`.`id` AND `status` = 'approved'),
  `review_count` = (SELECT COUNT(*) FROM `reviews` WHERE `product_id` = `products`.`id` AND `status` = 'approved'),
  `rating_average` = (SELECT COALESCE(AVG(`rating`), 0) FROM `reviews` WHERE `product_id` = `products`.`id` AND `status` = 'approved');

-- Update user statistics
UPDATE `users` SET
  `total_orders` = (SELECT COUNT(*) FROM `orders` WHERE `user_id` = `users`.`id`),
  `total_spent` = (SELECT COALESCE(SUM(`total_amount`), 0) FROM `orders` WHERE `user_id` = `users`.`id` AND `status` = 'delivered');

-- Update category product counts
UPDATE `categories` SET
  `product_count` = (SELECT COUNT(*) FROM `products` WHERE `category_id` = `categories`.`id` AND `deleted_at` IS NULL);

-- ============================================================================
-- COMPLETION MESSAGE
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 1;

SELECT CONCAT('
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ✅ SEED DATA LOADED SUCCESSFULLY                                   ║
║                                                                      ║
║   📊 Statistics:                                                     ║
║   • Users: ', (SELECT COUNT(*) FROM users), ' accounts created                                        ║
║   • Products: ', (SELECT COUNT(*) FROM products), ' items in catalog                                    ║
║   • Categories: ', (SELECT COUNT(*) FROM categories), ' categories                                           ║
║   • Orders: ', (SELECT COUNT(*) FROM orders), ' sample orders                                             ║
║   • Reviews: ', (SELECT COUNT(*) FROM reviews), ' product reviews                                        ║
║   • Coupons: ', (SELECT COUNT(*) FROM coupons), ' promotional codes                                       ║
║                                                                      ║
║   🔐 Demo Credentials:                                               ║
║   • Admin: admin / Admin@123456                                     ║
║   • Moderator: moderator / Moderator@123                            ║
║   • User: john_doe / User@123456                                    ║
║   • Test: testuser / test123                                        ║
║                                                                      ║
║   ⚠️  WARNING: FOR DEVELOPMENT USE ONLY!                            ║
║   DO NOT use this seed data in production!                          ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
') AS 'Seed Status';
