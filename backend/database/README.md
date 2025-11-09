# 🗄️ Database Documentation

## Overview

Military-grade database schema and seeding system for the SQLi Demo Platform. This database is designed with enterprise-level features including comprehensive security logging, audit trails, and analytics.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Schema Overview](#schema-overview)
- [Migrations](#migrations)
- [Seeding](#seeding)
- [Tables Reference](#tables-reference)
- [Security Features](#security-features)
- [Performance Optimization](#performance-optimization)
- [Maintenance](#maintenance)

## 🚀 Quick Start

### Prerequisites

- MySQL 8.0+ or MariaDB 10.5+
- Node.js 18+
- Database user with CREATE/ALTER/DROP privileges

### Initial Setup

```bash
# 1. Create database
mysql -u root -p
CREATE DATABASE sqli_demo_platform CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON sqli_demo_platform.* TO 'sqli_user'@'localhost' IDENTIFIED BY 'your_password';
FLUSH PRIVILEGES;
EXIT;

# 2. Configure environment
cp .env.example .env
# Edit .env with your database credentials

# 3. Run migrations
cd backend
npm run migrate

# 4. Seed demo data
npm run seed
```

### Quick Commands

```bash
# Seed all data
npm run seed

# Seed specific data
node database/seed.js --users
node database/seed.js --products

# Fresh seed (clean + seed)
npm run seed --fresh

# Clean database
node database/seed.js --clean

# Show statistics
node database/seed.js --stats
```

## 📊 Schema Overview

### Database Structure

- **30+ Tables**: Comprehensive data model
- **4 Views**: Pre-aggregated analytics
- **4 Stored Procedures**: Complex operations
- **5 Triggers**: Automated data management
- **3 Scheduled Events**: Maintenance tasks

### Key Features

✅ **ACID Compliance**: Full transaction support
✅ **Foreign Key Constraints**: Referential integrity
✅ **Soft Deletes**: Data recovery capability
✅ **Audit Trails**: Complete change history
✅ **Full-Text Search**: Optimized search indexes
✅ **Partitioning**: Large table optimization
✅ **JSON Support**: Flexible data storage

## 🗂️ Migrations

### Available Migrations

1. **001_initial_schema.sql** - Core tables (users, products, orders)
2. **002_security_tables.sql** - Security & logging tables
3. **003_analytics_tables.sql** - Analytics & tracking
4. **004_seed_data.sql** - Initial demo data

### Running Migrations

```bash
# Run all migrations
npm run migrate

# Run specific migration
mysql -u sqli_user -p sqli_demo_platform < database/migrations/001_initial_schema.sql

# Check migration status
mysql -u sqli_user -p -e "SELECT * FROM sqli_demo_platform.migrations;"
```

### Creating New Migrations

```bash
# Create migration file
touch database/migrations/005_your_migration.sql

# Add migration header
-- ============================================================================
-- Migration 005: Your Migration Name
-- ============================================================================
-- Description of what this migration does
-- Version: 1.0.0
-- Date: 2024-01-01
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- Your migration code here

SET FOREIGN_KEY_CHECKS = 1;
SELECT 'Migration 005: Your Migration Name - Completed' AS status;
```

## 🌱 Seeding

### Seed Modules

| Module | Description | Dependencies |
|--------|-------------|--------------|
| `users.seed.js` | User accounts | None |
| `categories.seed.js` | Product categories | None |
| `products.seed.js` | Product catalog | Categories |
| `orders.seed.js` | Sample orders | Users, Products |

### Custom Seeding

```javascript
// database/seeds/custom.seed.js
import { Database } from '../../src/core/Database.js';
import { Logger } from '../../src/core/Logger.js';

const db = Database.getInstance();
const logger = Logger.getInstance();

export async function seedCustomData() {
  try {
    logger.info('🌱 Seeding custom data...');
    
    // Your seeding logic here
    
    logger.info('✅ Custom data seeded');
    return { success: true };
  } catch (error) {
    logger.error('❌ Custom seeding failed:', error);
    throw error;
  }
}

export default seedCustomData;
```

### Demo Credentials

After seeding, use these credentials:

| Role | Username | Password | Purpose |
|------|----------|----------|---------|
| Super Admin | `admin` | `Admin@123456` | Full system access |
| Moderator | `moderator` | `Moderator@123` | Content moderation |
| Customer | `john_doe` | `User@123456` | Regular user |
| Test Account | `testuser` | `test123` | Testing purposes |

## 📚 Tables Reference

### Core Tables

#### Users & Authentication
- `users` - User accounts and profiles
- `user_sessions` - Active login sessions
- `login_history` - Login attempt tracking
- `api_tokens` - API access tokens

#### E-Commerce
- `categories` - Product categories (hierarchical)
- `products` - Product catalog
- `reviews` - Product reviews and ratings
- `orders` - Customer orders
- `order_items` - Order line items
- `coupons` - Discount codes
- `cart_items` - Shopping cart
- `wishlists` - User wishlists

#### Security & Logging
- `attack_logs` - Security attack detection
- `security_events` - Security-related events
- `audit_logs` - Complete audit trail
- `ip_blacklist` - Blocked IP addresses
- `rate_limits` - Rate limiting tracking

#### Analytics
- `page_views` - Page view tracking
- `search_queries` - Search analytics
- `event_tracking` - Custom event tracking

#### System
- `settings` - Application configuration
- `notifications` - User notifications
- `webhooks` - Webhook integrations
- `files` - File uploads
- `admin_notes` - Admin notes about users

### Database Views

```sql
-- Pre-aggregated analytics views

-- Admin Dashboard
SELECT * FROM admin_dashboard_view;

-- Product Statistics
SELECT * FROM product_stats_view;

-- User Activity
SELECT * FROM user_activity_view;

-- Attack Summary
SELECT * FROM attack_summary_view;
```

### Stored Procedures

```sql
-- Create an order
CALL sp_create_order(
  @user_id, @cart_items, @shipping_address, 
  @billing_address, @payment_method, @coupon_code,
  @order_id, @order_number, @total_amount
);

-- Apply coupon
CALL sp_apply_coupon(
  @coupon_code, @user_id, @subtotal,
  @discount_amount, @is_valid, @error_message
);

-- Calculate shipping
CALL sp_calculate_shipping(
  @destination_zip, @weight, @shipping_cost
);
```

## 🔐 Security Features

### Attack Detection

The database includes comprehensive attack logging:

```sql
-- View recent attacks
SELECT 
  attack_type, 
  severity, 
  ip_address,
  COUNT(*) as attempts
FROM attack_logs
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY attack_type, severity, ip_address
ORDER BY attempts DESC;
```

### Audit Trail

All critical operations are logged:

```sql
-- View user modifications
SELECT 
  u.username,
  al.action,
  al.entity_type,
  al.changed_fields,
  al.created_at
FROM audit_logs al
JOIN users u ON al.user_id = u.id
WHERE al.entity_type = 'user'
  AND al.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
ORDER BY al.created_at DESC;
```

### IP Blacklisting

Automatic and manual IP blocking:

```sql
-- Block an IP address
INSERT INTO ip_blacklist (
  ip_address, reason, severity, is_permanent
) VALUES (
  '192.168.1.100', 
  'Multiple SQL injection attempts', 
  'critical', 
  FALSE
);

-- View blocked IPs
SELECT * FROM ip_blacklist WHERE is_active = TRUE;
```

## ⚡ Performance Optimization

### Indexes

All critical columns are indexed:

- Primary keys on all tables
- Foreign key indexes
- Composite indexes for common queries
- Full-text indexes for search
- Covering indexes for analytics

### Partitioning

Large tables use partitioning:

```sql
-- Attack logs partitioned by month
ALTER TABLE attack_logs PARTITION BY RANGE (TO_DAYS(timestamp)) (
  PARTITION p_2024_01 VALUES LESS THAN (TO_DAYS('2024-02-01')),
  PARTITION p_2024_02 VALUES LESS THAN (TO_DAYS('2024-03-01')),
  ...
);
```

### Query Optimization

```sql
-- Use EXPLAIN to analyze queries
EXPLAIN SELECT * FROM products 
WHERE category_id = 1 
  AND status = 'active'
  AND deleted_at IS NULL;

-- Check slow queries
SHOW FULL PROCESSLIST;
SELECT * FROM mysql.slow_log ORDER BY query_time DESC LIMIT 10;
```

## 🔧 Maintenance

### Automated Maintenance

Scheduled events handle routine tasks:

```sql
-- Cleanup expired sessions (daily)
EVENT evt_cleanup_expired_sessions
  EVERY 1 DAY

-- Cleanup old carts (weekly)
EVENT evt_cleanup_old_carts
  EVERY 1 WEEK

-- Cleanup old logs (monthly)
EVENT evt_cleanup_old_logs
  EVERY 1 MONTH
```

### Manual Maintenance

```bash
# Optimize tables
npm run db:optimize

# Backup database
npm run backup:db

# Check database health
npm run db:check

# Repair tables
npm run db:repair
```

### Backup Strategy

```bash
# Full backup
mysqldump -u sqli_user -p sqli_demo_platform > backup_$(date +%Y%m%d_%H%M%S).sql

# Backup with compression
mysqldump -u sqli_user -p sqli_demo_platform | gzip > backup_$(date +%Y%m%d).sql.gz

# Restore from backup
mysql -u sqli_user -p sqli_demo_platform < backup.sql
```

### Data Cleanup

```sql
-- Clean old attack logs (keep 90 days)
DELETE FROM attack_logs 
WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);

-- Clean expired sessions
DELETE FROM user_sessions 
WHERE expires_at < NOW();

-- Archive old orders
INSERT INTO orders_archive 
SELECT * FROM orders 
WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 YEAR);
```

## 📊 Monitoring

### Database Statistics

```bash
# Show database stats
node database/seed.js --stats

# Check table sizes
mysql -u sqli_user -p -e "
SELECT 
  table_name AS 'Table',
  ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)',
  table_rows AS 'Rows'
FROM information_schema.TABLES
WHERE table_schema = 'sqli_demo_platform'
ORDER BY (data_length + index_length) DESC;
"
```

### Performance Monitoring

```sql
-- Check query cache
SHOW STATUS LIKE 'Qcache%';

-- Check connection stats
SHOW STATUS LIKE 'Connections';
SHOW STATUS LIKE 'Threads%';

-- Check slow queries
SHOW VARIABLES LIKE 'slow_query%';
SELECT * FROM mysql.slow_log ORDER BY query_time DESC LIMIT 10;
```

## 🐛 Troubleshooting

### Common Issues

**Connection Errors**
```bash
# Check MySQL service
sudo systemctl status mysql

# Test connection
mysql -u sqli_user -p -h localhost
```

**Migration Failures**
```bash
# Check foreign key constraints
SET FOREIGN_KEY_CHECKS = 0;
# Run migration
SET FOREIGN_KEY_CHECKS = 1;
```

**Seeding Errors**
```bash
# Clear and reseed
node database/seed.js --fresh --force

# Check for duplicate data
SELECT username, COUNT(*) FROM users GROUP BY username HAVING COUNT(*) > 1;
```

### Debug Mode

```bash
# Enable query logging
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'TABLE';

# View queries
SELECT * FROM mysql.general_log ORDER BY event_time DESC LIMIT 100;

# Disable when done
SET GLOBAL general_log = 'OFF';
```

## 📖 Additional Resources

- [MySQL Documentation](https://dev.mysql.com/doc/)
- [Database Design Best Practices](https://www.mysql.com/products/enterprise/design.html)
- [SQL Performance Tuning](https://dev.mysql.com/doc/refman/8.0/en/optimization.html)
- [Security Best Practices](https://dev.mysql.com/doc/refman/8.0/en/security.html)

## 🤝 Contributing

When adding new tables or modifying the schema:

1. Create a new migration file
2. Update this README
3. Add seed data if applicable
4. Update the ER diagram
5. Test thoroughly in development
6. Document any breaking changes

## 📝 License

MIT License - see LICENSE file for details

---

**⚠️ IMPORTANT**: This database schema includes intentionally vulnerable patterns for educational purposes. Never use these patterns in production systems!
