-- ============================================================================
-- Migration 002: Security Tables
-- ============================================================================
-- Creates security-focused tables for attack detection, logging, and audit
-- Version: 1.0.0
-- Date: 2024-01-01
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- ATTACK DETECTION & LOGGING
-- ============================================================================

-- Attack Logs - Main security event logging
CREATE TABLE IF NOT EXISTS `attack_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Attack Classification
  `attack_type` VARCHAR(50) NOT NULL COMMENT 'sqli, xss, csrf, etc',
  `attack_category` ENUM('injection', 'broken_auth', 'sensitive_data', 'xxe', 'broken_access', 'security_misconfig', 'xss', 'insecure_deserialization', 'components', 'insufficient_logging') DEFAULT 'injection',
  `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  `owasp_category` VARCHAR(20) DEFAULT NULL COMMENT 'A01, A02, etc',
  `cwe_id` VARCHAR(20) DEFAULT NULL COMMENT 'CWE-89, etc',
  
  -- Attack Details
  `payload` JSON NOT NULL COMMENT 'Attack payload',
  `patterns` JSON DEFAULT NULL COMMENT 'Detected patterns',
  `attack_vector` VARCHAR(100) DEFAULT NULL,
  `attack_complexity` ENUM('low', 'medium', 'high') DEFAULT 'medium',
  `attack_score` INT UNSIGNED DEFAULT 0 COMMENT '0-100 threat score',
  
  -- Request Context
  `endpoint` VARCHAR(500) NOT NULL,
  `http_method` VARCHAR(10) NOT NULL,
  `request_headers` JSON DEFAULT NULL,
  `request_body` MEDIUMTEXT DEFAULT NULL,
  `query_params` JSON DEFAULT NULL,
  `url_path` VARCHAR(500) DEFAULT NULL,
  
  -- Attacker Information
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `region` VARCHAR(100) DEFAULT NULL,
  `latitude` DECIMAL(10, 8) DEFAULT NULL,
  `longitude` DECIMAL(11, 8) DEFAULT NULL,
  `isp` VARCHAR(200) DEFAULT NULL,
  `organization` VARCHAR(200) DEFAULT NULL,
  
  -- Response & Actions
  `was_blocked` BOOLEAN NOT NULL DEFAULT FALSE,
  `block_reason` VARCHAR(255) DEFAULT NULL,
  `response_action` VARCHAR(50) DEFAULT NULL COMMENT 'logged, blocked, honeypot, rate_limited',
  `response_code` INT DEFAULT NULL,
  `response_time` INT UNSIGNED DEFAULT NULL COMMENT 'Milliseconds',
  
  -- WAF/IDS Information
  `waf_rule_id` VARCHAR(50) DEFAULT NULL,
  `ids_signature` VARCHAR(100) DEFAULT NULL,
  `threat_intelligence_match` BOOLEAN DEFAULT FALSE,
  `threat_intel_sources` JSON DEFAULT NULL,
  
  -- Forensics
  `stack_trace` TEXT DEFAULT NULL,
  `debug_info` JSON DEFAULT NULL,
  `evidence` JSON DEFAULT NULL COMMENT 'Additional forensic data',
  
  -- Follow-up Actions
  `requires_review` BOOLEAN NOT NULL DEFAULT FALSE,
  `reviewed_by` BIGINT UNSIGNED DEFAULT NULL,
  `reviewed_at` DATETIME DEFAULT NULL,
  `review_notes` TEXT DEFAULT NULL,
  `incident_id` VARCHAR(50) DEFAULT NULL COMMENT 'Link to incident response',
  
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
  KEY `idx_was_blocked` (`was_blocked`),
  KEY `idx_attack_score` (`attack_score`),
  KEY `idx_requires_review` (`requires_review`),
  KEY `idx_country_code` (`country_code`),
  KEY `idx_composite` (`attack_type`, `severity`, `timestamp`),
  
  CONSTRAINT `fk_attack_logs_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_attack_logs_reviewed_by` FOREIGN KEY (`reviewed_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Comprehensive attack logging';

-- Partition attack_logs by month for better performance
ALTER TABLE `attack_logs` PARTITION BY RANGE (TO_DAYS(`timestamp`)) (
  PARTITION p_2024_01 VALUES LESS THAN (TO_DAYS('2024-02-01')),
  PARTITION p_2024_02 VALUES LESS THAN (TO_DAYS('2024-03-01')),
  PARTITION p_2024_03 VALUES LESS THAN (TO_DAYS('2024-04-01')),
  PARTITION p_2024_04 VALUES LESS THAN (TO_DAYS('2024-05-01')),
  PARTITION p_2024_05 VALUES LESS THAN (TO_DAYS('2024-06-01')),
  PARTITION p_2024_06 VALUES LESS THAN (TO_DAYS('2024-07-01')),
  PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- Security Events - General security event tracking
CREATE TABLE IF NOT EXISTS `security_events` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Event Classification
  `event_type` VARCHAR(50) NOT NULL COMMENT 'login, logout, password_change, etc',
  `event_category` ENUM('authentication', 'authorization', 'data_access', 'configuration', 'attack', 'compliance', 'privacy') NOT NULL,
  `severity` ENUM('info', 'warning', 'error', 'critical') NOT NULL DEFAULT 'info',
  `risk_level` ENUM('none', 'low', 'medium', 'high', 'critical') DEFAULT 'none',
  
  -- Event Details
  `description` TEXT DEFAULT NULL,
  `details` JSON DEFAULT NULL,
  `affected_resource` VARCHAR(200) DEFAULT NULL,
  `resource_type` VARCHAR(50) DEFAULT NULL,
  `action` VARCHAR(50) DEFAULT NULL COMMENT 'create, read, update, delete, execute',
  
  -- Request Context
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  `request_id` VARCHAR(100) DEFAULT NULL,
  `endpoint` VARCHAR(500) DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  
  -- Status & Results
  `was_successful` BOOLEAN NOT NULL DEFAULT TRUE,
  `failure_reason` VARCHAR(255) DEFAULT NULL,
  `status_code` INT DEFAULT NULL,
  
  -- Compliance & Regulatory
  `compliance_relevant` BOOLEAN NOT NULL DEFAULT FALSE,
  `compliance_frameworks` JSON DEFAULT NULL COMMENT 'GDPR, HIPAA, PCI-DSS, etc',
  `retention_required_until` DATE DEFAULT NULL,
  
  -- Correlation
  `correlation_id` VARCHAR(100) DEFAULT NULL COMMENT 'Link related events',
  `parent_event_id` BIGINT UNSIGNED DEFAULT NULL,
  
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
  KEY `idx_was_successful` (`was_successful`),
  KEY `idx_correlation_id` (`correlation_id`),
  KEY `idx_compliance` (`compliance_relevant`, `retention_required_until`),
  
  CONSTRAINT `fk_security_events_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_security_events_parent` FOREIGN KEY (`parent_event_id`) 
    REFERENCES `security_events` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit Logs - Comprehensive audit trail
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Audit Information
  `action` VARCHAR(50) NOT NULL COMMENT 'create, update, delete, view, export',
  `entity_type` VARCHAR(50) NOT NULL COMMENT 'user, product, order, etc',
  `entity_id` BIGINT UNSIGNED NOT NULL,
  `entity_name` VARCHAR(255) DEFAULT NULL,
  
  -- Change Tracking
  `old_values` JSON DEFAULT NULL COMMENT 'Previous state',
  `new_values` JSON DEFAULT NULL COMMENT 'New state',
  `changed_fields` JSON DEFAULT NULL COMMENT 'List of changed fields',
  `change_summary` VARCHAR(500) DEFAULT NULL,
  
  -- Request Context
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  `request_id` VARCHAR(100) DEFAULT NULL,
  `session_id` VARCHAR(100) DEFAULT NULL,
  `endpoint` VARCHAR(500) DEFAULT NULL,
  `http_method` VARCHAR(10) DEFAULT NULL,
  
  -- Additional Context
  `description` VARCHAR(500) DEFAULT NULL,
  `metadata` JSON DEFAULT NULL,
  `business_context` VARCHAR(255) DEFAULT NULL COMMENT 'Why the change was made',
  
  -- Approval Workflow
  `requires_approval` BOOLEAN NOT NULL DEFAULT FALSE,
  `approval_status` ENUM('pending', 'approved', 'rejected') DEFAULT NULL,
  `approved_by` BIGINT UNSIGNED DEFAULT NULL,
  `approved_at` DATETIME DEFAULT NULL,
  
  -- Compliance
  `is_sensitive` BOOLEAN NOT NULL DEFAULT FALSE,
  `data_classification` ENUM('public', 'internal', 'confidential', 'restricted') DEFAULT 'internal',
  `retention_period_days` INT DEFAULT 2555 COMMENT 'Default 7 years',
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_action` (`action`),
  KEY `idx_entity` (`entity_type`, `entity_id`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_entity_type` (`entity_type`),
  KEY `idx_is_sensitive` (`is_sensitive`),
  KEY `idx_approval_status` (`approval_status`),
  
  CONSTRAINT `fk_audit_logs_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_audit_logs_approved_by` FOREIGN KEY (`approved_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Login History - Detailed login tracking
CREATE TABLE IF NOT EXISTS `login_history` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED DEFAULT NULL,
  
  -- Login Attempt Details
  `username` VARCHAR(50) NOT NULL,
  `email` VARCHAR(255) DEFAULT NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `user_agent` VARCHAR(500) DEFAULT NULL,
  
  -- Device Information
  `device_type` VARCHAR(50) DEFAULT NULL,
  `device_model` VARCHAR(100) DEFAULT NULL,
  `browser` VARCHAR(50) DEFAULT NULL,
  `browser_version` VARCHAR(20) DEFAULT NULL,
  `operating_system` VARCHAR(50) DEFAULT NULL,
  `os_version` VARCHAR(20) DEFAULT NULL,
  `device_fingerprint` VARCHAR(64) DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `region` VARCHAR(100) DEFAULT NULL,
  `postal_code` VARCHAR(20) DEFAULT NULL,
  `timezone` VARCHAR(50) DEFAULT NULL,
  `isp` VARCHAR(200) DEFAULT NULL,
  
  -- Login Status
  `success` BOOLEAN NOT NULL,
  `failure_reason` VARCHAR(255) DEFAULT NULL,
  `error_code` VARCHAR(50) DEFAULT NULL,
  
  -- Authentication Methods
  `auth_method` VARCHAR(50) DEFAULT 'password' COMMENT 'password, oauth, 2fa, biometric',
  `mfa_used` BOOLEAN NOT NULL DEFAULT FALSE,
  `mfa_type` VARCHAR(50) DEFAULT NULL COMMENT 'totp, sms, email, hardware',
  `oauth_provider` VARCHAR(50) DEFAULT NULL COMMENT 'google, facebook, github',
  
  -- Risk Assessment
  `risk_score` TINYINT UNSIGNED DEFAULT 0 COMMENT '0-100',
  `risk_factors` JSON DEFAULT NULL COMMENT 'Unusual location, time, device, etc',
  `is_suspicious` BOOLEAN NOT NULL DEFAULT FALSE,
  `requires_verification` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Session Information
  `session_id` VARCHAR(100) DEFAULT NULL,
  `session_duration` INT UNSIGNED DEFAULT NULL COMMENT 'Seconds',
  `remember_me` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Tracking
  `attempt_number` TINYINT UNSIGNED DEFAULT 1 COMMENT 'Sequential attempt for this user',
  `is_first_login` BOOLEAN NOT NULL DEFAULT FALSE,
  `days_since_last_login` INT DEFAULT NULL,
  
  -- Timestamps
  `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `logout_at` DATETIME DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_username` (`username`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_success` (`success`),
  KEY `idx_timestamp` (`timestamp`),
  KEY `idx_device_fingerprint` (`device_fingerprint`),
  KEY `idx_is_suspicious` (`is_suspicious`),
  KEY `idx_risk_score` (`risk_score`),
  KEY `idx_composite` (`user_id`, `timestamp`, `success`),
  
  CONSTRAINT `fk_login_history_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP Blacklist - Blocked IP addresses
CREATE TABLE IF NOT EXISTS `ip_blacklist` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- IP Information
  `ip_address` VARCHAR(45) NOT NULL UNIQUE,
  `ip_range` VARCHAR(100) DEFAULT NULL COMMENT 'CIDR notation',
  `ip_type` ENUM('ipv4', 'ipv6') NOT NULL,
  
  -- Blacklist Details
  `reason` VARCHAR(255) NOT NULL,
  `attack_type` VARCHAR(50) DEFAULT NULL,
  `severity` ENUM('low', 'medium', 'high', 'critical') NOT NULL,
  `threat_level` TINYINT UNSIGNED DEFAULT 5 COMMENT '1-10 scale',
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_permanent` BOOLEAN NOT NULL DEFAULT FALSE,
  `is_automated` BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Auto-blocked by system',
  
  -- Statistics
  `total_attacks` INT UNSIGNED NOT NULL DEFAULT 0,
  `attack_types` JSON DEFAULT NULL COMMENT 'Types of attacks from this IP',
  `first_seen` DATETIME DEFAULT NULL,
  `last_attack_at` DATETIME DEFAULT NULL,
  
  -- Geolocation
  `country_code` VARCHAR(2) DEFAULT NULL,
  `country_name` VARCHAR(100) DEFAULT NULL,
  `city` VARCHAR(100) DEFAULT NULL,
  `isp` VARCHAR(200) DEFAULT NULL,
  `organization` VARCHAR(200) DEFAULT NULL,
  
  -- Threat Intelligence
  `threat_intel_match` BOOLEAN DEFAULT FALSE,
  `threat_intel_sources` JSON DEFAULT NULL COMMENT 'External threat feeds',
  `reputation_score` TINYINT DEFAULT NULL COMMENT '-100 to 100',
  
  -- Expiration & Review
  `blocked_until` DATETIME DEFAULT NULL,
  `expires_at` DATETIME DEFAULT NULL,
  `auto_unblock` BOOLEAN NOT NULL DEFAULT TRUE,
  `requires_manual_review` BOOLEAN NOT NULL DEFAULT FALSE,
  `reviewed_by` BIGINT UNSIGNED DEFAULT NULL,
  `reviewed_at` DATETIME DEFAULT NULL,
  `review_notes` TEXT DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` BIGINT UNSIGNED DEFAULT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_ip_address` (`ip_address`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_blocked_until` (`blocked_until`),
  KEY `idx_severity` (`severity`),
  KEY `idx_is_permanent` (`is_permanent`),
  KEY `idx_country_code` (`country_code`),
  KEY `idx_threat_level` (`threat_level`),
  
  CONSTRAINT `fk_ip_blacklist_created_by` FOREIGN KEY (`created_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_ip_blacklist_reviewed_by` FOREIGN KEY (`reviewed_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP Whitelist - Trusted IP addresses
CREATE TABLE IF NOT EXISTS `ip_whitelist` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- IP Information
  `ip_address` VARCHAR(45) NOT NULL UNIQUE,
  `ip_range` VARCHAR(100) DEFAULT NULL,
  `ip_type` ENUM('ipv4', 'ipv6') NOT NULL,
  
  -- Whitelist Details
  `label` VARCHAR(100) NOT NULL,
  `description` TEXT DEFAULT NULL,
  `reason` VARCHAR(255) NOT NULL,
  
  -- Permissions
  `bypass_rate_limiting` BOOLEAN NOT NULL DEFAULT TRUE,
  `bypass_waf` BOOLEAN NOT NULL DEFAULT FALSE,
  `bypass_2fa` BOOLEAN NOT NULL DEFAULT FALSE,
  `allowed_actions` JSON DEFAULT NULL,
  
  -- Organization
  `organization` VARCHAR(200) DEFAULT NULL,
  `contact_email` VARCHAR(255) DEFAULT NULL,
  `contact_phone` VARCHAR(20) DEFAULT NULL,
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_permanent` BOOLEAN NOT NULL DEFAULT FALSE,
  
  -- Expiration
  `valid_from` DATETIME DEFAULT NULL,
  `valid_until` DATETIME DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` BIGINT UNSIGNED NOT NULL,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_ip_address` (`ip_address`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_valid_until` (`valid_until`),
  
  CONSTRAINT `fk_ip_whitelist_created_by` FOREIGN KEY (`created_by`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rate Limits - Rate limiting tracking
CREATE TABLE IF NOT EXISTS `rate_limits` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  
  -- Identifier
  `identifier` VARCHAR(100) NOT NULL COMMENT 'IP, user ID, or API token',
  `identifier_type` ENUM('ip', 'user', 'api_token', 'session') NOT NULL,
  `identifier_hash` VARCHAR(64) NOT NULL COMMENT 'Hashed for privacy',
  
  -- Resource/Endpoint
  `resource` VARCHAR(200) NOT NULL COMMENT 'Endpoint or resource path',
  `resource_type` ENUM('api', 'web', 'download', 'upload', 'search') DEFAULT 'api',
  
  -- Rate Limit Configuration
  `limit_type` ENUM('requests', 'bandwidth', 'concurrent') NOT NULL DEFAULT 'requests',
  `window_size` INT UNSIGNED NOT NULL COMMENT 'Window size in seconds',
  `max_requests` INT UNSIGNED NOT NULL,
  
  -- Current State
  `request_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `bandwidth_used` BIGINT UNSIGNED DEFAULT 0 COMMENT 'Bytes',
  `concurrent_connections` INT UNSIGNED DEFAULT 0,
  `window_start` DATETIME NOT NULL,
  `window_end` DATETIME NOT NULL,
  
  -- Blocking
  `is_blocked` BOOLEAN NOT NULL DEFAULT FALSE,
  `blocked_at` DATETIME DEFAULT NULL,
  `blocked_until` DATETIME DEFAULT NULL,
  `block_reason` VARCHAR(255) DEFAULT NULL,
  
  -- Tracking
  `first_request_at` DATETIME DEFAULT NULL,
  `last_request_at` DATETIME DEFAULT NULL,
  `total_requests_all_time` BIGINT UNSIGNED DEFAULT 0,
  `total_blocks_all_time` INT UNSIGNED DEFAULT 0,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_rate_limit_unique` (`identifier_hash`, `resource`, `window_start`),
  KEY `idx_identifier` (`identifier`),
  KEY `idx_resource` (`resource`),
  KEY `idx_window_end` (`window_end`),
  KEY `idx_is_blocked` (`is_blocked`),
  KEY `idx_identifier_type` (`identifier_type`),
  KEY `idx_composite` (`identifier_hash`, `resource`, `is_blocked`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- API Tokens - Secure API authentication
CREATE TABLE IF NOT EXISTS `api_tokens` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` BIGINT UNSIGNED NOT NULL,
  
  -- Token Information
  `name` VARCHAR(100) NOT NULL COMMENT 'Descriptive name',
  `token_hash` VARCHAR(64) NOT NULL UNIQUE COMMENT 'SHA256 hash',
  `token_prefix` VARCHAR(10) NOT NULL COMMENT 'First chars for identification',
  `token_version` TINYINT UNSIGNED NOT NULL DEFAULT 1,
  
  -- Permissions & Scopes
  `scopes` JSON NOT NULL COMMENT 'Array of permission scopes',
  `permissions` JSON DEFAULT NULL COMMENT 'Fine-grained permissions',
  `rate_limit` INT UNSIGNED DEFAULT 60 COMMENT 'Requests per minute',
  `rate_limit_period` ENUM('second', 'minute', 'hour', 'day') DEFAULT 'minute',
  
  -- Restrictions
  `allowed_ips` JSON DEFAULT NULL COMMENT 'IP whitelist',
  `blocked_ips` JSON DEFAULT NULL COMMENT 'IP blacklist',
  `allowed_origins` JSON DEFAULT NULL COMMENT 'CORS origins',
  `allowed_methods` JSON DEFAULT NULL COMMENT 'HTTP methods',
  
  -- Usage Tracking
  `usage_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `last_used_at` DATETIME DEFAULT NULL,
  `last_used_ip` VARCHAR(45) DEFAULT NULL,
  `last_used_endpoint` VARCHAR(500) DEFAULT NULL,
  `total_bandwidth` BIGINT UNSIGNED DEFAULT 0 COMMENT 'Bytes',
  
  -- Rate Limiting Stats
  `last_hour_requests` INT UNSIGNED NOT NULL DEFAULT 0,
  `last_day_requests` INT UNSIGNED NOT NULL DEFAULT 0,
  `rate_limit_exceeded_count` INT UNSIGNED DEFAULT 0,
  
  -- Status
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `is_compromised` BOOLEAN NOT NULL DEFAULT FALSE,
  `compromise_reason` VARCHAR(255) DEFAULT NULL,
  `compromise_detected_at` DATETIME DEFAULT NULL,
  
  -- Expiration & Rotation
  `expires_at` DATETIME DEFAULT NULL,
  `rotation_required` BOOLEAN NOT NULL DEFAULT FALSE,
  `rotation_required_at` DATETIME DEFAULT NULL,
  `last_rotated_at` DATETIME DEFAULT NULL,
  
  -- Audit
  `revoked_at` DATETIME DEFAULT NULL,
  `revoked_by` BIGINT UNSIGNED DEFAULT NULL,
  `revoke_reason` VARCHAR(255) DEFAULT NULL,
  
  -- Metadata
  `description` TEXT DEFAULT NULL,
  `metadata` JSON DEFAULT NULL,
  `tags` JSON DEFAULT NULL,
  
  -- Timestamps
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_token_hash` (`token_hash`),
  KEY `idx_user` (`user_id`),
  KEY `idx_token_prefix` (`token_prefix`),
  KEY `idx_is_active` (`is_active`),
  KEY `idx_expires_at` (`expires_at`),
  KEY `idx_is_compromised` (`is_compromised`),
  
  CONSTRAINT `fk_api_tokens_user` FOREIGN KEY (`user_id`) 
    REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_api_tokens_revoked_by` FOREIGN KEY (`revoked_by`) 
    REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Additional composite indexes for common security queries
CREATE INDEX idx_attacks_ip_type_time ON attack_logs(ip_address, attack_type, timestamp);
CREATE INDEX idx_attacks_severity_time ON attack_logs(severity, timestamp);
CREATE INDEX idx_attacks_user_time ON attack_logs(user_id, timestamp) WHERE user_id IS NOT NULL;

CREATE INDEX idx_security_events_category_time ON security_events(event_category, timestamp);
CREATE INDEX idx_security_events_user_category ON security_events(user_id, event_category);

CREATE INDEX idx_login_history_user_success ON login_history(user_id, success, timestamp);
CREATE INDEX idx_login_history_ip_time ON login_history(ip_address, timestamp);

-- ============================================================================
-- COMPLETION
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 1;

SELECT 'Migration 002: Security Tables - Completed Successfully' AS status;
