
/**
 * Review Model - Enterprise Edition v3.0
 * Production-ready review management with advanced ML features
 * 
 * @module models/Review
 * @version 3.0.0
 * @license MIT
 */

import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';
import { Queue } from '../core/Queue.js';
import { Metrics } from '../core/Metrics.js';
import { EventBus } from '../core/EventBus.js';
import { RateLimiter } from '../core/RateLimiter.js';
import { AuditLogger } from '../core/AuditLogger.js';
import { SearchIndex } from '../core/SearchIndex.js';
import { tables } from '../config/database.js';
import { ValidationError, NotFoundError } from '../middleware/errorHandler.js';
import { EventEmitter } from 'events';
import crypto from 'crypto';

const db = Database.getInstance();
const logger = Logger.getInstance();
const cache = Cache.getInstance();
const queue = Queue.getInstance();
const metrics = Metrics.getInstance();
const eventBus = EventBus.getInstance();
const rateLimiter = RateLimiter.getInstance();
const auditLogger = AuditLogger.getInstance();
const searchIndex = SearchIndex.getInstance();

// ============================================================================
// CONSTANTS
// ============================================================================

export const REVIEW_STATUS = Object.freeze({
  PENDING: 'pending',
  APPROVED: 'approved',
  REJECTED: 'rejected',
  FLAGGED: 'flagged',
  SPAM: 'spam',
  HIDDEN: 'hidden',
  ARCHIVED: 'archived'
});

export const SENTIMENT = Object.freeze({
  VERY_POSITIVE: 'very_positive',
  POSITIVE: 'positive',
  NEUTRAL: 'neutral',
  NEGATIVE: 'negative',
  VERY_NEGATIVE: 'very_negative'
});

const CACHE_TTL = { REVIEW: 3600, REVIEWS_LIST: 1800, STATS: 7200 };
const SPAM_THRESHOLD = 0.70;
const AUTO_APPROVE_THRESHOLD = 0.80;

// ============================================================================
// REVIEW MODEL
// ============================================================================

export class Review extends EventEmitter {
  constructor(data = {}) {
    super();
    
    // Core
    this.id = data.id || null;
    this.productId = data.product_id || null;
    this.userId = data.user_id || null;
    this.orderId = data.order_id || null;
    
    // Content
    this.rating = parseFloat(data.rating) || 0;
    this.title = data.title?.trim() || null;
    this.content = data.content?.trim() || null;
    this.pros = this._parseJSON(data.pros, []);
    this.cons = this._parseJSON(data.cons, []);
    
    // Verification
    this.isVerifiedPurchase = Boolean(data.is_verified_purchase);
    this.isPremiumReview = Boolean(data.is_premium_review);
    
    // Moderation
    this.status = data.status || REVIEW_STATUS.PENDING;
    this.moderationNotes = data.moderation_notes || null;
    this.moderatedBy = data.moderated_by || null;
    this.moderatedAt = this._parseDate(data.moderated_at);
    
    // AI Scores
    this.sentimentScore = parseFloat(data.sentiment_score) || 0;
    this.sentiment = data.sentiment || SENTIMENT.NEUTRAL;
    this.qualityScore = parseFloat(data.quality_score) || 0;
    this.spamScore = parseFloat(data.spam_score) || 0;
    this.toxicityScore = parseFloat(data.toxicity_score) || 0;
    this.authenticityScore = parseFloat(data.authenticity_score) || 0;
    
    // Engagement
    this.helpfulCount = parseInt(data.helpful_count) || 0;
    this.notHelpfulCount = parseInt(data.not_helpful_count) || 0;
    this.reportCount = parseInt(data.report_count) || 0;
    this.viewCount = parseInt(data.view_count) || 0;
    this.shareCount = parseInt(data.share_count) || 0;
    this.replyCount = parseInt(data.reply_count) || 0;
    
    // Media
    this.images = this._parseJSON(data.images, []);
    this.videos = this._parseJSON(data.videos, []);
    
    // Metadata
    this.ipAddress = data.ip_address || null;
    this.userAgent = data.user_agent || null;
    this.language = data.language || 'en';
    this.deviceType = data.device_type || null;
    this.deviceFingerprint = data.device_fingerprint || null;
    
    // Rewards
    this.rewardPoints = parseInt(data.reward_points) || 0;
    this.hasReward = Boolean(data.has_reward);
    
    // Timestamps
    this.createdAt = this._parseDate(data.created_at);
    this.updatedAt = this._parseDate(data.updated_at);
    this.publishedAt = this._parseDate(data.published_at);
    
    // Internal
    this._isNew = !this.id;
    this._isDirty = false;
    this._user = null;
    this._product = null;
  }

  // ==========================================================================
  // HELPERS
  // ==========================================================================

  _parseJSON(value, defaultValue = null) {
    if (!value) return defaultValue;
    if (typeof value === 'object') return value;
    try { return JSON.parse(value); } catch { return defaultValue; }
  }

  _parseDate(value) {
    if (!value) return null;
    if (value instanceof Date) return value;
    const date = new Date(value);
    return isNaN(date.getTime()) ? null : date;
  }

  _formatDateForDB(date) {
    if (!date) return null;
    if (!(date instanceof Date)) date = new Date(date);
    return date.toISOString().slice(0, 19).replace('T', ' ');
  }

  // ==========================================================================
  // COMPUTED PROPERTIES
  // ==========================================================================

  get helpfulnessRatio() {
    const total = this.helpfulCount + this.notHelpfulCount;
    return total > 0 ? (this.helpfulCount / total) * 100 : 0;
  }

  get isApproved() { return this.status === REVIEW_STATUS.APPROVED; }
  get isPending() { return this.status === REVIEW_STATUS.PENDING; }
  get isSpam() { return this.status === REVIEW_STATUS.SPAM || this.spamScore > SPAM_THRESHOLD; }
  get isHighQuality() { return this.qualityScore >= 0.75 && this.characterCount >= 100; }
  get hasMedia() { return this.images.length > 0 || this.videos.length > 0; }
  get isPositive() { return this.rating >= 4; }
  get isNegative() { return this.rating <= 2; }
  
  get characterCount() { return this.content?.length || 0; }
  get wordCount() { return this.content?.trim().split(/\s+/).filter(w => w.length > 0).length || 0; }
  get sentenceCount() {
    if (!this.content) return 0;
    return this.content.split(/[.!?]+/).filter(s => s.trim().length > 0).length;
  }

  get readTimeMinutes() {
    const wordsPerMinute = 200;
    return Math.max(1, Math.ceil(this.wordCount / wordsPerMinute));
  }

  get trustScore() {
    let score = 50;
    if (this.isVerifiedPurchase) score += 20;
    if (this.qualityScore > 0.7) score += 15;
    if (this.spamScore < 0.3) score += 10;
    if (this.helpfulnessRatio > 70) score += 10;
    if (this.hasMedia) score += 5;
    if (this.spamScore > 0.5) score -= 30;
    if (this.reportCount > 0) score -= (this.reportCount * 5);
    if (this.toxicityScore > 0.5) score -= 20;
    return Math.max(0, Math.min(100, score));
  }

  get engagementScore() {
    const score = (
      this.helpfulCount * 3 +
      this.notHelpfulCount * 1 +
      this.viewCount * 0.1 +
      this.shareCount * 5 +
      this.replyCount * 4
    );
    return Math.min(100, Math.round(score / 10));
  }

  // ==========================================================================
  // VALIDATION
  // ==========================================================================

  validate() {
    const errors = [];

    if (!this.productId) errors.push('Product ID is required');
    if (!this.userId) errors.push('User ID is required');
    
    if (!this.rating || this.rating < 0.5 || this.rating > 5) {
      errors.push('Rating must be between 0.5 and 5');
    }
    
    if (this.rating % 0.5 !== 0) {
      errors.push('Rating must be in 0.5 increments (e.g., 3.5, 4.0)');
    }
    
    if (!this.content || this.content.trim().length < 10) {
      errors.push('Review content must be at least 10 characters');
    }
    
    if (this.content && this.content.length > 10000) {
      errors.push('Review content cannot exceed 10,000 characters');
    }
    
    if (this.title && this.title.length > 250) {
      errors.push('Review title cannot exceed 250 characters');
    }
    
    if (this.images.length > 15) {
      errors.push('Cannot upload more than 15 images');
    }

    if (errors.length > 0) {
      throw new ValidationError('Review validation failed', { errors });
    }

    return true;
  }

  // ==========================================================================
  // QUALITY SCORING
  // ==========================================================================

  calculateQualityScore() {
    const scores = {
      contentLength: this._scoreContentLength(),
      contentDepth: this._scoreContentDepth(),
      structure: this._scoreStructure(),
      mediaQuality: this._scoreMediaQuality(),
      verification: this._scoreVerification(),
      engagement: this._scoreEngagement(),
      readability: this._scoreReadability()
    };

    const weights = {
      contentLength: 0.18,
      contentDepth: 0.22,
      structure: 0.15,
      mediaQuality: 0.15,
      verification: 0.15,
      engagement: 0.10,
      readability: 0.05
    };

    this.qualityScore = Object.entries(scores).reduce((total, [key, score]) => {
      return total + (score * weights[key]);
    }, 0);

    if (this.spamScore > 0.5) this.qualityScore *= 0.5;
    if (this.toxicityScore > 0.5) this.qualityScore *= 0.6;

    this.qualityScore = Math.max(0, Math.min(1, this.qualityScore));
    return this.qualityScore;
  }

  _scoreContentLength() {
    const length = this.characterCount;
    if (length >= 200 && length <= 800) return 1.0;
    if (length >= 100 && length < 200) return 0.7;
    if (length >= 50 && length < 100) return 0.5;
    if (length > 800 && length <= 1500) return 0.8;
    return 0.3;
  }

  _scoreContentDepth() {
    let score = 0;
    if (this.pros.length > 0) score += 0.3;
    if (this.cons.length > 0) score += 0.3;
    if (this.pros.length >= 2 && this.cons.length >= 2) score += 0.2;
    if (this.sentenceCount >= 3) score += 0.2;
    return Math.min(1, score);
  }

  _scoreStructure() {
    let score = 0;
    if (this.title && this.title.length >= 10) score += 0.4;
    if (this.content?.includes('\n\n')) score += 0.3;
    if (this.pros.length > 0 || this.cons.length > 0) score += 0.3;
    return Math.min(1, score);
  }

  _scoreMediaQuality() {
    if (!this.hasMedia) return 0;
    let score = 0.5;
    if (this.images.length >= 2) score += 0.2;
    if (this.videos.length >= 1) score += 0.3;
    return Math.min(1, score);
  }

  _scoreVerification() {
    return this.isVerifiedPurchase ? 1.0 : 0.3;
  }

  _scoreEngagement() {
    if (this.helpfulCount === 0 && this.notHelpfulCount === 0) return 0.5;
    return Math.min(1, this.helpfulnessRatio / 100);
  }

  _scoreReadability() {
    const avgWordLen = this.characterCount / (this.wordCount || 1);
    const avgSentenceLen = this.wordCount / (this.sentenceCount || 1);
    const wordScore = avgWordLen >= 4 && avgWordLen <= 6 ? 1 : 0.5;
    const sentenceScore = avgSentenceLen >= 10 && avgSentenceLen <= 25 ? 1 : 0.6;
    return (wordScore + sentenceScore) / 2;
  }

  // ==========================================================================
  // SPAM DETECTION
  // ==========================================================================

  async detectSpam() {
    const indicators = [];

    // Excessive capitalization
    const capsRatio = (this.content?.match(/[A-Z]/g) || []).length / this.characterCount;
    if (capsRatio > 0.5) indicators.push({ type: 'caps', weight: 0.25 });

    // Excessive punctuation
    const excessPunct = (this.content?.match(/[!?]{3,}/g) || []).length;
    if (excessPunct > 2) indicators.push({ type: 'punctuation', weight: 0.20 });

    // URLs
    const urlPattern = /https?:\/\/[^\s]+/gi;
    const urlCount = (this.content?.match(urlPattern) || []).length;
    if (urlCount > 0) indicators.push({ type: 'url', weight: 0.35 });

    // Email addresses
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
    if (emailPattern.test(this.content)) indicators.push({ type: 'email', weight: 0.30 });

    // Phone numbers
    const phonePattern = /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
    if (phonePattern.test(this.content)) indicators.push({ type: 'phone', weight: 0.25 });

    // Repetitive content
    const words = this.content?.toLowerCase().split(/\s+/) || [];
    const uniqueWords = new Set(words);
    const repetitionRatio = 1 - (uniqueWords.size / (words.length || 1));
    if (repetitionRatio > 0.6) indicators.push({ type: 'repetition', weight: 0.30 });

    // Very short content
    if (this.characterCount < 15) indicators.push({ type: 'short', weight: 0.20 });

    // Spam keywords
    const spamPhrases = [
      'buy now', 'click here', 'limited time', 'act fast', 'free money',
      'work from home', 'make money', 'guarantee', 'promotion code'
    ];
    const spamMatches = spamPhrases.filter(phrase => 
      this.content?.toLowerCase().includes(phrase)
    );
    if (spamMatches.length > 0) {
      indicators.push({ type: 'spam_phrases', weight: 0.40 * spamMatches.length });
    }

    // Check spam database
    const spamHash = crypto.createHash('md5').update(this.content?.toLowerCase() || '').digest('hex');
    const isKnownSpam = await this._checkSpamDatabase(spamHash);
    if (isKnownSpam) indicators.push({ type: 'known_spam', weight: 0.90 });

    // User behavior
    const userSpamScore = await this._getUserSpamScore(this.userId);
    if (userSpamScore > 0.5) {
      indicators.push({ type: 'user_history', weight: 0.30 * userSpamScore });
    }

    this.spamScore = Math.min(1, indicators.reduce((sum, ind) => sum + ind.weight, 0));

    if (this.spamScore > 0.5) {
      logger.warn('High spam score detected', {
        reviewId: this.id,
        spamScore: this.spamScore,
        indicators: indicators.map(i => i.type)
      });
    }

    return {
      score: this.spamScore,
      isSpam: this.spamScore > SPAM_THRESHOLD,
      indicators: indicators.map(i => i.type)
    };
  }

  async _checkSpamDatabase(hash) {
    try {
      const cached = await cache.get(`spam:hash:${hash}`);
      if (cached !== null) return cached === 'true';

      const [results] = await db.execute(
        `SELECT id FROM spam_patterns WHERE content_hash = ? LIMIT 1`,
        [hash]
      );

      const isSpam = results.length > 0;
      await cache.set(`spam:hash:${hash}`, isSpam.toString(), 86400);
      return isSpam;
    } catch {
      return false;
    }
  }

  async _getUserSpamScore(userId) {
    try {
      const cacheKey = `user:${userId}:spam_score`;
      const cached = await cache.get(cacheKey);
      if (cached !== null) return parseFloat(cached);

      const [results] = await db.execute(
        `SELECT 
          COUNT(*) as total_reviews,
          SUM(CASE WHEN status = 'spam' THEN 1 ELSE 0 END) as spam_reviews,
          AVG(spam_score) as avg_spam_score
         FROM ${tables.REVIEWS}
         WHERE user_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 90 DAY)`,
        [userId]
      );

      if (results.length === 0 || results[0].total_reviews === 0) return 0;

      const data = results[0];
      const spamRatio = data.spam_reviews / data.total_reviews;
      const score = (spamRatio * 0.7) + (data.avg_spam_score * 0.3);

      await cache.set(cacheKey, score.toString(), 3600);
      return score;
    } catch {
      return 0;
    }
  }

  // ==========================================================================
  // SENTIMENT ANALYSIS
  // ==========================================================================

  async analyzeSentiment() {
    if (!this.content) {
      this.sentiment = SENTIMENT.NEUTRAL;
      this.sentimentScore = 0;
      return { sentiment: this.sentiment, score: 0 };
    }

    const text = this.content.toLowerCase();

    const positiveWords = {
      strong: ['excellent', 'amazing', 'outstanding', 'perfect', 'fantastic', 'superb', 'brilliant'],
      moderate: ['great', 'good', 'nice', 'love', 'recommend', 'happy', 'satisfied', 'pleased'],
      mild: ['okay', 'decent', 'fine', 'acceptable', 'adequate']
    };

    const negativeWords = {
      strong: ['terrible', 'awful', 'horrible', 'worst', 'hate', 'useless', 'garbage'],
      moderate: ['bad', 'poor', 'disappointing', 'regret', 'avoid', 'broken', 'defective'],
      mild: ['lacking', 'mediocre', 'subpar', 'underwhelming']
    };

    const intensifiers = ['very', 'extremely', 'incredibly', 'absolutely', 'completely'];
    const negations = ['not', 'never', 'no', "n't", 'neither', 'nor'];

    let positiveScore = 0;
    let negativeScore = 0;

    const sentences = this.content.split(/[.!?]+/).filter(s => s.trim().length > 0);

    sentences.forEach(sentence => {
      const words = sentence.toLowerCase().split(/\s+/);
      
      words.forEach((word, index) => {
        let multiplier = 1.0;
        let isNegated = false;

        // Check for negations
        for (let i = Math.max(0, index - 3); i < index; i++) {
          if (negations.includes(words[i])) {
            isNegated = true;
            break;
          }
        }

        // Check for intensifiers
        if (index > 0 && intensifiers.includes(words[index - 1])) {
          multiplier = 1.5;
        }

        // Score words
        if (positiveWords.strong.includes(word)) {
          positiveScore += (isNegated ? -3 : 3) * multiplier;
        } else if (positiveWords.moderate.includes(word)) {
          positiveScore += (isNegated ? -2 : 2) * multiplier;
        } else if (positiveWords.mild.includes(word)) {
          positiveScore += (isNegated ? -1 : 1) * multiplier;
        }

        if (negativeWords.strong.includes(word)) {
          negativeScore += (isNegated ? -3 : 3) * multiplier;
        } else if (negativeWords.moderate.includes(word)) {
          negativeScore += (isNegated ? -2 : 2) * multiplier;
        } else if (negativeWords.mild.includes(word)) {
          negativeScore += (isNegated ? -1 : 1) * multiplier;
        }
      });
    });

    // Factor in rating
    const ratingBias = (this.rating - 3) * 0.3;

    // Calculate final score
    const totalScore = positiveScore - negativeScore;
    const normalizedScore = totalScore / Math.max(1, Math.abs(totalScore) + 10);
    this.sentimentScore = Math.max(-1, Math.min(1, normalizedScore + ratingBias));

    // Classify
    if (this.sentimentScore > 0.5) {
      this.sentiment = SENTIMENT.VERY_POSITIVE;
    } else if (this.sentimentScore > 0.15) {
      this.sentiment = SENTIMENT.POSITIVE;
    } else if (this.sentimentScore < -0.5) {
      this.sentiment = SENTIMENT.VERY_NEGATIVE;
    } else if (this.sentimentScore < -0.15) {
      this.sentiment = SENTIMENT.NEGATIVE;
    } else {
      this.sentiment = SENTIMENT.NEUTRAL;
    }

    return {
      sentiment: this.sentiment,
      score: this.sentimentScore,
      positiveScore,
      negativeScore
    };
  }

  // ==========================================================================
  // TOXICITY DETECTION
  // ==========================================================================

  async detectToxicity() {
    if (!this.content) {
      this.toxicityScore = 0;
      return { score: 0, isToxic: false };
    }

    const text = this.content.toLowerCase();
    let toxicityPoints = 0;

    // Profanity
    const profanityList = ['damn', 'hell', 'crap', 'sucks'];
    profanityList.forEach(word => {
      const regex = new RegExp(`\\b${word}\\b`, 'gi');
      const matches = text.match(regex);
      if (matches) toxicityPoints += matches.length * 0.2;
    });

    // Hate speech
    const hateSpeech = ['racist', 'sexist', 'bigot'];
    hateSpeech.forEach(word => {
      if (new RegExp(`\\b${word}\\b`, 'gi').test(text)) {
        toxicityPoints += 0.8;
      }
    });

    // Aggressive language
    const aggressiveTerms = ['stupid', 'idiot', 'moron', 'dumb', 'pathetic'];
    aggressiveTerms.forEach(word => {
      const matches = text.match(new RegExp(`\\b${word}\\b`, 'gi'));
      if (matches) toxicityPoints += matches.length * 0.15;
    });

    this.toxicityScore = Math.min(1, toxicityPoints);

    return {
      score: this.toxicityScore,
      isToxic: this.toxicityScore > 0.5
    };
  }

  // ==========================================================================
  // MODERATION
  // ==========================================================================

  async approve(moderatorId = null, notes = '') {
    if (!this.id) throw new ValidationError('Cannot approve unsaved review');

    this.status = REVIEW_STATUS.APPROVED;
    this.moderatedBy = moderatorId;
    this.moderatedAt = new Date();
    this.moderationNotes = notes;
    this.publishedAt = this.publishedAt || new Date();

    await this.save();

    await auditLogger.log('review.approved', { reviewId: this.id, moderatorId, notes });
    this.emit('approved', { moderatorId, notes });
    await queue.push('search.index', { type: 'review', id: this.id });

    logger.info('Review approved', { reviewId: this.id, moderatorId });
    return this;
  }

  async reject(moderatorId = null, reason = '') {
    if (!this.id) throw new ValidationError('Cannot reject unsaved review');

    this.status = REVIEW_STATUS.REJECTED;
    this.moderatedBy = moderatorId;
    this.moderatedAt = new Date();
    this.moderationNotes = reason;

    await this.save();
    await auditLogger.log('review.rejected', { reviewId: this.id, moderatorId, reason });
    this.emit('rejected', { moderatorId, reason });

    logger.info('Review rejected', { reviewId: this.id, moderatorId });
    return this;
  }

  async flag(reason = '', userId = null) {
    if (!this.id) throw new ValidationError('Cannot flag unsaved review');

    await rateLimiter.check(`flag:user:${userId}`, 10, 3600);

    this.status = REVIEW_STATUS.FLAGGED;
    this.reportCount++;

    await db.execute(
      `INSERT INTO ${tables.REVIEW_FLAGS} (review_id, user_id, reason, created_at)
       VALUES (?, ?, ?, NOW())`,
      [this.id, userId, reason]
    );

    await this.save();
    await auditLogger.log('review.flagged', { reviewId: this.id, userId, reason });
    this.emit('flagged', { reason, userId });

    if (this.reportCount >= 5) {
      await this.hide('Auto-hidden due to multiple reports', null);
    }

    logger.warn('Review flagged', { reviewId: this.id, reason });
    return this;
  }

  async markAsSpam(moderatorId = null) {
    if (!this.id) throw new ValidationError('Cannot mark unsaved review as spam');

    this.status = REVIEW_STATUS.SPAM;
    this.moderatedBy = moderatorId;
    this.moderatedAt = new Date();
    this.spamScore = 1.0;

    await this.save();

    const contentHash = crypto.createHash('md5').update(this.content.toLowerCase()).digest('hex');
    await db.execute(
      `INSERT IGNORE INTO spam_patterns (content_hash, review_id, created_at) VALUES (?, ?, NOW())`,
      [contentHash, this.id]
    );

    await auditLogger.log('review.spam', { reviewId: this.id, moderatorId });
    this.emit('markedAsSpam', { moderatorId });

    logger.warn('Review marked as spam', { reviewId: this.id });
    return this;
  }

  async hide(reason = '', moderatorId = null) {
    this.status = REVIEW_STATUS.HIDDEN;
    this.moderatedBy = moderatorId;
    this.moderatedAt = new Date();
    this.moderationNotes = reason;
    await this.save();

    logger.info('Review hidden', { reviewId: this.id });
    return this;
  }

  // ==========================================================================
  // VOTING
  // ==========================================================================

  async vote(userId, isHelpful) {
    if (!this.id) throw new ValidationError('Cannot vote on unsaved review');

    await rateLimiter.check(`vote:user:${userId}`, 100, 3600);

    const connection = await db.getConnection();
    
    try {
      await connection.beginTransaction();

      const [existingVotes] = await connection.execute(
        `SELECT id, is_helpful FROM ${tables.REVIEW_VOTES} 
         WHERE review_id = ? AND user_id = ? LIMIT 1 FOR UPDATE`,
        [this.id, userId]
      );

      if (existingVotes.length > 0) {
        const existingVote = existingVotes[0];
        
        if (existingVote.is_helpful !== isHelpful) {
          await connection.execute(
            `UPDATE ${tables.REVIEW_VOTES} SET is_helpful = ?, updated_at = NOW() WHERE id = ?`,
            [isHelpful, existingVote.id]
          );

          if (isHelpful) {
            this.helpfulCount++;
            this.notHelpfulCount = Math.max(0, this.notHelpfulCount - 1);
          } else {
            this.helpfulCount = Math.max(0, this.helpfulCount - 1);
            this.notHelpfulCount++;
          }
        }
      } else {
        await connection.execute(
          `INSERT INTO ${tables.REVIEW_VOTES} (review_id, user_id, is_helpful, created_at)
           VALUES (?, ?, ?, NOW())`,
          [this.id, userId, isHelpful]
        );

        if (isHelpful) this.helpfulCount++;
        else this.notHelpfulCount++;
      }

      await connection.execute(
        `UPDATE ${tables.REVIEWS} SET helpful_count = ?, not_helpful_count = ? WHERE id = ?`,
        [this.helpfulCount, this.notHelpfulCount, this.id]
      );

      await connection.commit();
      await cache.delete(CacheKeyBuilder.review(this.id));

      this.emit('voted', { userId, isHelpful });
      await metrics.increment('review.votes', 1, { review_id: this.id, helpful: isHelpful });

      logger.debug('Review voted', { reviewId: this.id, userId, isHelpful });
      return this;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  // ==========================================================================
  // LIFECYCLE HOOKS
  // ==========================================================================

  async beforeSave() {
    this.emit('beforeSave', this);

    if (this._isNew) {
      await this.analyzeSentiment();
      await this.detectSpam();
      await this.detectToxicity();
      this.calculateQualityScore();

      // Auto-moderate
      if (this.spamScore > SPAM_THRESHOLD) {
        this.status = REVIEW_STATUS.SPAM;
      } else if (this.toxicityScore > 0.7) {
        this.status = REVIEW_STATUS.FLAGGED;
      } else if (this.qualityScore >= AUTO_APPROVE_THRESHOLD && this.isVerifiedPurchase) {
        this.status = REVIEW_STATUS.APPROVED;
        this.publishedAt = new Date();
      }

      // Generate fingerprint
      if (!this.deviceFingerprint && this.userAgent && this.ipAddress) {
        this.deviceFingerprint = crypto.createHash('sha256')
          .update(`${this.userAgent}:${this.ipAddress}`)
          .digest('hex').substring(0, 32);
      }
    }

    if (this._isNew) this.createdAt = new Date();
    this.updatedAt = new Date();
  }

  async afterSave() {
    this.emit('afterSave', this);

    const wasNew = this._isNew;

    // Clear caches
    if (this.id) {
      const cacheKeys = [
        CacheKeyBuilder.review(this.id),
        `product:${this.productId}:reviews`,
        `user:${this.userId}:reviews`,
        `product:${this.productId}:rating`
      ];
      await Promise.all(cacheKeys.map(key => cache.delete(key)));
    }

    // Update product rating
    if (this.isApproved) {
      await queue.push('product.updateRating', { productId: this.productId });
    }

    // Index in search
    if (this.isApproved) {
      await queue.push('search.index', { type: 'review', id: this.id });
    }

    // Track metrics
    if (wasNew) {
      await metrics.increment('review.created', 1, {
        product_id: this.productId,
        status: this.status
      });
    }

    logger.info('Review saved', { reviewId: this.id, isNew: wasNew, status: this.status });

    this._isNew = false;
    this._isDirty = false;
  }

  // ==========================================================================
  // PRODUCT RATING UPDATE
  // ==========================================================================

  async updateProductRating() {
    const connection = await db.getConnection();

    try {
      await connection.beginTransaction();

      const [stats] = await connection.execute(
        `SELECT 
          COUNT(*) as total_reviews,
          AVG(rating) as average_rating,
          SUM(CASE WHEN rating >= 4.5 THEN 1 ELSE 0 END) as five_star,
          SUM(CASE WHEN rating >= 3.5 AND rating < 4.5 THEN 1 ELSE 0 END) as four_star,
          SUM(CASE WHEN rating >= 2.5 AND rating < 3.5 THEN 1 ELSE 0 END) as three_star,
          SUM(CASE WHEN rating >= 1.5 AND rating < 2.5 THEN 1 ELSE 0 END) as two_star,
          SUM(CASE WHEN rating < 1.5 THEN 1 ELSE 0 END) as one_star
         FROM ${tables.REVIEWS}
         WHERE product_id = ? AND status = ? FOR UPDATE`,
        [this.productId, REVIEW_STATUS.APPROVED]
      );

      if (stats.length > 0 && stats[0].total_reviews > 0) {
        const data = stats[0];
        
        await connection.execute(
          `UPDATE ${tables.PRODUCTS}
           SET average_rating = ?, total_reviews = ?, rating_distribution = ?, updated_at = NOW()
           WHERE id = ?`,
          [
            parseFloat(data.average_rating).toFixed(2),
            data.total_reviews,
            JSON.stringify({
              5: data.five_star || 0,
              4: data.four_star || 0,
              3: data.three_star || 0,
              2: data.two_star || 0,
              1: data.one_star || 0
            }),
            this.productId
          ]
        );

        await connection.commit();
        await cache.delete(`product:${this.productId}`);

        logger.info('Product rating updated', { productId: this.productId });
      } else {
        await connection.rollback();
      }
    } catch (error) {
      await connection.rollback();
      logger.error('Failed to update product rating', { error: error.message });
    } finally {
      connection.release();
    }
  }

  // ==========================================================================
  // CRUD OPERATIONS
  // ==========================================================================

  async save() {
    try {
      this.validate();
      await this.beforeSave();

      const connection = await db.getConnection();

      try {
        await connection.beginTransaction();

        if (this._isNew) {
          const [result] = await connection.execute(
            `INSERT INTO ${tables.REVIEWS} (
              product_id, user_id, order_id, rating, title, content, pros, cons,
              is_verified_purchase, is_premium_review, status, moderation_notes, 
              moderated_by, moderated_at, sentiment_score, sentiment, quality_score, 
              spam_score, toxicity_score, helpful_count, not_helpful_count, report_count, 
              view_count, share_count, reply_count, images, videos, ip_address, user_agent, 
              language, device_type, device_fingerprint, reward_points, has_reward,
              created_at, updated_at, published_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?)`,
            [
              this.productId, this.userId, this.orderId, this.rating, this.title, 
              this.content, JSON.stringify(this.pros), JSON.stringify(this.cons),
              this.isVerifiedPurchase, this.isPremiumReview, this.status, this.moderationNotes,
              this.moderatedBy, this._formatDateForDB(this.moderatedAt), this.sentimentScore, 
              this.sentiment, this.qualityScore, this.spamScore, this.toxicityScore, 
              this.helpfulCount, this.notHelpfulCount, this.reportCount, this.viewCount, 
              this.shareCount, this.replyCount, JSON.stringify(this.images), 
              JSON.stringify(this.videos), this.ipAddress, this.userAgent, this.language, 
              this.deviceType, this.deviceFingerprint, this.rewardPoints, this.hasReward,
              this._formatDateForDB(this.publishedAt)
            ]
          );

          this.id = result.insertId;
        } else {
          await connection.execute(
            `UPDATE ${tables.REVIEWS}
             SET rating = ?, title = ?, content = ?, pros = ?, cons = ?,
                 status = ?, moderation_notes = ?, moderated_by = ?, moderated_at = ?,
                 sentiment_score = ?, sentiment = ?, quality_score = ?, spam_score = ?, 
                 toxicity_score = ?, helpful_count = ?, not_helpful_count = ?, 
                 report_count = ?, view_count = ?, share_count = ?, reply_count = ?,
                 images = ?, videos = ?, updated_at = NOW(), published_at = ?
             WHERE id = ?`,
            [
              this.rating, this.title, this.content, JSON.stringify(this.pros), 
              JSON.stringify(this.cons), this.status, this.moderationNotes, this.moderatedBy,
              this._formatDateForDB(this.moderatedAt), this.sentimentScore, this.sentiment,
              this.qualityScore, this.spamScore, this.toxicityScore, this.helpfulCount,
              this.notHelpfulCount, this.reportCount, this.viewCount, this.shareCount,
              this.replyCount, JSON.stringify(this.images), JSON.stringify(this.videos),
              this._formatDateForDB(this.publishedAt), this.id
            ]
          );
        }

        await connection.commit();
        await this.afterSave();

        return this;
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    } catch (error) {
      logger.error('Review save failed', { error: error.message, reviewId: this.id });
      throw error;
    }
  }

  async delete() {
    if (!this.id) throw new ValidationError('Cannot delete unsaved review');

    const connection = await db.getConnection();

    try {
      await connection.beginTransaction();

      await connection.execute(`DELETE FROM ${tables.REVIEW_VOTES} WHERE review_id = ?`, [this.id]);
      await connection.execute(`DELETE FROM ${tables.REVIEW_FLAGS} WHERE review_id = ?`, [this.id]);
      await connection.execute(`DELETE FROM ${tables.REVIEW_REPLIES} WHERE review_id = ?`, [this.id]);
      await connection.execute(`DELETE FROM ${tables.REVIEWS} WHERE id = ?`, [this.id]);

      await connection.commit();

      await cache.delete(CacheKeyBuilder.review(this.id));
      await this.updateProductRating();
      await searchIndex.delete('reviews', this.id);

      this.emit('deleted');
      await auditLogger.log('review.deleted', { reviewId: this.id });

      logger.info('Review deleted', { reviewId: this.id });
      return true;
    } catch (error) {
      await connection.rollback();
      logger.error('Review deletion failed', { error: error.message });
      throw error;
    } finally {
      connection.release();
    }
  }

  // ==========================================================================
  // RELATIONSHIP METHODS
  // ==========================================================================

  async user(options = {}) {
    if (this._user && !options.reload) return this._user;

    const cacheKey = `user:${this.userId}:profile`;
    
    if (!options.reload) {
      const cached = await cache.get(cacheKey);
      if (cached) {
        this._user = JSON.parse(cached);
        return this._user;
      }
    }

    const [users] = await db.execute(
      `SELECT id, username, email, first_name, last_name, avatar FROM ${tables.USERS} 
       WHERE id = ? LIMIT 1`,
      [this.userId]
    );

    this._user = users[0] || null;
    
    if (this._user) {
      await cache.set(cacheKey, JSON.stringify(this._user), CACHE_TTL.REVIEW);
    }

    return this._user;
  }

  async product(options = {}) {
    if (this._product && !options.reload) return this._product;

    const cacheKey = `product:${this.productId}:basic`;
    
    if (!options.reload) {
      const cached = await cache.get(cacheKey);
      if (cached) {
        this._product = JSON.parse(cached);
        return this._product;
      }
    }

    const [products] = await db.execute(
      `SELECT id, name, slug, sku, price, images, average_rating FROM ${tables.PRODUCTS} 
       WHERE id = ? LIMIT 1`,
      [this.productId]
    );

    this._product = products[0] || null;
    
    if (this._product) {
      await cache.set(cacheKey, JSON.stringify(this._product), CACHE_TTL.REVIEW);
    }

    return this._product;
  }

  async votes(options = {}) {
    const [votes] = await db.execute(
      `SELECT v.*, u.username FROM ${tables.REVIEW_VOTES} v
       LEFT JOIN ${tables.USERS} u ON v.user_id = u.id
       WHERE v.review_id = ? ORDER BY v.created_at DESC LIMIT 100`,
      [this.id]
    );

    return votes;
  }

  async replies(options = {}) {
    const [replies] = await db.execute(
      `SELECT r.*, u.username, u.avatar FROM ${tables.REVIEW_REPLIES} r
       LEFT JOIN ${tables.USERS} u ON r.user_id = u.id
       WHERE r.review_id = ? ORDER BY r.created_at ASC`,
      [this.id]
    );

    return replies;
  }

  async addReply(userId, content, isMerchant = false) {
    if (!this.id) throw new ValidationError('Cannot reply to unsaved review');

    await rateLimiter.check(`reply:user:${userId}`, 20, 3600);

    const [result] = await db.execute(
      `INSERT INTO ${tables.REVIEW_REPLIES} (review_id, user_id, content, is_merchant, created_at)
       VALUES (?, ?, ?, ?, NOW())`,
      [this.id, userId, content, isMerchant]
    );

    this.replyCount++;
    await db.execute(
      `UPDATE ${tables.REVIEWS} SET reply_count = reply_count + 1 WHERE id = ?`,
      [this.id]
    );

    await cache.delete(CacheKeyBuilder.review(this.id));
    this.emit('replied', { userId, content });

    return result.insertId;
  }

  // ==========================================================================
  // UTILITY METHODS
  // ==========================================================================

  async incrementViewCount() {
    this.viewCount++;
    await db.execute(
      `UPDATE ${tables.REVIEWS} SET view_count = view_count + 1 WHERE id = ?`,
      [this.id]
    );
    await metrics.increment('review.views', 1, { review_id: this.id });
  }

  async incrementShareCount() {
    this.shareCount++;
    await db.execute(
      `UPDATE ${tables.REVIEWS} SET share_count = share_count + 1 WHERE id = ?`,
      [this.id]
    );
    await metrics.increment('review.shares', 1, { review_id: this.id });
  }

  // ==========================================================================
  // SERIALIZATION
  // ==========================================================================

  toJSON(options = {}) {
    const { includeUser = false, includeProduct = false, includeSensitive = false, includeScores = false } = options;

    const json = {
      id: this.id,
      productId: this.productId,
      userId: this.userId,
      rating: this.rating,
      title: this.title,
      content: this.content,
      pros: this.pros,
      cons: this.cons,
      isVerifiedPurchase: this.isVerifiedPurchase,
      status: this.status,
      sentiment: this.sentiment,
      images: this.images,
      videos: this.videos,
      metrics: {
        helpfulCount: this.helpfulCount,
        notHelpfulCount: this.notHelpfulCount,
        helpfulnessRatio: this.helpfulnessRatio,
        viewCount: this.viewCount,
        shareCount: this.shareCount,
        replyCount: this.replyCount,
        engagementScore: this.engagementScore
      },
      computed: {
        isHighQuality: this.isHighQuality,
        hasMedia: this.hasMedia,
        isPositive: this.isPositive,
        readTimeMinutes: this.readTimeMinutes,
        characterCount: this.characterCount,
        wordCount: this.wordCount,
        trustScore: this.trustScore
      },
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      publishedAt: this.publishedAt
    };

    if (includeScores) {
      json.scores = {
        quality: this.qualityScore,
        spam: this.spamScore,
        toxicity: this.toxicityScore,
        sentiment: this.sentimentScore
      };
    }

    if (includeUser && this._user) {
      json.user = {
        id: this._user.id,
        username: this._user.username,
        avatar: this._user.avatar
      };
    }

    if (includeProduct && this._product) {
      json.product = {
        id: this._product.id,
        name: this._product.name,
        slug: this._product.slug
      };
    }

    if (includeSensitive) {
      json.sensitive = {
        ipAddress: this.ipAddress,
        deviceFingerprint: this.deviceFingerprint,
        moderationNotes: this.moderationNotes,
        reportCount: this.reportCount
      };
    }

    return json;
  }

  toPublicAPI() {
    return this.toJSON({ includeUser: true, includeScores: false });
  }

  toAdminAPI() {
    return this.toJSON({ 
      includeUser: true, 
      includeProduct: true, 
      includeSensitive: true, 
      includeScores: true 
    });
  }

  // ==========================================================================
  // STATIC METHODS
  // ==========================================================================

  static async findById(id, options = {}) {
    if (!id) throw new ValidationError('Review ID is required');

    const cacheKey = CacheKeyBuilder.review(id);
    
    if (!options.reload) {
      const cached = await cache.get(cacheKey);
      if (cached) return new Review(JSON.parse(cached));
    }

    const [reviews] = await db.execute(
      `SELECT * FROM ${tables.REVIEWS} WHERE id = ? LIMIT 1`,
      [id]
    );

    if (reviews.length === 0) throw new NotFoundError('Review not found');

    const review = new Review(reviews[0]);
    await cache.set(cacheKey, JSON.stringify(reviews[0]), CACHE_TTL.REVIEW);

    return review;
  }

  static async findByProductId(productId, options = {}) {
    const { status = REVIEW_STATUS.APPROVED, limit = 20, offset = 0, orderBy = 'helpful' } = options;

    const cacheKey = `product:${productId}:reviews:${status}:${orderBy}:${limit}:${offset}`;
    const cached = await cache.get(cacheKey);
    
    if (cached) return JSON.parse(cached).map(data => new Review(data));

    let orderClause;
    switch (orderBy) {
      case 'helpful':
        orderClause = 'ORDER BY (helpful_count - not_helpful_count) DESC, created_at DESC';
        break;
      case 'recent':
        orderClause = 'ORDER BY created_at DESC';
        break;
      case 'rating_high':
        orderClause = 'ORDER BY rating DESC, created_at DESC';
        break;
      case 'rating_low':
        orderClause = 'ORDER BY rating ASC, created_at DESC';
        break;
      default:
        orderClause = 'ORDER BY created_at DESC';
    }

    const [reviews] = await db.execute(
      `SELECT * FROM ${tables.REVIEWS}
       WHERE product_id = ? AND status = ?
       ${orderClause}
       LIMIT ? OFFSET ?`,
      [productId, status, limit, offset]
    );

    const reviewObjects = reviews.map(data => new Review(data));
    await cache.set(cacheKey, JSON.stringify(reviews), CACHE_TTL.REVIEWS_LIST);

    return reviewObjects;
  }

  static async findByUserId(userId, options = {}) {
    const { limit = 20, offset = 0 } = options;

    const [reviews] = await db.execute(
      `SELECT * FROM ${tables.REVIEWS}
       WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [userId, limit, offset]
    );

    return reviews.map(data => new Review(data));
  }

  static async getProductStats(productId) {
    const cacheKey = `product:${productId}:stats`;
    const cached = await cache.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total,
        AVG(rating) as avg_rating,
        AVG(quality_score) as avg_quality,
        SUM(CASE WHEN is_verified_purchase = 1 THEN 1 ELSE 0 END) as verified,
        SUM(CASE WHEN rating >= 4.5 THEN 1 ELSE 0 END) as five_star,
        SUM(CASE WHEN rating >= 3.5 AND rating < 4.5 THEN 1 ELSE 0 END) as four_star,
        SUM(CASE WHEN rating >= 2.5 AND rating < 3.5 THEN 1 ELSE 0 END) as three_star,
        SUM(CASE WHEN rating >= 1.5 AND rating < 2.5 THEN 1 ELSE 0 END) as two_star,
        SUM(CASE WHEN rating < 1.5 THEN 1 ELSE 0 END) as one_star
       FROM ${tables.REVIEWS}
       WHERE product_id = ? AND status = ?`,
      [productId, REVIEW_STATUS.APPROVED]
    );

    const result = stats[0] || {};
    await cache.set(cacheKey, JSON.stringify(result), CACHE_TTL.STATS);
    return result;
  }

  static async bulkUpdateStatus(reviewIds, status, moderatorId) {
    if (!Array.isArray(reviewIds) || reviewIds.length === 0) {
      throw new ValidationError('Review IDs array is required');
    }

    const placeholders = reviewIds.map(() => '?').join(',');
    
    await db.execute(
      `UPDATE ${tables.REVIEWS}
       SET status = ?, moderated_by = ?, moderated_at = NOW()
       WHERE id IN (${placeholders})`,
      [status, moderatorId, ...reviewIds]
    );

    await Promise.all(reviewIds.map(id => cache.delete(CacheKeyBuilder.review(id))));

    logger.info('Bulk status update', { count: reviewIds.length, status });
    return reviewIds.length;
  }

  static async getPendingReviews(options = {}) {
    const { limit = 50, offset = 0 } = options;

    const [reviews] = await db.execute(
      `SELECT * FROM ${tables.REVIEWS}
       WHERE status = ?
       ORDER BY created_at ASC
       LIMIT ? OFFSET ?`,
      [REVIEW_STATUS.PENDING, limit, offset]
    );

    return reviews.map(data => new Review(data));
  }

  static async getHighQualityReviews(productId, limit = 5) {
    const [reviews] = await db.execute(
      `SELECT * FROM ${tables.REVIEWS}
       WHERE product_id = ? AND status = ? AND quality_score >= 0.75
       ORDER BY quality_score DESC, helpful_count DESC
       LIMIT ?`,
      [productId, REVIEW_STATUS.APPROVED, limit]
    );

    return reviews.map(data => new Review(data));
  }

  static async searchReviews(query, options = {}) {
    const { productId = null, minRating = null, maxRating = null, limit = 20 } = options;

    let sql = `SELECT * FROM ${tables.REVIEWS} WHERE status = ? AND content LIKE ?`;
    const params = [REVIEW_STATUS.APPROVED, `%${query}%`];

    if (productId) {
      sql += ` AND product_id = ?`;
      params.push(productId);
    }

    if (minRating) {
      sql += ` AND rating >= ?`;
      params.push(minRating);
    }

    if (maxRating) {
      sql += ` AND rating <= ?`;
      params.push(maxRating);
    }

    sql += ` ORDER BY helpful_count DESC LIMIT ?`;
    params.push(limit);

    const [reviews] = await db.execute(sql, params);
    return reviews.map(data => new Review(data));
  }
}

// ============================================================================
// EXPORT
// ============================================================================

export default Review;
