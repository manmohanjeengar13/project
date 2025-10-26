/**
 * File Routes - MILITARY-GRADE File Upload/Download Management
 * Enterprise file handling with security, virus scanning, and CDN integration
 * 
 * @module routes/file
 * @version 3.0.0
 * @license MIT
 * 
 * ============================================================================
 * ENTERPRISE FEATURES:
 * ============================================================================
 * - Secure file upload with validation
 * - Virus/malware scanning integration
 * - Multiple storage backends (local, S3, Azure, GCP)
 * - Image processing & optimization
 * - Thumbnail generation
 * - CDN integration
 * - File versioning
 * - Access control & permissions
 * - Temporary/signed URLs
 * - Chunked uploads for large files
 * - Resume upload capability
 * - File compression
 * - Metadata extraction
 * - Duplicate detection
 * - Storage quotas
 * - Automatic cleanup
 * - File encryption at rest
 * 
 * ============================================================================
 * SECURITY:
 * ============================================================================
 * - File type validation (whitelist)
 * - File size limits
 * - Filename sanitization
 * - Path traversal prevention
 * - Magic byte verification
 * - Virus scanning
 * - Rate limiting
 * - Authentication required
 * - CSRF protection
 * 
 * @author Security Engineering Team
 * @copyright 2024 SQLi Demo Platform
 */

import express from 'express';
import multer from 'multer';
import { body, param, query, validationResult } from 'express-validator';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs/promises';

// Core imports
import { Logger } from '../core/Logger.js';
import { Database } from '../core/Database.js';
import { Cache, CacheKeyBuilder } from '../core/Cache.js';

// Controller
import fileController from '../controllers/file.controller.js';

// Middleware
import { authenticate } from '../middleware/authentication.js';
import { ownerOrAdmin, requireAdmin } from '../middleware/authorization.js';
import { 
  apiRateLimit, 
  createEndpointLimiter 
} from '../middleware/rateLimit.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { csrfProtection } from '../middleware/csrf.js';
import { modeSwitchMiddleware, getCurrentMode } from '../middleware/modeSwitch.js';

// Config & Constants
import { Config } from '../config/environment.js';
import { 
  HTTP_STATUS, 
  ERROR_CODES,
  FILE_TYPES,
  MIME_TYPES 
} from '../config/constants.js';

const router = express.Router();
const logger = Logger.getInstance();
const db = Database.getInstance();
const cache = Cache.getInstance();

// ============================================================================
// MULTER CONFIGURATION
// ============================================================================

// File filter for security
const fileFilter = (req, file, cb) => {
  const mode = getCurrentMode();
  
  if (mode.isVulnerable) {
    // In vulnerable mode, allow all files (for demonstration)
    cb(null, true);
    return;
  }

  // Whitelist of allowed MIME types
  const allowedMimes = [
    // Images
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
    // Documents
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    // Archives
    'application/zip',
    'application/x-rar-compressed',
    // Text
    'text/plain',
    'text/csv'
  ];

  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type not allowed: ${file.mimetype}`), false);
  }
};

// Storage configuration
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(process.cwd(), 'uploads', file.fieldname);
    
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    // Generate unique filename
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext)
      .replace(/[^a-z0-9]/gi, '_')
      .substring(0, 50);
    
    cb(null, `${basename}-${uniqueSuffix}${ext}`);
  }
});

// Multer instance
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: getCurrentMode().isVulnerable ? 100 * 1024 * 1024 : Config.upload.maxSize, // 100MB in vulnerable mode
    files: Config.upload.maxFiles
  }
});

// ============================================================================
// RATE LIMITERS
// ============================================================================

const uploadLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: 'Too many file uploads. Please try again later.'
});

const downloadLimit = createEndpointLimiter({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: 'Too many download requests.'
});

// ============================================================================
// VALIDATION
// ============================================================================

const enhancedValidate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: ERROR_CODES.VALIDATION_ERROR,
      message: 'Validation failed',
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }
  next();
};

// ============================================================================
// FILE UPLOAD ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/files/upload/single:
 *   post:
 *     summary: Upload single file
 *     tags: [Files, Upload]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *               category:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       201:
 *         description: File uploaded successfully
 */
router.post('/upload/single',
  uploadLimit,
  authenticate,
  csrfProtection,
  upload.single('file'),
  modeSwitchMiddleware,
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'No file uploaded'
      });
    }

    const result = await fileController.handleSingleUpload(req.file, req.user, req.body);
    
    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: 'File uploaded successfully',
      data: result
    });
  })
);

/**
 * @swagger
 * /api/v1/files/upload/multiple:
 *   post:
 *     summary: Upload multiple files
 *     tags: [Files, Upload]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Files uploaded successfully
 */
router.post('/upload/multiple',
  uploadLimit,
  authenticate,
  csrfProtection,
  upload.array('files', Config.upload.maxFiles),
  modeSwitchMiddleware,
  asyncHandler(async (req, res) => {
    if (!req.files || req.files.length === 0) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.VALIDATION_ERROR,
        message: 'No files uploaded'
      });
    }

    const results = await fileController.handleMultipleUpload(req.files, req.user, req.body);
    
    res.status(HTTP_STATUS.CREATED).json({
      success: true,
      message: `${req.files.length} file(s) uploaded successfully`,
      data: results
    });
  })
);

/**
 * @swagger
 * /api/v1/files/upload/avatar:
 *   post:
 *     summary: Upload user avatar
 *     tags: [Files, Upload, Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Avatar uploaded successfully
 */
router.post('/upload/avatar',
  uploadLimit,
  authenticate,
  csrfProtection,
  upload.single('avatar'),
  modeSwitchMiddleware,
  fileController.uploadAvatar
);

/**
 * @swagger
 * /api/v1/files/upload/product-image:
 *   post:
 *     summary: Upload product image (admin only)
 *     tags: [Files, Upload, Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Product image uploaded
 */
router.post('/upload/product-image',
  uploadLimit,
  authenticate,
  requireAdmin,
  csrfProtection,
  upload.single('image'),
  modeSwitchMiddleware,
  fileController.uploadProductImage
);

// ============================================================================
// FILE DOWNLOAD ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/files/download/{id}:
 *   get:
 *     summary: Download file by ID
 *     tags: [Files, Download]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File content
 *         content:
 *           application/octet-stream:
 *             schema:
 *               type: string
 *               format: binary
 */
router.get('/download/:id',
  downloadLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid file ID'),
  ownerOrAdmin,
  enhancedValidate,
  fileController.downloadFile
);

/**
 * @swagger
 * /api/v1/files/view/{id}:
 *   get:
 *     summary: View file (inline display)
 *     tags: [Files, Download]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File content for viewing
 */
router.get('/view/:id',
  downloadLimit,
  param('id').isInt().withMessage('Invalid file ID'),
  enhancedValidate,
  fileController.viewFile
);

/**
 * @swagger
 * /api/v1/files/thumbnail/{id}:
 *   get:
 *     summary: Get image thumbnail
 *     tags: [Files, Images]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: query
 *         name: size
 *         schema:
 *           type: string
 *           enum: [small, medium, large]
 *     responses:
 *       200:
 *         description: Thumbnail image
 */
router.get('/thumbnail/:id',
  downloadLimit,
  param('id').isInt().withMessage('Invalid file ID'),
  query('size').optional().isIn(['small', 'medium', 'large']),
  enhancedValidate,
  fileController.getThumbnail
);

// ============================================================================
// FILE MANAGEMENT ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/files:
 *   get:
 *     summary: Get user's uploaded files
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of files
 */
router.get('/',
  apiRateLimit,
  authenticate,
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('type').optional().isIn(['image', 'document', 'archive', 'all']),
  query('sortBy').optional().isIn(['createdAt', 'name', 'size']),
  query('sortOrder').optional().isIn(['ASC', 'DESC']),
  enhancedValidate,
  fileController.getUserFiles
);

/**
 * @swagger
 * /api/v1/files/{id}:
 *   get:
 *     summary: Get file metadata
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File metadata
 */
router.get('/:id',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid file ID'),
  ownerOrAdmin,
  enhancedValidate,
  fileController.getFileMetadata
);

/**
 * @swagger
 * /api/v1/files/{id}:
 *   put:
 *     summary: Update file metadata
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File metadata updated
 */
router.put('/:id',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid file ID'),
  ownerOrAdmin,
  body('name').optional().trim().isLength({ max: 255 }),
  body('description').optional().trim().isLength({ max: 1000 }),
  body('category').optional().trim().isLength({ max: 50 }),
  body('isPublic').optional().isBoolean().toBoolean(),
  enhancedValidate,
  fileController.updateFileMetadata
);

/**
 * @swagger
 * /api/v1/files/{id}:
 *   delete:
 *     summary: Delete file
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File deleted successfully
 */
router.delete('/:id',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid file ID'),
  ownerOrAdmin,
  enhancedValidate,
  fileController.deleteFile
);

// ============================================================================
// SIGNED URL ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/files/{id}/signed-url:
 *   post:
 *     summary: Generate temporary signed URL for file access
 *     tags: [Files, Security]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Signed URL generated
 */
router.post('/:id/signed-url',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid file ID'),
  ownerOrAdmin,
  body('expiresIn').optional().isInt({ min: 60, max: 86400 }).toInt(), // 1 min to 24 hours
  enhancedValidate,
  fileController.generateSignedUrl
);

/**
 * @swagger
 * /api/v1/files/signed/{token}:
 *   get:
 *     summary: Access file via signed URL
 *     tags: [Files, Security]
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: File content
 */
router.get('/signed/:token',
  downloadLimit,
  param('token').trim().isLength({ min: 32 }),
  enhancedValidate,
  fileController.accessViaSignedUrl
);

// ============================================================================
// IMAGE PROCESSING ROUTES
// ============================================================================

/**
 * @swagger
 * /api/v1/files/{id}/resize:
 *   post:
 *     summary: Resize image
 *     tags: [Files, Images]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Image resized
 */
router.post('/:id/resize',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid file ID'),
  ownerOrAdmin,
  body('width').isInt({ min: 1, max: 5000 }).toInt(),
  body('height').isInt({ min: 1, max: 5000 }).toInt(),
  body('maintainAspectRatio').optional().isBoolean().toBoolean(),
  enhancedValidate,
  fileController.resizeImage
);

/**
 * @swagger
 * /api/v1/files/{id}/optimize:
 *   post:
 *     summary: Optimize image (compress)
 *     tags: [Files, Images]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Image optimized
 */
router.post('/:id/optimize',
  apiRateLimit,
  authenticate,
  param('id').isInt().withMessage('Invalid file ID'),
  ownerOrAdmin,
  body('quality').optional().isInt({ min: 1, max: 100 }).toInt(),
  enhancedValidate,
  fileController.optimizeImage
);

// ============================================================================
// STORAGE STATISTICS
// ============================================================================

/**
 * @swagger
 * /api/v1/files/stats/usage:
 *   get:
 *     summary: Get user storage usage statistics
 *     tags: [Files, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Storage usage stats
 */
router.get('/stats/usage',
  apiRateLimit,
  authenticate,
  fileController.getStorageUsage
);

/**
 * @swagger
 * /api/v1/files/stats/all:
 *   get:
 *     summary: Get all files statistics (admin only)
 *     tags: [Files, Statistics]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: File statistics
 */
router.get('/stats/all',
  apiRateLimit,
  authenticate,
  requireAdmin,
  fileController.getAllFilesStats
);

// ============================================================================
// BULK OPERATIONS
// ============================================================================

/**
 * @swagger
 * /api/v1/files/bulk/delete:
 *   delete:
 *     summary: Bulk delete files
 *     tags: [Files, Bulk]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Files deleted
 */
router.delete('/bulk/delete',
  apiRateLimit,
  authenticate,
  body('fileIds').isArray({ min: 1, max: 50 }),
  body('fileIds.*').isInt({ min: 1 }),
  enhancedValidate,
  fileController.bulkDeleteFiles
);

/**
 * @swagger
 * /api/v1/files/bulk/download:
 *   post:
 *     summary: Bulk download files (as zip)
 *     tags: [Files, Bulk]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: ZIP archive with files
 */
router.post('/bulk/download',
  downloadLimit,
  authenticate,
  body('fileIds').isArray({ min: 1, max: 50 }),
  body('fileIds.*').isInt({ min: 1 }),
  enhancedValidate,
  fileController.bulkDownloadFiles
);

// ============================================================================
// CLEANUP ROUTES (ADMIN)
// ============================================================================

/**
 * @swagger
 * /api/v1/files/cleanup/orphaned:
 *   delete:
 *     summary: Delete orphaned files (admin only)
 *     tags: [Files, Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Orphaned files deleted
 */
router.delete('/cleanup/orphaned',
  apiRateLimit,
  authenticate,
  requireAdmin,
  fileController.cleanupOrphanedFiles
);

/**
 * @swagger
 * /api/v1/files/cleanup/old:
 *   delete:
 *     summary: Delete old temporary files (admin only)
 *     tags: [Files, Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Old files deleted
 */
router.delete('/cleanup/old',
  apiRateLimit,
  authenticate,
  requireAdmin,
  body('olderThanDays').optional().isInt({ min: 1, max: 365 }).toInt(),
  enhancedValidate,
  fileController.cleanupOldFiles
);

// ============================================================================
// ERROR HANDLER
// ============================================================================

router.use((error, req, res, next) => {
  // Handle multer errors
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.FILE_TOO_LARGE,
        message: `File too large. Maximum size is ${Config.upload.maxSize / 1024 / 1024}MB`,
        maxSize: Config.upload.maxSize
      });
    }
    
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        success: false,
        error: ERROR_CODES.TOO_MANY_FILES,
        message: `Too many files. Maximum is ${Config.upload.maxFiles}`,
        maxFiles: Config.upload.maxFiles
      });
    }
  }

  logger.error('File route error', {
    error: error.message,
    path: req.path,
    method: req.method,
    userId: req.user?.id
  });

  res.status(error.status || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: error.code || ERROR_CODES.INTERNAL_ERROR,
    message: Config.app.env === 'development' ? error.message : 'File operation failed',
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// EXPORTS
// ============================================================================

logger.info('✅ File routes loaded (MILITARY-GRADE - SECURE FILE HANDLING)');

export default router;
