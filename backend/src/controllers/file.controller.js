/**
 * File Controller
 * Handles file uploads, management, and storage
 */

import multer from 'multer';
import sharp from 'sharp';
import path from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import { Database } from '../core/Database.js';
import { Logger } from '../core/Logger.js';
import { Config } from '../config/environment.js';
import { fileUploadConfig } from '../config/security.js';
import { sanitizeFilename } from '../middleware/sanitization.js';
import { 
  HTTP_STATUS, 
  PAGINATION,
  FILE_TYPES,
  USER_ROLES 
} from '../config/constants.js';
import { NotFoundError, ValidationError, AuthorizationError } from '../middleware/errorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = Database.getInstance();
const logger = Logger.getInstance();

/**
 * Configure multer storage
 */
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = Config.upload.destination;
    
    // Ensure directory exists
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const sanitized = sanitizeFilename(file.originalname);
    const ext = path.extname(sanitized);
    const uniqueName = `${uuidv4()}${ext}`;
    cb(null, uniqueName);
  }
});

/**
 * File filter for validation
 */
const fileFilter = (req, file, cb) => {
  // In vulnerable mode, accept all files
  if (Config.security.mode === 'vulnerable') {
    return cb(null, true);
  }

  // Check MIME type
  if (!fileUploadConfig.allowedMimeTypes.includes(file.mimetype)) {
    return cb(new Error(`File type ${file.mimetype} is not allowed`), false);
  }

  // Check extension
  const ext = path.extname(file.originalname).toLowerCase();
  if (!fileUploadConfig.allowedExtensions.includes(ext)) {
    return cb(new Error(`File extension ${ext} is not allowed`), false);
  }

  // Check blocked extensions
  if (fileUploadConfig.blockedExtensions.includes(ext)) {
    return cb(new Error(`File extension ${ext} is blocked for security reasons`), false);
  }

  cb(null, true);
};

/**
 * Configure multer
 */
const upload = multer({
  storage,
  limits: {
    fileSize: fileUploadConfig.maxFileSize,
    files: fileUploadConfig.maxFiles
  },
  fileFilter
});

/**
 * Upload single file
 */
export const uploadFile = async (req, res, next) => {
  try {
    upload.single('file')(req, res, async (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          throw new ValidationError(`File size exceeds maximum allowed size of ${fileUploadConfig.maxFileSize / (1024 * 1024)}MB`);
        }
        throw new ValidationError(err.message);
      } else if (err) {
        throw new ValidationError(err.message);
      }

      if (!req.file) {
        throw new ValidationError('No file uploaded');
      }

      const file = req.file;
      const userId = req.user.id;

      let optimizedPath = file.path;

      // Optimize image if it's an image
      if (file.mimetype.startsWith('image/') && Config.upload.enableImageOptimization) {
        try {
          const optimizedFilename = `optimized_${file.filename}`;
          optimizedPath = path.join(Config.upload.destination, optimizedFilename);

          await sharp(file.path)
            .resize(fileUploadConfig.image.maxWidth, fileUploadConfig.image.maxHeight, {
              fit: 'inside',
              withoutEnlargement: true
            })
            .jpeg({ quality: fileUploadConfig.image.quality })
            .toFile(optimizedPath);

          // Create thumbnail
          const thumbnailFilename = `thumb_${file.filename}`;
          const thumbnailPath = path.join(Config.upload.destination, thumbnailFilename);

          await sharp(file.path)
            .resize(fileUploadConfig.image.thumbnailWidth, fileUploadConfig.image.thumbnailHeight, {
              fit: 'cover'
            })
            .jpeg({ quality: 80 })
            .toFile(thumbnailPath);

          // Delete original and use optimized
          await fs.unlink(file.path);
          file.filename = optimizedFilename;
          file.path = optimizedPath;

          logger.debug('Image optimized', { originalSize: file.size, optimizedPath });
        } catch (optimizationError) {
          logger.error('Image optimization failed:', optimizationError);
          // Continue with original file
        }
      }

      // Determine file type
      let fileType = FILE_TYPES.OTHER;
      if (file.mimetype.startsWith('image/')) fileType = FILE_TYPES.IMAGE;
      else if (file.mimetype.startsWith('video/')) fileType = FILE_TYPES.VIDEO;
      else if (file.mimetype.startsWith('audio/')) fileType = FILE_TYPES.AUDIO;
      else if (file.mimetype.includes('pdf') || file.mimetype.includes('document')) fileType = FILE_TYPES.DOCUMENT;

      // Store file metadata in database
      const [result] = await db.execute(
        `INSERT INTO files (
          user_id, original_name, filename, mime_type, size, 
          file_type, path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          userId,
          file.originalname,
          file.filename,
          file.mimetype,
          file.size,
          fileType,
          file.path
        ]
      );

      const fileId = result.insertId;

      logger.info('File uploaded', { fileId, userId, filename: file.filename });

      res.status(HTTP_STATUS.CREATED).json({
        success: true,
        message: 'File uploaded successfully',
        data: {
          id: fileId,
          filename: file.filename,
          originalName: file.originalname,
          size: file.size,
          mimeType: file.mimetype,
          fileType,
          url: `/uploads/${file.filename}`
        }
      });
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Upload multiple files
 */
export const uploadMultipleFiles = async (req, res, next) => {
  try {
    upload.array('files', fileUploadConfig.maxFiles)(req, res, async (err) => {
      if (err) {
        throw new ValidationError(err.message);
      }

      if (!req.files || req.files.length === 0) {
        throw new ValidationError('No files uploaded');
      }

      const userId = req.user.id;
      const uploadedFiles = [];

      for (const file of req.files) {
        // Determine file type
        let fileType = FILE_TYPES.OTHER;
        if (file.mimetype.startsWith('image/')) fileType = FILE_TYPES.IMAGE;

        // Store in database
        const [result] = await db.execute(
          `INSERT INTO files (
            user_id, original_name, filename, mime_type, size, 
            file_type, path, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
          [
            userId,
            file.originalname,
            file.filename,
            file.mimetype,
            file.size,
            fileType,
            file.path
          ]
        );

        uploadedFiles.push({
          id: result.insertId,
          filename: file.filename,
          originalName: file.originalname,
          size: file.size,
          mimeType: file.mimetype,
          url: `/uploads/${file.filename}`
        });
      }

      logger.info('Multiple files uploaded', { count: uploadedFiles.length, userId });

      res.status(HTTP_STATUS.CREATED).json({
        success: true,
        message: `${uploadedFiles.length} files uploaded successfully`,
        data: uploadedFiles
      });
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get user files
 */
export const getFiles = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      fileType = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = ['user_id = ?'];
    const values = [userId];

    if (fileType) {
      conditions.push('file_type = ?');
      values.push(fileType);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM files ${whereClause}`,
      values
    );

    // Get files
    const [files] = await db.execute(
      `SELECT id, original_name, filename, mime_type, size, file_type, created_at
       FROM files
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: files,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get file by ID
 */
export const getFileById = async (req, res, next) => {
  try {
    const fileId = req.params.id;
    const userId = req.user.id;

    const [files] = await db.execute(
      'SELECT * FROM files WHERE id = ? LIMIT 1',
      [fileId]
    );

    if (files.length === 0) {
      throw new NotFoundError('File');
    }

    const file = files[0];

    // Check authorization
    if (file.user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only access your own files');
    }

    res.json({
      success: true,
      data: file
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Download file
 */
export const downloadFile = async (req, res, next) => {
  try {
    const fileId = req.params.id;
    const userId = req.user.id;

    const [files] = await db.execute(
      'SELECT * FROM files WHERE id = ? LIMIT 1',
      [fileId]
    );

    if (files.length === 0) {
      throw new NotFoundError('File');
    }

    const file = files[0];

    // Check authorization
    if (file.user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only download your own files');
    }

    // Check if file exists
    try {
      await fs.access(file.path);
    } catch (error) {
      throw new NotFoundError('File not found on disk');
    }

    // Set headers
    res.setHeader('Content-Type', file.mime_type);
    res.setHeader('Content-Disposition', `attachment; filename="${file.original_name}"`);
    res.setHeader('Content-Length', file.size);

    // Stream file
    const fileStream = require('fs').createReadStream(file.path);
    fileStream.pipe(res);

    logger.info('File downloaded', { fileId, userId });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete file
 */
export const deleteFile = async (req, res, next) => {
  try {
    const fileId = req.params.id;
    const userId = req.user.id;

    const [files] = await db.execute(
      'SELECT * FROM files WHERE id = ? LIMIT 1',
      [fileId]
    );

    if (files.length === 0) {
      throw new NotFoundError('File');
    }

    const file = files[0];

    // Check authorization
    if (file.user_id !== userId && ![USER_ROLES.ADMIN, USER_ROLES.SUPER_ADMIN].includes(req.user.role)) {
      throw new AuthorizationError('You can only delete your own files');
    }

    // Delete physical file
    try {
      await fs.unlink(file.path);
      
      // Delete thumbnail if exists
      const thumbnailPath = path.join(
        path.dirname(file.path),
        `thumb_${path.basename(file.path)}`
      );
      await fs.unlink(thumbnailPath).catch(() => {});
    } catch (error) {
      logger.warn('Failed to delete physical file', { fileId, error: error.message });
    }

    // Delete from database
    await db.execute('DELETE FROM files WHERE id = ?', [fileId]);

    logger.info('File deleted', { fileId, userId });

    res.json({
      success: true,
      message: 'File deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get file statistics
 */
export const getFileStats = async (req, res, next) => {
  try {
    // Overall statistics
    const [stats] = await db.execute(
      `SELECT 
        COUNT(*) as total_files,
        COALESCE(SUM(size), 0) as total_size,
        COUNT(CASE WHEN file_type = 'image' THEN 1 END) as images,
        COUNT(CASE WHEN file_type = 'document' THEN 1 END) as documents,
        COUNT(CASE WHEN file_type = 'video' THEN 1 END) as videos,
        COUNT(CASE WHEN file_type = 'audio' THEN 1 END) as audio
       FROM files`
    );

    // User statistics
    const [userStats] = await db.execute(
      `SELECT user_id, COUNT(*) as file_count, COALESCE(SUM(size), 0) as total_size
       FROM files
       GROUP BY user_id
       ORDER BY total_size DESC
       LIMIT 10`
    );

    // Recent uploads
    const [recent] = await db.execute(
      `SELECT f.*, u.username
       FROM files f
       JOIN users u ON f.user_id = u.id
       ORDER BY f.created_at DESC
       LIMIT 10`
    );

    res.json({
      success: true,
      data: {
        overview: {
          ...stats[0],
          totalSizeMB: (stats[0].total_size / (1024 * 1024)).toFixed(2)
        },
        topUsers: userStats,
        recentUploads: recent
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get all files (Admin only)
 */
export const getAllFiles = async (req, res, next) => {
  try {
    const {
      page = PAGINATION.DEFAULT_PAGE,
      limit = PAGINATION.DEFAULT_LIMIT,
      fileType = '',
      userId = ''
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Build WHERE clause
    const conditions = [];
    const values = [];

    if (fileType) {
      conditions.push('f.file_type = ?');
      values.push(fileType);
    }

    if (userId) {
      conditions.push('f.user_id = ?');
      values.push(userId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const [countResult] = await db.execute(
      `SELECT COUNT(*) as total FROM files f ${whereClause}`,
      values
    );

    // Get files
    const [files] = await db.execute(
      `SELECT f.*, u.username
       FROM files f
       JOIN users u ON f.user_id = u.id
       ${whereClause}
       ORDER BY f.created_at DESC
       LIMIT ? OFFSET ?`,
      [...values, parseInt(limit), offset]
    );

    res.json({
      success: true,
      data: files,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].total,
        pages: Math.ceil(countResult[0].total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Cleanup old files (Admin only)
 */
export const cleanupOldFiles = async (req, res, next) => {
  try {
    const { olderThan = 90 } = req.body; // days

    // Get files to delete
    const [files] = await db.execute(
      'SELECT * FROM files WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
      [parseInt(olderThan)]
    );

    let deletedCount = 0;

    // Delete physical files
    for (const file of files) {
      try {
        await fs.unlink(file.path);
        deletedCount++;
      } catch (error) {
        logger.warn('Failed to delete file', { fileId: file.id, error: error.message });
      }
    }

    // Delete from database
    await db.execute(
      'DELETE FROM files WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
      [parseInt(olderThan)]
    );

    logger.info('Old files cleaned up', { deletedCount, adminId: req.user.id });

    res.json({
      success: true,
      message: `${deletedCount} files deleted successfully`
    });
  } catch (error) {
    next(error);
  }
};

export default {
  uploadFile,
  uploadMultipleFiles,
  getFiles,
  getFileById,
  downloadFile,
  deleteFile,
  getFileStats,
  getAllFiles,
  cleanupOldFiles
};
