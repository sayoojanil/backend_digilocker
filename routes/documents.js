import express from 'express';
import { body, validationResult, query } from 'express-validator';
import Document from '../models/Document.js';
import ActivityLog from '../models/ActivityLog.js';
import User from '../models/User.js';
import { protect } from '../middleware/auth.js';
import { upload, deleteFromCloudinary, isCloudinaryConfigured } from '../config/cloudinary.js';
import logger from '../config/logger.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import https from 'https';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// All routes require authentication
router.use(protect);

// @route   GET /api/documents
// @desc    Get all documents for authenticated user
// @access  Private
router.get(
  '/',
  [
    query('category').optional().isIn([
      'identity',
      'financial',
      'medical',
      'insurance',
      'legal',
      'personal',
      'travel',
      'other',
    ]),
    query('favorite').optional().isBoolean(),
    query('archived').optional().isBoolean(),
    query('search').optional().isString(),
  ],
  async (req, res) => {
    try {
      const { category, favorite, archived, search } = req.query;
      const query = { userId: req.user.id };

      if (category) query.category = category;
      if (favorite === 'true') query.isFavorite = true;
      if (archived === 'true') query.isArchived = true;
      else if (archived !== 'true') query.isArchived = false;

      let documents = await Document.find(query).sort({ createdAt: -1 });

      // Search filter
      if (search) {
        const searchLower = search.toLowerCase();
        documents = documents.filter(
          (doc) =>
            doc.name.toLowerCase().includes(searchLower) ||
            doc.tags.some((tag) => tag.toLowerCase().includes(searchLower)) ||
            doc.metadata.issuer?.toLowerCase().includes(searchLower) ||
            doc.metadata.notes?.toLowerCase().includes(searchLower)
        );
      }

      res.json({
        success: true,
        count: documents.length,
        data: documents,
      });
    } catch (error) {
      logger.error(`Get documents error: ${error.message}`);
      res.status(500).json({
        success: false,
        message: 'Error fetching documents',
      });
    }
  }
);

// @route   GET /api/documents/:id
// @desc    Get single document
// @access  Private
router.get('/:id', async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    // Log view activity
    await ActivityLog.create({
      userId: req.user.id,
      documentId: document._id,
      documentName: document.name,
      action: 'view',
    });

    res.json({
      success: true,
      data: document,
    });
  } catch (error) {
    logger.error(`Get document error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching document',
    });
  }
});

// @route   POST /api/documents
// @desc    Upload/create a new document
// @access  Private
router.post(
  '/',
  upload.single('file'),
  [
    body('name').optional().trim(),
    body('category')
      .optional()
      .isIn([
        'identity',
        'financial',
        'medical',
        'insurance',
        'legal',
        'personal',
        'travel',
        'other',
      ])
      .withMessage('Invalid category'),
    body('type')
      .optional()
      .isIn(['pdf', 'image', 'license', 'insurance', 'other'])
      .withMessage('Invalid document type'),
  ],
  async (req, res) => {
    try {
      // Validate file first
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: 'No file uploaded',
        });
      }

      // Validate other fields (optional, but if provided must be valid)
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array(),
        });
      }

      // Check storage limit
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const fileSize = req.file.size || 0;
      const newStorageUsed = (user.storageUsed || 0) + fileSize;
      if (newStorageUsed > (user.storageLimit || 1073741824)) {
        // Delete uploaded file
        try {
          const publicId = isCloudinaryConfigured()
            ? req.file.public_id
            : `${req.user.id}/${req.file.filename}`;
          const resourceType = isCloudinaryConfigured()
            ? req.file.resource_type
            : 'auto';
          await deleteFromCloudinary(publicId, resourceType);
        } catch (deleteError) {
          logger.error(`Error deleting file after storage limit: ${deleteError.message}`);
        }
        return res.status(400).json({
          success: false,
          message: 'Storage limit exceeded',
        });
      }

      // Determine fileType from mimetype (must be one of: pdf, jpg, png, webp, gif)
      const mimetype = (req.file.mimetype || '').toLowerCase().split(';')[0].trim();
      let fileType;

      if (mimetype === 'application/pdf') {
        fileType = 'pdf';
      } else if (mimetype === 'image/jpeg' || mimetype === 'image/jpg') {
        fileType = 'jpg';
      } else if (mimetype === 'image/png') {
        fileType = 'png';
      } else if (mimetype === 'image/webp') {
        fileType = 'webp';
      } else if (mimetype === 'image/gif') {
        fileType = 'gif';
      } else {
        logger.error('Invalid file type received', {
          mimetype: req.file.mimetype,
          normalizedMimetype: mimetype,
          originalname: req.file.originalname,
          filename: req.file.filename
        });
        return res.status(400).json({
          success: false,
          message: 'Invalid file type. Only PDF, JPG, PNG, WebP, and GIF files are allowed.',
        });
      }

      // Determine file URL and public ID based on storage type
      let fileUrl, publicId, resourceType, thumbnailUrl;

      if (isCloudinaryConfigured()) {
        // Cloudinary provides secure_url and public_id
        fileUrl = req.file.secure_url || req.file.url || req.file.path;
        publicId = req.file.public_id || req.file.filename;

        // Determine resource type from URL or file type
        if (req.file.resource_type && req.file.resource_type !== 'auto') {
          resourceType = req.file.resource_type;
        } else if (fileType === 'pdf') {
          resourceType = 'raw';
        } else {
          resourceType = 'image';
        }

        thumbnailUrl = resourceType === 'image' ? fileUrl : null;

        // Validate Cloudinary response
        if (!fileUrl) {
          logger.error('Cloudinary upload incomplete', {
            file: req.file,
            hasSecureUrl: !!req.file.secure_url,
            hasUrl: !!req.file.url,
            hasPath: !!req.file.path,
            hasPublicId: !!req.file.public_id,
            hasFilename: !!req.file.filename
          });
          return res.status(500).json({
            success: false,
            message: 'File upload failed. Cloudinary did not return file information.',
          });
        }

        // If we don't have public_id, try to extract it from the URL
        if (!publicId && fileUrl) {
          try {
            const urlParts = fileUrl.split('/');
            const uploadIndex = urlParts.findIndex(part => part === 'upload');
            if (uploadIndex !== -1 && urlParts.length > uploadIndex + 2) {
              publicId = urlParts.slice(uploadIndex + 2).join('/').split('.')[0];
            }
          } catch (e) {
            logger.warn('Could not extract public_id from URL');
          }
        }
      } else {
        // Local storage - construct file URL
        let fileName = req.file.filename;

        if (!fileName) {
          if (req.file.path) {
            const pathParts = req.file.path.split(path.sep);
            fileName = pathParts[pathParts.length - 1];
          } else if (req.file.originalname) {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
            const ext = path.extname(req.file.originalname);
            fileName = `file-${uniqueSuffix}${ext}`;
          } else {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
            const ext = fileType === 'pdf' ? '.pdf' : fileType === 'jpg' ? '.jpg' : '.png';
            fileName = `file-${uniqueSuffix}${ext}`;
          }
        }

        const userId = req.user.id.toString();
        fileUrl = `${req.protocol}://${req.get('host')}/uploads/${userId}/${fileName}`;
        publicId = `${userId}/${fileName}`;
        resourceType = 'auto';
        thumbnailUrl = fileType !== 'pdf' ? fileUrl : null;
      }

      // Ensure fileUrl and publicId are valid strings
      const finalFileUrl = String(fileUrl || '').trim();
      const finalPublicId = String(publicId || '').trim();

      if (!finalFileUrl || !finalPublicId) {
        logger.error('Missing fileUrl or publicId after upload processing', {
          fileUrl: finalFileUrl,
          publicId: finalPublicId,
          originalFileUrl: fileUrl,
          originalPublicId: publicId,
          file: req.file,
          isCloudinaryConfigured: isCloudinaryConfigured()
        });
        return res.status(500).json({
          success: false,
          message: 'Error processing uploaded file. Missing file information.',
        });
      }

      // Prepare document data
      const documentName = (req.body.name && req.body.name.trim()) || req.file.originalname || `Document-${Date.now()}`;
      const documentType = req.body.type || (fileType === 'pdf' ? 'pdf' : 'image');
      const documentCategory = req.body.category || 'other';

      // Parse tags and metadata safely
      let tags = [];
      if (req.body.tags) {
        try {
          tags = typeof req.body.tags === 'string' ? JSON.parse(req.body.tags) : req.body.tags;
          if (!Array.isArray(tags)) tags = [];
        } catch (e) {
          logger.warn('Failed to parse tags, using empty array');
          tags = [];
        }
      }

      let metadata = {};
      if (req.body.metadata) {
        try {
          metadata = typeof req.body.metadata === 'string' ? JSON.parse(req.body.metadata) : req.body.metadata;
          if (typeof metadata !== 'object' || metadata === null) metadata = {};
        } catch (e) {
          logger.warn('Failed to parse metadata, using empty object');
          metadata = {};
        }
      }

      // Create document
      const document = await Document.create({
        userId: req.user.id,
        name: documentName,
        type: documentType,
        category: documentCategory,
        fileType: fileType,
        size: fileSize,
        tags: tags,
        metadata: metadata,
        fileUrl: finalFileUrl,
        cloudinaryPublicId: finalPublicId,
        cloudinaryResourceType: resourceType,
        thumbnailUrl: thumbnailUrl,
        isArchived: false,
        isFavorite: false,
      });

      // Update user storage
      await User.findByIdAndUpdate(req.user.id, {
        storageUsed: newStorageUsed,
      });

      // Log activity
      try {
        await ActivityLog.create({
          userId: req.user.id,
          documentId: document._id,
          documentName: document.name,
          action: 'upload',
        });
      } catch (activityError) {
        logger.error(`Failed to log activity: ${activityError.message}`);
      }

      logger.info(`Document uploaded successfully: ${document.name} by user ${req.user.id}`);

      res.status(201).json({
        success: true,
        data: document,
      });
    } catch (error) {
      logger.error(`Upload document error: ${error.message}`);
      logger.error(`Error stack: ${error.stack}`);

      let errorMessage = 'Error uploading document';

      if (error.name === 'ValidationError') {
        errorMessage = `Validation error: ${error.message}`;
      } else if (error.message) {
        errorMessage = error.message;
      }

      // Delete uploaded file if upload failed
      if (req.file) {
        try {
          const publicId = isCloudinaryConfigured()
            ? req.file.public_id
            : `${req.user.id}/${req.file.filename}`;
          const resourceType = isCloudinaryConfigured()
            ? req.file.resource_type
            : 'auto';
          await deleteFromCloudinary(publicId, resourceType);
        } catch (deleteError) {
          logger.error(`Error deleting file after upload failure: ${deleteError.message}`);
        }
      }

      res.status(500).json({
        success: false,
        message: errorMessage,
      });
    }
  }
);

// @route   PUT /api/documents/:id
// @desc    Update a document
// @access  Private
router.put(
  '/:id',
  [
    body('name').optional().trim().notEmpty(),
    body('category')
      .optional()
      .isIn([
        'identity',
        'financial',
        'medical',
        'insurance',
        'legal',
        'personal',
        'travel',
        'other',
      ]),
  ],
  async (req, res) => {
    logger.info(`PUT /api/documents/${req.params.id} hit`);
    logger.info(`Request body keys: ${Object.keys(req.body)}`);
    if (req.body.tags) logger.info(`Tags type: ${typeof req.body.tags}, value: ${JSON.stringify(req.body.tags)}`);
    if (req.body.metadata) logger.info(`Metadata type: ${typeof req.body.metadata}, value: ${JSON.stringify(req.body.metadata)}`);

    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array(),
        });
      }

      let document = await Document.findOne({
        _id: req.params.id,
        userId: req.user.id,
      });

      if (!document) {
        return res.status(404).json({
          success: false,
          message: 'Document not found',
        });
      }

      const oldName = document.name;

      // Update document
      const updateData = {};
      if (req.body.name) updateData.name = req.body.name;
      if (req.body.category) updateData.category = req.body.category;
      if (req.body.tags) updateData.tags = req.body.tags;
      if (req.body.metadata) updateData.metadata = req.body.metadata;
      if (req.body.isArchived !== undefined) updateData.isArchived = req.body.isArchived;
      if (req.body.isFavorite !== undefined) updateData.isFavorite = req.body.isFavorite;

      document = await Document.findByIdAndUpdate(
        req.params.id,
        updateData,
        { new: true, runValidators: true }
      );

      // Log rename activity if name changed
      if (oldName !== document.name) {
        await ActivityLog.create({
          userId: req.user.id,
          documentId: document._id,
          documentName: document.name,
          action: 'rename',
        });
      }

      res.json({
        success: true,
        data: document,
      });
    } catch (error) {
      logger.error(`Update document error: ${error.message}`);
      logger.error(error.stack);
      res.status(500).json({
        success: false,
        message: 'Error updating document',
      });
    }
  }
);

// @route   DELETE /api/documents/:id
// @desc    Delete a document
// @access  Private
router.delete('/:id', async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    // Delete file from Cloudinary
    if (document.cloudinaryPublicId) {
      try {
        await deleteFromCloudinary(
          document.cloudinaryPublicId,
          document.cloudinaryResourceType || 'auto'
        );
      } catch (error) {
        logger.error(`Error deleting file from Cloudinary: ${error.message}`);
      }
    }

    // Update user storage
    const user = await User.findById(req.user.id);
    await User.findByIdAndUpdate(req.user.id, {
      storageUsed: Math.max(0, user.storageUsed - document.size),
    });

    // Log activity
    await ActivityLog.create({
      userId: req.user.id,
      documentId: document._id,
      documentName: document.name,
      action: 'delete',
    });

    // Delete document
    await Document.findByIdAndDelete(req.params.id);

    logger.info(`Document deleted: ${document.name} by user ${req.user.id}`);

    res.json({
      success: true,
      message: 'Document deleted successfully',
    });
  } catch (error) {
    logger.error(`Delete document error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error deleting document',
    });
  }
});

// @route   POST /api/documents/:id/archive
// @desc    Archive/unarchive a document
// @access  Private
router.post('/:id/archive', async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    document.isArchived = !document.isArchived;
    await document.save();

    // Log activity
    await ActivityLog.create({
      userId: req.user.id,
      documentId: document._id,
      documentName: document.name,
      action: 'archive',
    });

    res.json({
      success: true,
      data: document,
    });
  } catch (error) {
    logger.error(`Archive document error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error archiving document',
    });
  }
});

// @route   POST /api/documents/:id/favorite
// @desc    Toggle favorite status
// @access  Private
router.post('/:id/favorite', async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    document.isFavorite = !document.isFavorite;
    await document.save();

    res.json({
      success: true,
      data: document,
    });
  } catch (error) {
    logger.error(`Toggle favorite error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error updating favorite status',
    });
  }
});

// @route   GET /api/documents/:id/download
// @desc    Get download URL for a document
// @access  Private
router.get('/:id/download', async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    if (!document.fileUrl) {
      return res.status(404).json({
        success: false,
        message: 'File URL not found',
      });
    }

    // Log download activity
    await ActivityLog.create({
      userId: req.user.id,
      documentId: document._id,
      documentName: document.name,
      action: 'download',
    });

    // Handle download based on storage type
    if (isCloudinaryConfigured() && document.fileUrl.startsWith('http')) {
      // For Cloudinary, create a download URL with proper filename
      let downloadUrl = document.fileUrl;
      
      // Add download transformation if it's a Cloudinary URL
      if (downloadUrl.includes('cloudinary.com') && downloadUrl.includes('/upload/')) {
        const parts = downloadUrl.split('/upload/');
        if (parts.length === 2) {
          // Add fl_attachment transformation with filename
          const safeFilename = encodeURIComponent(document.name.replace(/\.[^/.]+$/, "")) + 
                             (document.fileType === 'pdf' ? '.pdf' : 
                              document.fileType === 'jpg' ? '.jpg' : 
                              document.fileType === 'png' ? '.png' : 
                              document.fileType === 'webp' ? '.webp' : 
                              document.fileType === 'gif' ? '.gif' : '.pdf');
          downloadUrl = `${parts[0]}/upload/fl_attachment:${safeFilename}/${parts[1]}`;
        }
      }
      
      // Redirect to the Cloudinary download URL
      res.redirect(downloadUrl);
    } else {
      // Local file - fix path resolution
      const filename = path.basename(document.fileUrl);
      const userId = document.userId.toString();
      const correctFilePath = path.join(__dirname, '..', 'uploads', userId, filename);

      logger.info(`Attempting download for document ${document._id}`);
      logger.info(`- Document URL: ${document.fileUrl}`);
      logger.info(`- Correct FilePath: ${correctFilePath}`);

      if (fs.existsSync(correctFilePath)) {
        // Set proper headers for download with filename
        const safeFilename = encodeURIComponent(document.name) + 
                           (document.fileType === 'pdf' ? '.pdf' : 
                            document.fileType === 'jpg' ? '.jpg' : 
                            document.fileType === 'png' ? '.png' : 
                            document.fileType === 'webp' ? '.webp' : 
                            document.fileType === 'gif' ? '.gif' : '');
        
        res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
        res.download(correctFilePath, document.name);
      } else {
        logger.error(`File not found for download: ${correctFilePath}`);
        return res.status(404).json({
          success: false,
          message: 'File not found on server',
        });
      }
    }
  } catch (error) {
    logger.error(`Download document error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error downloading document',
    });
  }
});

// @route   GET /api/documents/:id/view
// @desc    View document inline (for PDFs in iframe or new tab)
// @access  Private
router.get('/:id/view', async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!document) {
      logger.error(`View PDF failed: Document not found ${req.params.id}`);
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    logger.info(`View PDF Request: ${document._id} (${document.name})`);
    logger.info(`- FileType: ${document.fileType}`);
    logger.info(`- FileUrl: ${document.fileUrl}`);

    // Only allow viewing for PDFs (case insensitive check)
    const fileTypeLower = document.fileType?.toLowerCase();
    if (fileTypeLower !== 'pdf') {
      logger.warn(`View PDF blocked: Invalid fileType '${document.fileType}' for doc ${document._id}`);
      return res.status(400).json({
        success: false,
        message: 'This route is only for PDF documents',
      });
    }

    // For Cloudinary URLs
    if (document.fileUrl.includes('cloudinary')) {
      let cloudinaryUrl = document.fileUrl;
      
      // Ensure the URL has inline viewing (no forced download)
      if (cloudinaryUrl.includes('/upload/')) {
        const parts = cloudinaryUrl.split('/upload/');
        if (parts.length === 2) {
          // Check if it already has transformations
          const transformationPart = parts[1].split('/');
          const hasFlAttachment = transformationPart.some(part => part.startsWith('fl_attachment'));
          
          if (hasFlAttachment) {
            // Remove any existing fl_attachment transformation
            cloudinaryUrl = parts[0] + '/upload/' + 
                           transformationPart.filter(part => !part.startsWith('fl_attachment')).join('/');
          }
          
          // Add fl_attachment:false for inline viewing
          cloudinaryUrl = `${parts[0]}/upload/fl_attachment:false/${parts[1]}`;
        }
      }
      
      logger.info(`Proxying Cloudinary URL: ${cloudinaryUrl}`);
      
      // Set proper headers for inline viewing
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(document.name)}.pdf"`);
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      
      // Proxy the Cloudinary content
      https.get(cloudinaryUrl, (cloudinaryRes) => {
        // Forward status code
        res.statusCode = cloudinaryRes.statusCode;
        
        // Forward headers (but override Content-Disposition)
        Object.keys(cloudinaryRes.headers).forEach(key => {
          const lowerKey = key.toLowerCase();
          if (lowerKey !== 'content-disposition') {
            res.setHeader(key, cloudinaryRes.headers[key]);
          }
        });
        
        // Ensure Content-Type is correct
        res.setHeader('Content-Type', 'application/pdf');
        
        // Pipe the response
        cloudinaryRes.pipe(res);
      }).on('error', (err) => {
        logger.error(`Cloudinary proxy error: ${err.message}`);
        res.status(500).json({
          success: false,
          message: 'Error fetching document from cloud storage',
        });
      });
      
      return;
    }

    // For local files
    const filename = path.basename(document.fileUrl);
    const userId = document.userId.toString();
    const filePath = path.join(__dirname, '..', 'uploads', userId, filename);

    logger.info(`View PDF Attempt`);
    logger.info(`- Doc ID: ${document._id}`);
    logger.info(`- URL: ${document.fileUrl}`);
    logger.info(`- Target Path: ${filePath}`);

    if (!fs.existsSync(filePath)) {
      logger.error(`View PDF failed: File not found at ${filePath}`);
      return res.status(404).json({
        success: false,
        message: 'File not found on server',
      });
    }

    // Set headers for inline viewing with proper filename
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(document.name)}.pdf"`);
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);

  } catch (error) {
    logger.error(`View document error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error viewing document',
    });
  }
});

export default router;