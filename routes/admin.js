import express from 'express';
import User from '../models/User.js';
import Document from '../models/Document.js';
import { adminAuth } from '../middleware/adminAuth.js';
import logger from '../config/logger.js';

const router = express.Router();

// Apply adminAuth middleware to all admin routes
router.use(adminAuth);

// @route   GET /api/admin/users
// @desc    Get all users
// @access  Private/Admin
router.get('/users', async (req, res) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 });
    res.json({
      success: true,
      data: users.map(user => ({
        id: user.id || user._id.toString(),
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit,
        isGuest: user.isGuest,
        isAdmin: user.isAdmin,
        createdAt: user.createdAt,
      })),
    });
  } catch (error) {
    logger.error(`Admin Get Users error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching users',
    });
  }
});

// @route   GET /api/admin/users/:id
// @desc    Get specific user details and their documents
// @access  Private/Admin
router.get('/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const documents = await Document.find({ userId: user._id }).sort({ createdAt: -1 });

    res.json({
      success: true,
      data: {
        user: {
          id: user.id || user._id.toString(),
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          storageUsed: user.storageUsed,
          storageLimit: user.storageLimit,
          isGuest: user.isGuest,
          isAdmin: user.isAdmin,
          createdAt: user.createdAt,
        },
        documents: documents.map(doc => ({
          id: doc._id.toString(),
          name: doc.name,
          type: doc.type,
          category: doc.category,
          fileType: doc.fileType,
          size: doc.size,
          tags: doc.tags,
          metadata: doc.metadata,
          thumbnailUrl: doc.thumbnailUrl,
          fileUrl: doc.fileUrl,
          isArchived: doc.isArchived,
          isFavorite: doc.isFavorite,
          folder: doc.folder,
          verificationStatus: doc.verificationStatus || 'pending',
          createdAt: doc.createdAt,
        })),
      },
    });
  } catch (error) {
    logger.error(`Admin Get User Details error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching user details',
    });
  }
});

// @route   PATCH /api/admin/documents/:id/status
// @desc    Update document verification status
// @access  Private/Admin
router.patch('/documents/:id/status', async (req, res) => {
  try {
    const { status } = req.body;

    if (!['pending', 'verification_sent', 'verified'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status. Must be pending, verification_sent, or verified',
      });
    }

    const document = await Document.findById(req.params.id);
    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    document.verificationStatus = status;
    await document.save();

    logger.info(`Admin updated document ${document._id} status to ${status}`);

    res.json({
      success: true,
      message: 'Document verification status updated successfully',
      data: {
        id: document._id.toString(),
        verificationStatus: document.verificationStatus,
      },
    });
  } catch (error) {
    logger.error(`Admin Update Document Status error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error updating document status',
    });
  }
});

export default router;
