import express from 'express';
import Document from '../models/Document.js';
import User from '../models/User.js';
import { protect } from '../middleware/auth.js';
import logger from '../config/logger.js';

const router = express.Router();

// All routes require authentication
router.use(protect);

// @route   GET /api/stats
// @desc    Get storage statistics for authenticated user
// @access  Private
router.get('/', async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const documents = await Document.find({
      userId: req.user.id,
      isArchived: false,
    });

    const categoryBreakdown = {};

    documents.forEach((doc) => {
      const cat = doc.category || 'other';
      categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + 1;
    });

    const stats = {
      used: user.storageUsed,
      limit: user.storageLimit,
      documentCount: documents.length,
      categoryBreakdown,
    };

    res.json({
      success: true,
      data: stats,
    });
  } catch (error) {
    logger.error(`Get stats error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
    });
  }
});

export default router;


