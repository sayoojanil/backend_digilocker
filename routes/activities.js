import express from 'express';
import ActivityLog from '../models/ActivityLog.js';
import { protect } from '../middleware/auth.js';
import logger from '../config/logger.js';

const router = express.Router();

// All routes require authentication
router.use(protect);

// @route   GET /api/activities
// @desc    Get activity logs for authenticated user
// @access  Private
router.get('/', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const activities = await ActivityLog.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('documentId', 'name category');

    res.json({
      success: true,
      count: activities.length,
      data: activities,
    });
  } catch (error) {
    logger.error(`Get activities error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching activities',
    });
  }
});

export default router;


