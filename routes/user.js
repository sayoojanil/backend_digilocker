import express from 'express';
import { body, validationResult } from 'express-validator';
import User from '../models/User.js';
import { protect } from '../middleware/auth.js';
import logger from '../config/logger.js';

const router = express.Router();

// All routes require authentication
router.use(protect);

// @route   GET /api/user/profile
// @desc    Get user profile
// @access  Private
router.get('/profile', async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json({
      success: true,
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit,
        isGuest: user.isGuest,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    logger.error(`Get profile error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching profile',
    });
  }
});

// @route   PUT /api/user/profile
// @desc    Update user profile
// @access  Private
router.put(
  '/profile',
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array(),
        });
      }

      const updateData = {};
      if (req.body.name) updateData.name = req.body.name;
      if (req.body.avatar !== undefined) updateData.avatar = req.body.avatar;

      const user = await User.findByIdAndUpdate(
        req.user.id,
        updateData,
        { new: true, runValidators: true }
      );

      res.json({
        success: true,
        data: {
          id: user._id,
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          storageUsed: user.storageUsed,
          storageLimit: user.storageLimit,
          isGuest: user.isGuest,
          createdAt: user.createdAt,
        },
      });
    } catch (error) {
      logger.error(`Update profile error: ${error.message}`);
      res.status(500).json({
        success: false,
        message: 'Error updating profile',
      });
    }
  }
);

export default router;


