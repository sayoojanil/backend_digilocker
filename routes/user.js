import express from 'express';
import { body, validationResult } from 'express-validator';
import User from '../models/User.js';
import { protect } from '../middleware/auth.js';
import logger from '../config/logger.js';

import { upload, deleteFromCloudinary, isCloudinaryConfigured } from '../config/cloudinary.js';

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
        avatarPublicId: user.avatarPublicId,
        storageUsed: user.storageUsed,
         adharImage: user.adharImage,
        storageLimit: user.storageLimit,
        isGuest: user.isGuest,
        isAdmin: user.isAdmin || false,
        phone: user.phone,
        gender: user.gender,
        dob: user.dob,
        adharImage: user.adharImage,
        adharImagePublicId: user.adharImagePublicId,

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
      if (req.body.phone) updateData.phone = req.body.phone;
      if (req.body.gender) updateData.gender = req.body.gender;
      if (req.body.dob) updateData.dob = req.body.dob;



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
          avatarPublicId: user.avatarPublicId,
          storageUsed: user.storageUsed,
          storageLimit: user.storageLimit,
          isGuest: user.isGuest,
          isAdmin: user.isAdmin || false,
          createdAt: user.createdAt,
          phone: user.phone,
          gender: user.gender,
          dob: user.dob,
          adharImage: user.adharImage,
          adharImagePublicId: user.adharImagePublicId,
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

// @route   POST /api/user/avatar
// @desc    Upload/Update user profile picture (avatar)
// @access  Private
router.post('/avatar', upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded',
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Delete existing avatar from storage if it exists to avoid leakage
    if (user.avatarPublicId) {
      try {
        await deleteFromCloudinary(user.avatarPublicId, 'image');
      } catch (deleteError) {
        logger.error(`Failed to delete old avatar ${user.avatarPublicId}: ${deleteError.message}`);
      }
    }

    let avatarUrl, avatarPublicId;

    if (isCloudinaryConfigured()) {
      avatarUrl = req.file.secure_url || req.file.url || req.file.path;
      avatarPublicId = req.file.public_id || req.file.filename;
    } else {
      const fileName = req.file.filename;
      const userId = user._id.toString();
      avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${userId}/${fileName}`;
      avatarPublicId = `${userId}/${fileName}`;
    }

    user.avatar = avatarUrl;
    user.avatarPublicId = avatarPublicId;
    await user.save();

    res.json({
      success: true,
      message: 'Profile picture updated successfully',
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        avatarPublicId: user.avatarPublicId,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit,
        isGuest: user.isGuest,
        isAdmin: user.isAdmin || false,
        adharImage: user.adharImage,
        adharImagePublicId: user.adharImagePublicId,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    logger.error(`Upload avatar error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error uploading profile picture',
    });
  }
});

// @route   DELETE /api/user/avatar
// @desc    Delete/Remove user profile picture (avatar)
// @access  Private
router.delete('/avatar', async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    if (!user.avatar && !user.avatarPublicId) {
      return res.json({
        success: true,
        message: 'No avatar to remove',
        data: {
          id: user._id,
          name: user.name,
          email: user.email,
          avatar: null,
          avatarPublicId: null,
          storageUsed: user.storageUsed,
          storageLimit: user.storageLimit,
          isGuest: user.isGuest,
          isAdmin: user.isAdmin || false,
          adharImage: user.adharImage,
          adharImagePublicId: user.adharImagePublicId,
          createdAt: user.createdAt,
        },
      });
    }

    // Delete from storage if avatarPublicId exists
    if (user.avatarPublicId) {
      try {
        await deleteFromCloudinary(user.avatarPublicId, 'image');
      } catch (deleteError) {
        logger.error(`Failed to delete avatar from storage ${user.avatarPublicId}: ${deleteError.message}`);
      }
    }

    user.avatar = null;
    user.avatarPublicId = null;
    await user.save();

    res.json({
      success: true,
      message: 'Profile picture removed successfully',
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: null,
        avatarPublicId: null,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit,
        isGuest: user.isGuest,
        isAdmin: user.isAdmin || false,
        adharImage: user.adharImage,
        adharImagePublicId: user.adharImagePublicId,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    logger.error(`Delete avatar error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error removing profile picture',
    });
  }
});

// @route   POST /api/user/adhar
// @desc    Upload/Update user Aadhaar card image
// @access  Private
router.post('/adhar', upload.single('adharImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded',
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Delete existing Aadhaar image from storage if it exists to avoid leaks
    if (user.adharImagePublicId) {
      try {
        await deleteFromCloudinary(user.adharImagePublicId, 'image');
      } catch (deleteError) {
        logger.error(`Failed to delete old Aadhaar ${user.adharImagePublicId}: ${deleteError.message}`);
      }
    }

    let adharImageUrl, adharImagePublicId;

    if (isCloudinaryConfigured()) {
      adharImageUrl = req.file.secure_url || req.file.url || req.file.path;
      adharImagePublicId = req.file.public_id || req.file.filename;
    } else {
      const fileName = req.file.filename;
      const userId = user._id.toString();
      adharImageUrl = `${req.protocol}://${req.get('host')}/uploads/${userId}/${fileName}`;
      adharImagePublicId = `${userId}/${fileName}`;
    }

    user.adharImage = adharImageUrl;
    user.adharImagePublicId = adharImagePublicId;
    await user.save();

    res.json({
      success: true,
      message: 'Aadhaar image updated successfully',
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        avatarPublicId: user.avatarPublicId,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit,
        isGuest: user.isGuest,
        isAdmin: user.isAdmin || false,
        adharImage: user.adharImage,
        adharImagePublicId: user.adharImagePublicId,
        phone: user.phone,
        gender: user.gender,
        dob: user.dob,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    logger.error(`Upload Aadhaar error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error uploading Aadhaar image',
    });
  }
});

// @route   DELETE /api/user/adhar
// @desc    Delete/Remove user Aadhaar image
// @access  Private
router.delete('/adhar', async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    if (!user.adharImage && !user.adharImagePublicId) {
      return res.json({
        success: true,
        message: 'No Aadhaar image to remove',
        data: {
          id: user._id,
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          avatarPublicId: user.avatarPublicId,
          storageUsed: user.storageUsed,
          storageLimit: user.storageLimit,
          isGuest: user.isGuest,
          isAdmin: user.isAdmin || false,
          adharImage: null,
          adharImagePublicId: null,
          phone: user.phone,
          gender: user.gender,
          dob: user.dob,
          createdAt: user.createdAt,
        },
      });
    }

    // Delete from storage if adharImagePublicId exists
    if (user.adharImagePublicId) {
      try {
        await deleteFromCloudinary(user.adharImagePublicId, 'image');
      } catch (deleteError) {
        logger.error(`Failed to delete Aadhaar from storage ${user.adharImagePublicId}: ${deleteError.message}`);
      }
    }

    user.adharImage = null;
    user.adharImagePublicId = null;
    await user.save();

    res.json({
      success: true,
      message: 'Aadhaar image removed successfully',
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        avatarPublicId: user.avatarPublicId,
        storageUsed: user.storageUsed,
        storageLimit: user.storageLimit,
        isGuest: user.isGuest,
        isAdmin: user.isAdmin || false,
        adharImage: null,
        adharImagePublicId: null,
        phone: user.phone,
        gender: user.gender,
        dob: user.dob,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    logger.error(`Delete Aadhaar error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error removing Aadhaar image',
    });
  }
});

export default router;


