import express from 'express';
import { body, validationResult } from 'express-validator';
import mongoose from 'mongoose';
import User from '../models/User.js';
import { generateToken } from '../utils/generateToken.js';
import logger from '../config/logger.js';
import { upload, deleteFromCloudinary, isCloudinaryConfigured } from '../config/cloudinary.js';

const router = express.Router();

// @route   POST /auth/signup
// @desc    Register a new user
// @access  Public
router.post(
  '/signup',
  (req, res, next) => {
    // Generate ObjectId for the user beforehand so the file upload path has access to the user ID folder
    req.userId = new mongoose.Types.ObjectId().toString();
    next();
  },
  upload.single('adharImage'),
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        // Clean up file if uploaded
        if (req.file) {
          const publicId = isCloudinaryConfigured()
            ? req.file.public_id
            : `${req.userId}/${req.file.filename}`;
          const resourceType = isCloudinaryConfigured()
            ? req.file.resource_type
            : 'auto';
          try {
            await deleteFromCloudinary(publicId, resourceType);
          } catch (deleteError) {
            logger.error(`Error deleting file on validation failure: ${deleteError.message}`);
          }
        }

        const errorMessages = errors.array().map(err => err.msg).join(', ');
        return res.status(400).json({
          success: false,
          message: errorMessages || 'Validation failed',
          errors: errors.array(),
        });
      }

      const { name, email, password } = req.body;

      // Check if user already exists
      const userExists = await User.findOne({ email });
      if (userExists) {
        // Clean up file if uploaded
        if (req.file) {
          const publicId = isCloudinaryConfigured()
            ? req.file.public_id
            : `${req.userId}/${req.file.filename}`;
          const resourceType = isCloudinaryConfigured()
            ? req.file.resource_type
            : 'auto';
          try {
            await deleteFromCloudinary(publicId, resourceType);
          } catch (deleteError) {
            logger.error(`Error deleting file on duplicate user: ${deleteError.message}`);
          }
        }

        return res.status(400).json({
          success: false,
          message: 'User already exists',
        });
      }

      // Determine Aadhar image URL and public ID
      let adharImageUrl = null;
      let adharImagePublicId = null;

      if (req.file) {
        if (isCloudinaryConfigured()) {
          adharImageUrl = req.file.secure_url || req.file.url || req.file.path;
          adharImagePublicId = req.file.public_id || req.file.filename;
        } else {
          const fileName = req.file.filename;
          const userId = req.userId;
          adharImageUrl = `${req.protocol}://${req.get('host')}/uploads/${userId}/${fileName}`;
          adharImagePublicId = `${userId}/${fileName}`;
        }
      }

      // Create user
      const user = await User.create({
        _id: req.userId,
        name,
        email,
        password,
        adharImage: adharImageUrl,
        adharImagePublicId: adharImagePublicId,
      });

      logger.info(`New user registered: ${user.email}`);

      res.status(201).json({
        success: true,
        token: generateToken(user._id, user.isAdmin),
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
          avatar: user.avatar || null,
          adharImage: user.adharImage || null,
          adharImagePublicId: user.adharImagePublicId || null,
          storageUsed: user.storageUsed || 0,
          storageLimit: user.storageLimit || 1073741824,
          isGuest: user.isGuest || false,
          isAdmin: user.isAdmin || false,
          createdAt: user.createdAt,
        },
      });
    } catch (error) {
      logger.error(`Signup error: ${error.message}`);
      
      // Clean up file if uploaded
      if (req.file) {
        try {
          const publicId = isCloudinaryConfigured()
            ? req.file.public_id
            : `${req.userId}/${req.file.filename}`;
          const resourceType = isCloudinaryConfigured()
            ? req.file.resource_type
            : 'auto';
          await deleteFromCloudinary(publicId, resourceType);
        } catch (deleteError) {
          logger.error(`Error deleting file after signup failure: ${deleteError.message}`);
        }
      }
      
      // Handle duplicate email error
      if (error.code === 11000 || error.message.includes('duplicate')) {
        return res.status(400).json({
          success: false,
          message: 'User with this email already exists',
        });
      }
      
      res.status(500).json({
        success: false,
        message: error.message || 'Server error during signup',
      });
    }
  }
);

// @route   PUT /auth/change-password
// @desc    Change user password
// @access  Private


// @route   POST /loginWithEmail
// @desc    Authenticate user and get token
// @access  Public
router.post(
  '/loginWithEmail',
  [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(err => err.msg).join(', ');
        return res.status(400).json({
          success: false,
          message: errorMessages || 'Validation failed',
          errors: errors.array(),
        });
      }

      const { email, password } = req.body;

      // Check for user
      const user = await User.findOne({ email }).select('+password');
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
      }

      // Check password
      const isMatch = await user.matchPassword(password);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
      }

      logger.info(`User logged in: ${user.email}`);

      res.json({
        success: true,
        token: generateToken(user._id, user.isAdmin),
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
          avatar: user.avatar || null,
          adharImage: user.adharImage || null,
          adharImagePublicId: user.adharImagePublicId || null,
          storageUsed: user.storageUsed || 0,
          storageLimit: user.storageLimit || 1073741824,
          isGuest: user.isGuest || false,
          isAdmin: user.isAdmin || false,
          phone: user.phone || '',
          gender: user.gender || '',
          dob: user.dob || null,
          createdAt: user.createdAt,
        },
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}`);
      res.status(500).json({
        success: false,
        message: error.message || 'Server error during login',
      });
    }
  }
);

export default router;


