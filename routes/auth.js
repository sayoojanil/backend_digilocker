import express from 'express';
import { body, validationResult } from 'express-validator';
import User from '../models/User.js';
import { generateToken } from '../utils/generateToken.js';
import logger from '../config/logger.js';

const router = express.Router();

// @route   POST /auth/signup
// @desc    Register a new user
// @access  Public
router.post(
  '/signup',
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
        return res.status(400).json({
          success: false,
          message: 'User already exists',
        });
      }

      // Create user
      const user = await User.create({
        name,
        email,
        password,
      });

      logger.info(`New user registered: ${user.email}`);

      res.status(201).json({
        success: true,
        token: generateToken(user._id),
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
          avatar: user.avatar || null,
          storageUsed: user.storageUsed || 0,
          storageLimit: user.storageLimit || 1073741824,
          isGuest: user.isGuest || false,
          createdAt: user.createdAt,
        },
      });
    } catch (error) {
      logger.error(`Signup error: ${error.message}`);
      
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
        token: generateToken(user._id),
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
          avatar: user.avatar || null,
          storageUsed: user.storageUsed || 0,
          storageLimit: user.storageLimit || 1073741824,
          isGuest: user.isGuest || false,
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


