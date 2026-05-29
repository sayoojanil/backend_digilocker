import express from 'express';
import Category from '../models/Category.js';
import Document from '../models/Document.js';
import { protect } from '../middleware/auth.js';
import logger from '../config/logger.js';

const router = express.Router();

// All routes require authentication
router.use(protect);

// @route   GET /api/categories
// @desc    Get all custom categories for user
// @access  Private
router.get('/', async (req, res) => {
  try {
    const categories = await Category.find({ userId: req.user.id });
    res.json({
      success: true,
      data: categories,
    });
  } catch (error) {
    logger.error(`Get categories error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching categories',
    });
  }
});

// @route   POST /api/categories
// @desc    Create a new custom category
// @access  Private
router.post('/', async (req, res) => {
  try {
    const { label, icon } = req.body;

    if (!label) {
      return res.status(400).json({
        success: false,
        message: 'Category label is required',
      });
    }

    const key = `custom_${Date.now()}`;

    const newCategory = await Category.create({
      userId: req.user.id,
      key,
      label,
      icon: icon || 'Folder',
    });

    res.status(201).json({
      success: true,
      data: newCategory,
    });
  } catch (error) {
    logger.error(`Create category error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error while creating category',
    });
  }
});

// @route   DELETE /api/categories/:id
// @desc    Delete a custom category
// @access  Private
router.delete('/:id', async (req, res) => {
  try {
    const category = await Category.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!category) {
      return res.status(404).json({
        success: false,
        message: 'Category not found or unauthorized',
      });
    }

    const categoryKey = category.key;

    await Category.deleteOne({ _id: req.params.id });

    // Update documents using this category to 'other'
    await Document.updateMany(
      { userId: req.user.id, category: categoryKey },
      { $set: { category: 'other' } }
    );

    res.json({
      success: true,
      message: 'Category deleted successfully',
    });
  } catch (error) {
    logger.error(`Delete category error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Server error while deleting category',
    });
  }
});

export default router;
