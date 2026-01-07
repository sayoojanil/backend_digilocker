import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import logger from './logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config();

// Check if Cloudinary is configured
export const isCloudinaryConfigured = () => {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  return !!(cloudName && apiKey && apiSecret);
};

// Validate Cloudinary credentials
const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
const apiKey = process.env.CLOUDINARY_API_KEY;
const apiSecret = process.env.CLOUDINARY_API_SECRET;

const hasCloudinaryConfig = isCloudinaryConfigured();

// Configure Cloudinary only if credentials are present
if (hasCloudinaryConfig) {
  cloudinary.config({
    cloud_name: cloudName,
    api_key: apiKey,
    api_secret: apiSecret,
  });
}

// Create storage - Cloudinary if configured, otherwise local disk storage
let storage;
if (hasCloudinaryConfig) {
  try {
    storage = new CloudinaryStorage({
      cloudinary: cloudinary,
      params: async (req, file) => {
        // Check if user is authenticated
        if (!req.user || !req.user.id) {
          throw new Error('User authentication required for file upload');
        }

        // Determine resource type based on file mimetype
        let resourceType = 'auto'; // Let Cloudinary auto-detect
        
        // For PDFs, we need to specify 'raw' to avoid issues
        if (file.mimetype === 'application/pdf') {
          resourceType = 'raw';
        }

        return {
          folder: `secure-vault/digiusers/${req.user.id}`, // Organize by user
          resource_type: resourceType,
          allowed_formats: ['jpg', 'jpeg', 'png', 'pdf', 'webp', 'gif'],
          public_id: `${Date.now()}-${Math.round(Math.random() * 1e9)}`,
          transformation: file.mimetype.startsWith('image/') ? [
            { width: 800, height: 800, crop: 'limit', quality: 'auto' }
          ] : [],
        };
      },
    });
  } catch (error) {
    logger.error(`Failed to initialize Cloudinary storage: ${error.message}`);
    // Fall back to local storage if Cloudinary fails
    storage = createLocalStorage();
  }
} else {
  // Use local storage as fallback
  storage = createLocalStorage();
}

// Local storage configuration
function createLocalStorage() {
  const uploadDir = path.join(__dirname, '../uploads');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  return multer.diskStorage({
    destination: function (req, file, cb) {
      const userDir = path.join(uploadDir, req.user?.id || 'default');
      if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
      }
      cb(null, userDir);
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(file.originalname);
      cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    },
  });
}

// File filter
const fileFilter = (req, file, cb) => {
  const allowedTypes = process.env.ALLOWED_FILE_TYPES?.split(',') || [
    'application/pdf',
    'image/jpeg',
    'image/png',
    'image/jpg',
    'image/webp',
    'image/gif'
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error(
        'Invalid file type. Only PDF, JPG, PNG, WebP, and GIF files are allowed.'
      ),
      false
    );
  }
};

// Create multer upload middleware
export const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 20971520, // 20MB default
  },
  fileFilter: fileFilter,
});

// Helper function to delete file from Cloudinary or local storage
export const deleteFromCloudinary = async (publicId, resourceType = 'auto') => {
  if (!isCloudinaryConfigured()) {
    // If using local storage, delete from local filesystem
    try {
      // publicId format for local files: userId/filename
      const filePath = path.join(__dirname, '../uploads', publicId);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        logger.info(`Local file deleted: ${publicId}`);
      } else {
        logger.warn(`Local file not found: ${publicId}`);
      }
      return { result: 'ok' };
    } catch (error) {
      logger.error(`Error deleting local file: ${error.message}`);
      // Don't throw error, just return not_found to allow graceful handling
      return { result: 'not_found' };
    }
  }

  try {
    // For Cloudinary, if resource_type is 'auto', try to determine it or omit it
    const destroyOptions = resourceType && resourceType !== 'auto' 
      ? { resource_type: resourceType }
      : {};
    
    const result = await cloudinary.uploader.destroy(publicId, destroyOptions);
    return result;
  } catch (error) {
    logger.error('Error deleting from Cloudinary:', error);
    throw error;
  }
};

// Helper function to get file URL from Cloudinary public_id
export const getCloudinaryUrl = (publicId, resourceType = 'auto', options = {}) => {
  if (!isCloudinaryConfigured()) {
    // Return local file path if not using Cloudinary
    return `/uploads/${publicId}`;
  }
  return cloudinary.url(publicId, {
    resource_type: resourceType,
    secure: true,
    ...options,
  });
};

export default cloudinary;
