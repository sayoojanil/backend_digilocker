import mongoose from 'mongoose';

const documentMetadataSchema = new mongoose.Schema({
  issuer: {
    type: String,
    default: null,
  },
  expiryDate: {
    type: Date,
    default: null,
  },
  notes: {
    type: String,
    default: null,
  },
  documentNumber: {
    type: String,
    default: null,
  },
}, { _id: false });

const documentSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: [true, 'Document name is required'],
      trim: true,
    },
    type: {
      type: String,
      enum: ['pdf', 'image', 'license', 'insurance', 'other'],
      required: true,
    },
    category: {
      type: String,
      enum: [
        'identity',
        'financial',
        'medical',
        'insurance',
        'legal',
        'personal',
        'travel',
        'other',
      ],
      required: true,
    },
    fileType: {
      type: String,
      enum: ['pdf', 'jpg', 'png'],
      required: true,
    },
    size: {
      type: Number,
      required: true,
    },
    tags: [
      {
        type: String,
        trim: true,
      },
    ],
    metadata: {
      type: documentMetadataSchema,
      default: {},
    },
    thumbnailUrl: {
      type: String,
      default: null,
    },
    fileUrl: {
      type: String,
      required: [true, 'fileUrl is required'],
    },
    cloudinaryPublicId: {
      type: String,
      required: [true, 'File identifier is required'],
      // This field stores the file identifier for both Cloudinary and local storage
    },
    cloudinaryResourceType: {
      type: String,
      default: 'auto',
    },
    isArchived: {
      type: Boolean,
      default: false,
      index: true,
    },
    isFavorite: {
      type: Boolean,
      default: false,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for better query performance
documentSchema.index({ userId: 1, isArchived: 1 });
documentSchema.index({ userId: 1, category: 1 });
documentSchema.index({ userId: 1, isFavorite: 1 });
documentSchema.index({ userId: 1, createdAt: -1 });

const Document = mongoose.model('Document', documentSchema);

export default Document;


