import mongoose from 'mongoose';

const categorySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    key: {
      type: String,
      required: true,
      trim: true,
    },
    label: {
      type: String,
      required: true,
      trim: true,
    },
    icon: {
      type: String,
      required: true,
      default: 'Folder',
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// Ensure a user cannot have duplicate category keys
categorySchema.index({ userId: 1, key: 1 }, { unique: true });

const Category = mongoose.model('Category', categorySchema);

export default Category;
