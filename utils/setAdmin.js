import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import User from '../models/User.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load env vars from backend/.env
dotenv.config({ path: join(__dirname, '../.env') });

const email = process.argv[2];

if (!email) {
  console.error('Please provide a user email: node setAdmin.js <email>');
  process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    const user = await User.findOne({ email });
    if (!user) {
      console.error(`User with email "${email}" not found.`);
      process.exit(1);
    }
    user.isAdmin = true;
    await user.save();
    console.log(`\x1b[32mSuccess: Successfully updated ${email} to Admin!\x1b[0m`);
    process.exit(0);
  })
  .catch(err => {
    console.error('Connection or query error:', err);
    process.exit(1);
  });
