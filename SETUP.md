# Backend Setup Guide

## Quick Start

1. **Install Dependencies**
   ```bash
   cd backend
   npm install
   ```

2. **Set Up Environment Variables**
   
   Create a `.env` file in the `backend` directory:
   ```env
   # Server Configuration
   PORT=6000
   NODE_ENV=development

   # Database
   MONGODB_URI=mongodb://localhost:27017/secure-vault

   # JWT
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-min-32-chars
   JWT_EXPIRE=7d

   # File Upload
   MAX_FILE_SIZE=20971520
   ALLOWED_FILE_TYPES=application/pdf,image/jpeg,image/png,image/jpg

   # Cloudinary Configuration (for cloud file storage)
   CLOUDINARY_CLOUD_NAME=your-cloudinary-cloud-name
   CLOUDINARY_API_KEY=your-cloudinary-api-key
   CLOUDINARY_API_SECRET=your-cloudinary-api-secret

   # CORS
   FRONTEND_URL=http://localhost:5173

   # Storage Limits
   DEFAULT_STORAGE_LIMIT=1073741824
   ```

   **Important:** 
   - Change `JWT_SECRET` to a strong random string in production!
   - Get your Cloudinary credentials from https://cloudinary.com/
     - Sign up for a free account
     - Go to Dashboard to get your Cloud Name, API Key, and API Secret

3. **Start MongoDB**
   
   Make sure MongoDB is running on your system:
   ```bash
   # On macOS with Homebrew
   brew services start mongodb-community

   # On Linux
   sudo systemctl start mongod

   # On Windows
   # Start MongoDB service from Services panel
   ```

   Or use MongoDB Atlas (cloud):
   - Create account at https://www.mongodb.com/cloud/atlas
   - Create a cluster
   - Get connection string and update `MONGODB_URI` in `.env`

3. **Set Up Cloudinary (for file storage)**
   
   - Create a free account at https://cloudinary.com/
   - Go to Dashboard
   - Copy your Cloud Name, API Key, and API Secret
   - Add them to your `.env` file:
     ```
     CLOUDINARY_CLOUD_NAME=your-cloud-name
     CLOUDINARY_API_KEY=your-api-key
     CLOUDINARY_API_SECRET=your-api-secret
     ```

4. **Install Dependencies (including Cloudinary)**
   ```bash
   npm install
   ```

5. **Run the Server**
   ```bash
   # Development mode (with auto-reload)
   npm run dev

   # Production mode
   npm start
   ```

6. **Verify Installation**
   
   Visit http://localhost:5000/health in your browser or:
   ```bash
   curl http://localhost:5000/health
   ```

   You should see:
   ```json
   {
     "success": true,
     "message": "Server is running",
     "timestamp": "..."
   }
   ```

## Testing the API

### Register a New User
```bash
curl -X POST http://localhost:5000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Login
```bash
curl -X POST http://localhost:5000/loginWithEmail \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

Save the `token` from the response for authenticated requests.

### Get User Profile (Authenticated)
```bash
curl http://localhost:5000/api/user/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Frontend Integration

Update your frontend `.env` file (or `vite.config.ts`) to point to the backend:
```env
VITE_API_URL=http://localhost:5000
```

## Production Deployment

1. Set `NODE_ENV=production` in `.env`
2. Use a strong `JWT_SECRET` (at least 32 characters)
3. Update `FRONTEND_URL` to your production frontend URL
4. Use a production MongoDB instance (MongoDB Atlas recommended)
5. Consider using cloud storage (AWS S3, Google Cloud Storage) for file uploads
6. Set up proper logging and monitoring
7. Use a process manager like PM2:
   ```bash
   npm install -g pm2
   pm2 start server.js --name secure-vault-api
   ```

## Troubleshooting

### MongoDB Connection Issues
- Ensure MongoDB is running
- Check `MONGODB_URI` is correct
- For Atlas, ensure your IP is whitelisted

### Port Already in Use
- Change `PORT` in `.env` to a different port
- Or kill the process using port 5000

### File Upload Issues
- Verify Cloudinary credentials are correct in `.env`
- Check `MAX_FILE_SIZE` matches your needs (Cloudinary free tier: 10MB per file)
- Verify file types match `ALLOWED_FILE_TYPES`
- Check Cloudinary dashboard for upload errors

### CORS Issues
- Ensure `FRONTEND_URL` matches your frontend URL exactly
- Check browser console for CORS errors


