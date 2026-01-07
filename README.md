# Secure Vault Pro - Backend API

Production-ready backend API for Secure Vault Pro document management system.

## Features

- 🔐 JWT-based authentication
- 📁 Document upload and management
- 🔍 Search and filtering capabilities
- 📊 Storage statistics and activity logging
- 🛡️ Security best practices (helmet, rate limiting, CORS)
- 📝 Comprehensive error handling and logging
- ✅ Input validation
- 🗄️ MongoDB database with Mongoose

## Tech Stack

- **Node.js** - Runtime environment
- **Express** - Web framework
- **MongoDB** - Database
- **Mongoose** - ODM
- **JWT** - Authentication
- **Multer** - File uploads
- **Express Validator** - Input validation
- **Winston** - Logging

## Installation

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
```

3. Update the `.env` file with your configuration:
- `MONGODB_URI` - Your MongoDB connection string
- `JWT_SECRET` - A secure random string for JWT signing
- `FRONTEND_URL` - Your frontend URL for CORS

4. Start MongoDB (if running locally):
```bash
mongod
```

5. Run the server:
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## API Endpoints

### Authentication

- `POST /auth/signup` - Register a new user
- `POST /loginWithEmail` - Login with email and password

### Documents

- `GET /api/documents` - Get all documents (supports query params: category, favorite, archived, search)
- `GET /api/documents/:id` - Get single document
- `POST /api/documents` - Upload a new document (multipart/form-data)
- `PUT /api/documents/:id` - Update a document
- `DELETE /api/documents/:id` - Delete a document
- `POST /api/documents/:id/archive` - Archive/unarchive a document
- `POST /api/documents/:id/favorite` - Toggle favorite status
- `GET /api/documents/:id/download` - Download a document

### User

- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update user profile

### Activities

- `GET /api/activities` - Get activity logs (supports limit query param)

### Statistics

- `GET /api/stats` - Get storage statistics

## Authentication

All protected routes require a Bearer token in the Authorization header:
```
Authorization: Bearer <token>
```

## File Upload

Document uploads use `multipart/form-data` with the following fields:
- `file` - The file to upload (PDF, JPG, or PNG)
- `name` - Document name (optional, defaults to filename)
- `category` - Document category (required)
- `type` - Document type (optional)
- `tags` - JSON array of tags (optional)
- `metadata` - JSON object with metadata (optional)

## Environment Variables

See `.env.example` for all available environment variables.

## Project Structure

```
backend/
├── config/          # Configuration files
│   ├── database.js  # MongoDB connection
│   └── logger.js    # Winston logger setup
├── middleware/      # Express middleware
│   ├── auth.js      # JWT authentication
│   ├── errorHandler.js  # Error handling
│   └── upload.js    # File upload configuration
├── models/          # Mongoose models
│   ├── User.js
│   ├── Document.js
│   └── ActivityLog.js
├── routes/          # API routes
│   ├── auth.js
│   ├── documents.js
│   ├── user.js
│   ├── activities.js
│   └── stats.js
├── utils/          # Utility functions
│   └── generateToken.js
├── uploads/         # Uploaded files (gitignored)
├── server.js        # Main server file
└── package.json
```

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Rate limiting
- CORS protection
- Helmet security headers
- Input validation
- File type and size restrictions

## Error Handling

The API uses consistent error responses:
```json
{
  "success": false,
  "message": "Error message"
}
```

## Logging

Logs are written to:
- `error.log` - Error level logs
- `combined.log` - All logs
- Console (development mode)

## License

ISC


