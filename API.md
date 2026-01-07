# API Documentation

## Base URL
```
http://localhost:5000
```

## Authentication

All protected endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <your-token>
```

## Endpoints

### Authentication

#### Register User
```http
POST /auth/signup
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "token": "jwt-token-here",
  "user": {
    "id": "user-id",
    "name": "John Doe",
    "email": "john@example.com",
    "avatar": null,
    "storageUsed": 0,
    "storageLimit": 1073741824,
    "isGuest": false,
    "createdAt": "2024-01-01T00:00:00.000Z"
  }
}
```

#### Login
```http
POST /loginWithEmail
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:** Same as signup

---

### Documents

#### Get All Documents
```http
GET /api/documents?category=identity&favorite=true&archived=false&search=passport
Authorization: Bearer <token>
```

**Query Parameters:**
- `category` - Filter by category (identity, financial, medical, etc.)
- `favorite` - Filter favorites (true/false)
- `archived` - Filter archived (true/false)
- `search` - Search in name, tags, issuer, notes

**Response:**
```json
{
  "success": true,
  "count": 10,
  "data": [
    {
      "_id": "doc-id",
      "userId": "user-id",
      "name": "Passport.pdf",
      "type": "pdf",
      "category": "identity",
      "fileType": "pdf",
      "size": 2621440,
      "tags": ["passport", "travel"],
      "metadata": {
        "issuer": "US Department of State",
        "expiryDate": "2034-06-15T00:00:00.000Z",
        "documentNumber": "US12345678"
      },
      "fileUrl": "/api/documents/user/user-id/filename.pdf",
      "isArchived": false,
      "isFavorite": true,
      "createdAt": "2024-01-01T00:00:00.000Z",
      "updatedAt": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

#### Get Single Document
```http
GET /api/documents/:id
Authorization: Bearer <token>
```

#### Upload Document
```http
POST /api/documents
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <file>
name: "Document Name"
category: "identity"
type: "pdf"
tags: ["tag1", "tag2"]  // JSON string
metadata: {"issuer": "Issuer Name"}  // JSON string
```

#### Update Document
```http
PUT /api/documents/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "New Name",
  "category": "financial",
  "tags": ["tag1", "tag2"],
  "metadata": {
    "issuer": "New Issuer",
    "notes": "Some notes"
  },
  "isFavorite": true,
  "isArchived": false
}
```

#### Delete Document
```http
DELETE /api/documents/:id
Authorization: Bearer <token>
```

#### Archive/Unarchive Document
```http
POST /api/documents/:id/archive
Authorization: Bearer <token>
```

#### Toggle Favorite
```http
POST /api/documents/:id/favorite
Authorization: Bearer <token>
```

#### Download Document
```http
GET /api/documents/:id/download
Authorization: Bearer <token>
```

---

### User

#### Get Profile
```http
GET /api/user/profile
Authorization: Bearer <token>
```

#### Update Profile
```http
PUT /api/user/profile
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "New Name",
  "avatar": "avatar-url"
}
```

---

### Activities

#### Get Activity Logs
```http
GET /api/activities?limit=50
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "count": 10,
  "data": [
    {
      "_id": "activity-id",
      "userId": "user-id",
      "action": "upload",
      "documentId": {
        "_id": "doc-id",
        "name": "Document.pdf",
        "category": "identity"
      },
      "documentName": "Document.pdf",
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

---

### Statistics

#### Get Storage Stats
```http
GET /api/stats
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "used": 52428800,
    "limit": 1073741824,
    "documentCount": 15,
    "categoryBreakdown": {
      "identity": 5,
      "financial": 3,
      "medical": 2,
      "insurance": 2,
      "legal": 1,
      "personal": 1,
      "travel": 1,
      "other": 0
    }
  }
}
```

---

## Error Responses

All errors follow this format:
```json
{
  "success": false,
  "message": "Error message here"
}
```

**Status Codes:**
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (invalid/missing token)
- `404` - Not Found
- `500` - Internal Server Error

---

## File Upload Limits

- **Max File Size:** 20MB (configurable via `MAX_FILE_SIZE`)
- **Allowed Types:** PDF, JPG, PNG
- **Storage Limit:** 1GB per user (configurable)


