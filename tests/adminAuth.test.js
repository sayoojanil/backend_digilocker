// backend/tests/adminAuth.test.js

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../../src/app'); // adjust path to your Express app entry
const User = require('../models/User');

// Helper to generate JWT (assuming generateToken utility exists)
const { generateToken } = require('../utils/generateToken');

describe('Admin Auth Middleware', () => {
  let server;
  beforeAll(async () => {
    // Connect to in-memory MongoDB
    const { MongoMemoryServer } = require('mongodb-memory-server');
    const mongod = await MongoMemoryServer.create();
    await mongoose.connect(mongod.getUri(), { useNewUrlParser: true, useUnifiedTopology: true });
    server = app.listen();
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoose.connection.close();
    server.close();
  });

  test('rejects request without token', async () => {
    const res = await request(server).get('/api/admin/users');
    expect(res.status).toBe(401);
  });

  test('rejects non‑admin user', async () => {
    const user = await User.create({ name: 'User', email: 'user@example.com', password: 'pass', isAdmin: false });
    const token = generateToken(user);
    const res = await request(server).get('/api/admin/users').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('allows admin user', async () => {
    const admin = await User.create({ name: 'Admin', email: 'admin@example.com', password: 'pass', isAdmin: true });
    const token = generateToken(admin);
    const res = await request(server).get('/api/admin/users').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});
