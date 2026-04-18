// ============================================================
// Auth Routes — Topic 1: JWT + bcrypt
// ============================================================
const express = require('express');
const router = express.Router();
const { login, getCurrentUser } = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');

// Public routes
router.post('/login', login);

// Private routes
router.get('/me', authenticateToken, getCurrentUser);

module.exports = router;
