// ============================================================
// Auth Routes 
// ============================================================
const express = require('express');
const router = express.Router();
const { login, getCurrentUser } = require('../controllers/auth');
const { authenticateToken } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { loginValidator } = require('../validators/authValidator');

// Public routes
router.post('/login', loginValidator, validate, login);

// Private routes
router.get('/me', authenticateToken, getCurrentUser);

module.exports = router;
