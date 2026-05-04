// ============================================================
// Auth Routes 
// ============================================================
import express from 'express';
const router = express.Router();
import { login, getCurrentUser } from '../controllers/auth';
import { authenticateToken } from '../middleware/auth';
import { validate } from '../middleware/validate';
import { loginValidator } from '../validators/authValidator';

// Public routes
router.post('/login', loginValidator, validate, login);

// Private routes
router.get('/me', authenticateToken, getCurrentUser);

export default router;
