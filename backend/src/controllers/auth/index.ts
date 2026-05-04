import type { Request } from 'express';

import asyncHandler from 'express-async-handler';
import * as authService from '../../services/auth';

interface LoginRequestBody {
  email: string;
  password: string;
}

/**
 * @desc    Authenticate user & get token
 * @route   POST /api/auth/login
 * @access  Public
 */
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body as LoginRequestBody;
  res.json(await authService.login({ email, password }));
});

/**
 * @desc    Get current user profile
 * @route   GET /api/auth/me
 * @access  Private
 */
const getCurrentUser = asyncHandler(async (req, res) => {
  const userId = (req as Request).user?.userId;
  if (!userId) {
    res.status(401);
    throw new Error('Unauthorized');
  }

  const user = await authService.getCurrentUser(userId);

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  res.json(user);
});

export {
  login,
  getCurrentUser
};
