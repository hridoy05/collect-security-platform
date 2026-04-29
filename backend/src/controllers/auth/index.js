const asyncHandler = require('express-async-handler');
const authService = require('../../services/auth');

/**
 * @desc    Authenticate user & get token
 * @route   POST /api/auth/login
 * @access  Public
 */
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  res.json(await authService.login({ email, password }));
});

/**
 * @desc    Get current user profile
 * @route   GET /api/auth/me
 * @access  Private
 */
const getCurrentUser = asyncHandler(async (req, res) => {
  const user = await authService.getCurrentUser(req.user.userId);

  if (!user) {
    res.status(404);
    throw new Error('User not found');
  }

  res.json(user);
});

module.exports = {
  login,
  getCurrentUser
};
