const asyncHandler = require('express-async-handler');
const jwt = require('jsonwebtoken');
const prisma = require('../config/prismaClient');
const { verifyPassword } = require('../services/cryptoService');
const logger = require('../services/loggerService');

/**
 * @desc    Authenticate user & get token
 * @route   POST /api/auth/login
 * @access  Public
 */
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || user.isActive === false) {
    // Same response time for missing user (prevent enumeration)
    await new Promise(r => setTimeout(r, 200));
    res.status(401);
    throw new Error('Invalid credentials');
  }

  const valid = await verifyPassword(password, user.password);

  if (!valid) {
    res.status(401);
    throw new Error('Invalid credentials');
  }

  // Update last login
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLogin: new Date() }
  });

  // Issue JWT
  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h', algorithm: 'HS256' }
  );

  logger.info(`Successful login: ${user.email}`, { userId: user.id });

  res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role, fullName: user.fullName }
  });
});

/**
 * @desc    Get current user profile
 * @route   GET /api/auth/me
 * @access  Private
 */
const getCurrentUser = asyncHandler(async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.userId },
    select: { id: true, email: true, role: true, fullName: true, lastLogin: true }
  });

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
