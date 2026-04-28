const jwt = require('jsonwebtoken');
const logger = require('../../infrastructure/logging/logger');
const userRepository = require('../../repositories/auth');
const { verifyPassword } = require('../crypto');

async function login({ email, password }) {
  const user = await userRepository.findByEmail(email);

  if (!user || user.isActive === false) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    throw unauthorizedError();
  }

  const valid = await verifyPassword(password, user.password);
  if (!valid) {
    throw unauthorizedError();
  }

  await userRepository.updateLastLogin(user.id);

  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h', algorithm: 'HS256' }
  );

  logger.info(`Successful login: ${user.email}`, { userId: user.id });

  return {
    token,
    user: { id: user.id, email: user.email, role: user.role, fullName: user.fullName }
  };
}

async function getCurrentUser(userId) {
  return userRepository.findProfileById(userId);
}

function unauthorizedError() {
  const error = new Error('Invalid credentials');
  error.statusCode = 401;
  return error;
}

module.exports = {
  getCurrentUser,
  login
};
