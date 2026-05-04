import jwt from 'jsonwebtoken';

import logger from '../../infrastructure/logging/logger';
import * as userRepository from '../../repositories/auth';
import { verifyPassword } from '../crypto';

interface LoginInput {
  email: string;
  password: string;
}

interface UnauthorizedError extends Error {
  statusCode: number;
}

function getJwtSecret(): string {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET not configured');
  }

  return process.env.JWT_SECRET;
}

async function login({ email, password }: LoginInput) {
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
    getJwtSecret(),
    { expiresIn: '8h', algorithm: 'HS256' }
  );

  logger.info(`Successful login: ${user.email}`, { userId: user.id });

  return {
    token,
    user: { id: user.id, email: user.email, role: user.role, fullName: user.fullName }
  };
}

async function getCurrentUser(userId: string) {
  return userRepository.findProfileById(userId);
}

function unauthorizedError(): UnauthorizedError {
  const error = new Error('Invalid credentials') as UnauthorizedError;
  error.statusCode = 401;
  return error;
}

export { getCurrentUser, login };
