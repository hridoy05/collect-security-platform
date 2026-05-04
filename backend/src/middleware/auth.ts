import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

import logger from '../infrastructure/logging/logger';
import type { AuthTokenPayload } from '../types/auth';

function getJwtSecret(): string {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET not configured');
  }

  return process.env.JWT_SECRET;
}

function authenticateToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn('Unauthorized access attempt: No token provided', {
      path: req.originalUrl,
      ip: req.ip
    });
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const user = jwt.verify(token, getJwtSecret()) as AuthTokenPayload;
    req.user = user;
    next();
  } catch (error) {
    logger.warn('Unauthorized access attempt: Invalid token', {
      path: req.originalUrl,
      ip: req.ip,
      error: error instanceof Error ? error.message : 'Unknown token error'
    });
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

export { authenticateToken };
