// ============================================================
import type { ErrorRequestHandler, RequestHandler } from 'express';

import logger from '../infrastructure/logging/logger';

interface HttpError extends Error {
  statusCode?: number;
}

const errorHandler: ErrorRequestHandler = (err: HttpError, req, res, _next) => {
  const statusCode = err.statusCode || (res.statusCode === 200 ? 500 : res.statusCode);
  
  // Log the error for observability
  logger.error(`${req.method} ${req.url}`, { message: err.message, stack: err.stack, path: req.url });
  
  if (process.env.NODE_ENV === 'development') {
    console.error(err.stack);
  }

  res.status(statusCode).json({
    error: err.message || 'Internal Server Error',
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    timestamp: new Date().toISOString(),
    path: req.url
  });
};

const notFound: RequestHandler = (req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  res.status(404);
  next(error);
};

export { errorHandler, notFound };
